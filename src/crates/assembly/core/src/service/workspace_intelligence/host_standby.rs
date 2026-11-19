//! Bounded standby scheduling for one workspace intelligence host.
//!
//! This is not a scheduler and not a governance loop: it only decides *when* the
//! host re-reads the persisted facts. One worker exists per host, and only while
//! the host has at least one genuinely enabled scope.
//!
//! Two wake-up sources and one fallback exist, and they are deliberately
//! asymmetric:
//!
//! - the **catalog revision hint** the composition supplies (a process-local
//!   `watch::Receiver<u64>`, obtained from the workspace owner's
//!   `subscribe_catalog_changes` association before the host is built) only
//!   short-circuits the sleep. It is a hint, not authority: another host process
//!   can rewrite the registry with no local event at all, so it can never be the
//!   thing that makes a decision;
//! - **shutdown** ends the worker;
//! - the **coarse periodic fallback** bounds how long a change made outside this
//!   process stays unnoticed. The delay starts at [`STANDBY_BASE_DELAY`], doubles
//!   and is capped at [`STANDBY_MAX_DELAY`], and is reset whenever the revision
//!   hint fired. One sleep per host, never one per scope.
//!
//! A hint whose sender is dropped is retired for good: the worker then runs on the
//! fallback schedule alone, with the same delays as a host composed without a hint.
//! A closed `watch` receiver would otherwise resolve `changed()` immediately and
//! pre-empt every fresh sleep, which would read the registry back to back with no
//! delay at all. Retiring the hint costs at most one immediate re-evaluation, the
//! one that observes the close.
//!
//! The worker itself performs no disk read and no write. It awaits the caller's
//! evaluation future, which re-reads the persisted registry through the
//! read-only catalog reader and therefore re-reads at most once per wake-up.
//!
//! Cancellation and drain are the host's job: this module only guarantees that a
//! dropped [`StandbyWorker`] stops, and that a joined one has finished its current
//! evaluation future before returning.

use std::future::Future;
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;

/// First fallback delay of an idle host with at least one enabled scope.
pub(crate) const STANDBY_BASE_DELAY: Duration = Duration::from_millis(250);

/// Upper bound of the fallback delay.
pub(crate) const STANDBY_MAX_DELAY: Duration = Duration::from_secs(30);

/// Bounded exponential fallback delay.
#[derive(Debug, Clone)]
pub(crate) struct StandbyBackoff {
    base: Duration,
    max: Duration,
    next: Duration,
}

impl StandbyBackoff {
    /// Builds a backoff starting at `base`, never exceeding `max`.
    pub(crate) fn new(base: Duration, max: Duration) -> Self {
        let base = if base.is_zero() {
            Duration::from_millis(1)
        } else {
            base
        };
        let max = max.max(base);
        Self {
            base,
            max,
            next: base,
        }
    }

    /// Returns the next delay and grows the following one, capped.
    pub(crate) fn next_delay(&mut self) -> Duration {
        let current = self.next;
        self.next = current.saturating_mul(2).min(self.max);
        current
    }

    /// Restarts the sequence at the base delay.
    pub(crate) fn reset(&mut self) {
        self.next = self.base;
    }
}

/// Waits until the caller asked the worker to stop (or dropped the host).
async fn wait_for_stop(stop: &mut watch::Receiver<bool>) {
    // `wait_for` is cancel-safe and returns immediately when the value already
    // satisfies the predicate. A closed channel means the host is gone, which is
    // also a stop request.
    let _ = stop.wait_for(|requested| *requested).await;
}

/// One bounded fallback sleep, short-circuited by a revision hint.
///
/// `true` means the hint fired. `false` means the fallback sleep elapsed, or that
/// the hint is closed and this wait degraded to the plain sleep.
///
/// A `watch::Receiver::changed()` future resolves IMMEDIATELY once every sender is
/// dropped, so a closed hint that were kept would pre-empt every freshly armed
/// sleep and turn the fallback into a busy loop with no delay at all. The hint is
/// therefore retired permanently on the first error and the plain
/// `sleep(delay).await` path takes over, which is what keeps the documented
/// [`STANDBY_BASE_DELAY`]-to-[`STANDBY_MAX_DELAY`] schedule intact.
async fn wait_for_wake_up(
    delay: Duration,
    revision: &mut Option<watch::Receiver<u64>>,
) -> bool {
    match revision {
        Some(hint) => {
            let sleep = tokio::time::sleep(delay);
            tokio::pin!(sleep);
            let changed = tokio::select! {
                _ = &mut sleep => return false,
                changed = hint.changed() => changed,
            };
            match changed {
                Ok(()) => true,
                Err(_) => {
                    // Closed for good: from here on this host has no hint at all.
                    *revision = None;
                    false
                }
            }
        }
        None => {
            tokio::time::sleep(delay).await;
            false
        }
    }
}

/// One host-owned standby worker.
///
/// Dropping the handle stops the worker; [`StandbyWorker::join`] waits for the
/// current evaluation future, so a caller can bound the wait with its own drain
/// budget instead of trusting this module.
pub(crate) struct StandbyWorker {
    task: Option<JoinHandle<()>>,
}

impl StandbyWorker {
    /// Starts the worker.
    ///
    /// `evaluate` is the host's re-evaluation future, invoked once per wake-up.
    /// It must be bounded work: this module never cancels it, which is why a
    /// caller that needs a bounded drain has to use [`StandbyWorker::join`] under
    /// its own timeout.
    pub(crate) fn spawn<F, Fut>(
        base: Duration,
        max: Duration,
        mut revision: Option<watch::Receiver<u64>>,
        mut stop: watch::Receiver<bool>,
        evaluate: F,
    ) -> Self
    where
        F: Fn() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let mut backoff = StandbyBackoff::new(base, max);
        let task = tokio::spawn(async move {
            loop {
                let delay = backoff.next_delay();
                let hinted = tokio::select! {
                    // Shutdown wins over any pending fallback sleep and any hint.
                    () = wait_for_stop(&mut stop) => break,
                    hinted = wait_for_wake_up(delay, &mut revision) => hinted,
                };
                if hinted {
                    // A catalog write happened: retry the fast schedule.
                    backoff.reset();
                }
                if *stop.borrow() {
                    break;
                }
                evaluate().await;
            }
        });
        Self { task: Some(task) }
    }

    /// Waits for the worker to observe the stop signal and finish.
    pub(crate) async fn join(mut self) {
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for StandbyWorker {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const FAST_BASE: Duration = Duration::from_millis(5);
    const FAST_MAX: Duration = Duration::from_millis(20);
    const DEADLINE: Duration = Duration::from_secs(10);

    #[test]
    fn fallback_delays_double_and_are_capped() {
        let mut backoff = StandbyBackoff::new(
            Duration::from_millis(250),
            Duration::from_secs(30),
        );
        let delays: Vec<u64> = (0..10).map(|_| backoff.next_delay().as_millis() as u64).collect();
        assert_eq!(
            delays,
            vec![250, 500, 1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000]
        );
        backoff.reset();
        assert_eq!(backoff.next_delay(), Duration::from_millis(250));
    }

    #[test]
    fn the_reviewed_fallback_literals_are_the_ones_production_uses() {
        // `HostTiming::default` builds the production backoff out of exactly these
        // two constants, so pinning their literal values here pins the schedule a
        // real host runs on.
        assert_eq!(STANDBY_BASE_DELAY, Duration::from_millis(250));
        assert_eq!(STANDBY_MAX_DELAY, Duration::from_secs(30));
        let mut backoff = StandbyBackoff::new(STANDBY_BASE_DELAY, STANDBY_MAX_DELAY);
        assert_eq!(backoff.next_delay(), Duration::from_millis(250));
        for _ in 0..12 {
            backoff.next_delay();
        }
        assert_eq!(backoff.next_delay(), Duration::from_secs(30));
    }

    #[tokio::test]
    async fn a_stop_signal_cancels_the_worker_before_any_evaluation() {
        let (stop, stop_rx) = watch::channel(false);
        let runs = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&runs);
        let worker = StandbyWorker::spawn(
            Duration::from_secs(30),
            Duration::from_secs(60),
            None,
            stop_rx,
            move || {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
            },
        );
        stop.send(true).unwrap();
        tokio::time::timeout(DEADLINE, worker.join())
            .await
            .expect("a stopped worker must join promptly");
        assert_eq!(runs.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn the_periodic_fallback_evaluates_without_any_catalog_event() {
        let (stop, stop_rx) = watch::channel(false);
        let runs = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&runs);
        let worker = StandbyWorker::spawn(FAST_BASE, FAST_MAX, None, stop_rx, move || {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        });
        let deadline = tokio::time::Instant::now() + DEADLINE;
        while runs.load(Ordering::SeqCst) < 3 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(FAST_BASE).await;
        }
        assert!(runs.load(Ordering::SeqCst) >= 3);
        stop.send(true).unwrap();
        tokio::time::timeout(DEADLINE, worker.join()).await.expect("join");
    }

    #[tokio::test]
    async fn a_catalog_hint_short_circuits_the_fallback_sleep() {
        let (stop, stop_rx) = watch::channel(false);
        let (revision, revision_rx) = watch::channel(0u64);
        let runs = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&runs);
        // The fallback is far longer than the test: only the hint can wake it.
        let worker = StandbyWorker::spawn(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Some(revision_rx),
            stop_rx,
            move || {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
            },
        );
        tokio::time::sleep(FAST_BASE).await;
        assert_eq!(runs.load(Ordering::SeqCst), 0);
        revision.send_modify(|value| *value += 1);
        let deadline = tokio::time::Instant::now() + DEADLINE;
        while runs.load(Ordering::SeqCst) < 1 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(FAST_BASE).await;
        }
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        stop.send(true).unwrap();
        tokio::time::timeout(DEADLINE, worker.join()).await.expect("join");
    }

    #[tokio::test]
    async fn a_closed_revision_hint_never_turns_the_fallback_into_a_busy_loop() {
        // A closed `watch` channel makes `changed()` resolve immediately forever, so
        // a hint that were kept would pre-empt every freshly armed sleep and the
        // worker would evaluate back to back instead of on its 30 s schedule. Here
        // the sender is dropped before the worker starts and the fallback delay is
        // far longer than the observation window: a busy loop evaluates thousands of
        // times, a correct worker at most once (the retirement wake-up) and then
        // nothing until the sleep elapses.
        let (stop, stop_rx) = watch::channel(false);
        let (revision, revision_rx) = watch::channel(0u64);
        drop(revision);
        let runs = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&runs);
        let worker = StandbyWorker::spawn(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Some(revision_rx),
            stop_rx,
            move || {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
            },
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        let observed = runs.load(Ordering::SeqCst);
        assert!(
            observed <= 1,
            "a closed hint must not reschedule the worker: {observed} evaluations in 200 ms"
        );
        // The retirement wake-up must not repeat: with the hint gone the worker is on
        // the 30 s fallback, so a second window observes no further evaluation.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            runs.load(Ordering::SeqCst),
            observed,
            "the retired hint must not keep waking the worker"
        );
        stop.send(true).unwrap();
        tokio::time::timeout(DEADLINE, worker.join()).await.expect("join");
    }

    #[tokio::test]
    async fn a_dropped_worker_stops_running_evaluations() {
        let (_stop, stop_rx) = watch::channel(false);
        let runs = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&runs);
        let worker = StandbyWorker::spawn(FAST_BASE, FAST_MAX, None, stop_rx, move || {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        });
        tokio::time::sleep(FAST_MAX).await;
        drop(worker);
        let observed = runs.load(Ordering::SeqCst);
        tokio::time::sleep(FAST_MAX * 4).await;
        assert_eq!(
            runs.load(Ordering::SeqCst),
            observed,
            "a dropped worker must not keep evaluating"
        );
    }
}

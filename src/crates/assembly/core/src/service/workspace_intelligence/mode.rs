//! Workspace intelligence tier derivation from control facts.
//!
//! The tier is a function of two facts only: the control-record switch and the
//! configured workspace model reference. Enhancement-domain counts, autonomy
//! limits, and capability delivery never change the tier; they travel as
//! orthogonal facts so later phases can act on them without re-deriving it.
//!
//! There is deliberately no fallback to a default model, a session model, or
//! any other implicit binding: a missing reference stays `Baseline`.

/// Opaque identifier of the configured workspace model reference.
///
/// Only the identifier is modeled here; provider settings and model
/// configuration keep their own owners. The identifier is kept verbatim, so a
/// configured value is never silently rewritten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkspaceModelRef(String);

impl WorkspaceModelRef {
    /// Parses a reference identifier, rejecting only a blank value.
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        if raw.trim().is_empty() {
            None
        } else {
            Some(Self(raw.to_owned()))
        }
    }

    /// The identifier exactly as it was configured.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Resolution fact of a configured workspace model reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkspaceModelResolution {
    /// The reference resolves to a usable model.
    Resolved,
    /// The reference cannot be resolved; the reference itself is kept.
    Unresolvable,
}

/// Model binding carried by a derived mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkspaceModelState {
    /// The derived tier binds no workspace model.
    NotReferenced,
    /// A workspace model is configured and resolvable.
    Configured,
    /// A workspace model is configured but cannot be resolved.
    ConfiguredUnresolvable,
}

impl WorkspaceModelState {
    /// A configured but unresolvable model degrades orthogonally: it does not
    /// change the tier.
    pub(crate) fn is_degraded(self) -> bool {
        matches!(self, Self::ConfiguredUnresolvable)
    }
}

/// Capability delivery fact. Orthogonal to the tier and to degradation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CapabilityDelivery {
    /// The host delivers the capability the tier needs.
    Delivered,
    /// The host cannot deliver it right now.
    Unavailable,
}

/// Workspace intelligence tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkspaceIntelligenceTier {
    /// The switch is absent or off. Nothing is derived, including the reference.
    Off,
    /// The switch is on and no workspace model is configured.
    Baseline,
    /// The switch is on and a workspace model is configured.
    Intelligent,
}

/// Input facts of tier derivation.
#[derive(Debug, Clone)]
pub(crate) struct ModeFacts {
    /// Control-record switch. `None` means the field was absent, which is off.
    pub(crate) enabled: Option<bool>,
    /// Configured workspace model reference.
    pub(crate) model_ref: Option<WorkspaceModelRef>,
    /// Host capability delivery fact, passed through unchanged.
    pub(crate) delivery: CapabilityDelivery,
}

/// Derived mode: the tier plus the orthogonal facts that traveled with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DerivedMode {
    /// Derived tier.
    pub(crate) tier: WorkspaceIntelligenceTier,
    /// Model binding the derived tier carries.
    pub(crate) model_state: WorkspaceModelState,
    /// The reference the derived tier consumed. `Off` and `Baseline` consume no
    /// reference; the read contract keeps any unconsumed value verbatim.
    pub(crate) model_ref: Option<WorkspaceModelRef>,
    /// Delivery fact, unchanged from the input.
    pub(crate) delivery: CapabilityDelivery,
}

impl DerivedMode {
    /// True when a configured workspace model could not be resolved.
    pub(crate) fn is_degraded(&self) -> bool {
        self.model_state.is_degraded()
    }
}

/// Derives the tier from control facts.
///
/// `resolve` is called at most once, and only on the `Intelligent` path, so a
/// workspace that is off or on the baseline never resolves a model reference.
pub(crate) fn derive_mode<F>(facts: ModeFacts, resolve: F) -> DerivedMode
where
    F: FnOnce(&WorkspaceModelRef) -> WorkspaceModelResolution,
{
    let ModeFacts {
        enabled,
        model_ref,
        delivery,
    } = facts;

    if !matches!(enabled, Some(true)) {
        return DerivedMode {
            tier: WorkspaceIntelligenceTier::Off,
            model_state: WorkspaceModelState::NotReferenced,
            model_ref: None,
            delivery,
        };
    }

    let Some(model_ref) = model_ref else {
        return DerivedMode {
            tier: WorkspaceIntelligenceTier::Baseline,
            model_state: WorkspaceModelState::NotReferenced,
            model_ref: None,
            delivery,
        };
    };

    let model_state = match resolve(&model_ref) {
        WorkspaceModelResolution::Resolved => WorkspaceModelState::Configured,
        WorkspaceModelResolution::Unresolvable => WorkspaceModelState::ConfiguredUnresolvable,
    };

    DerivedMode {
        tier: WorkspaceIntelligenceTier::Intelligent,
        model_state,
        model_ref: Some(model_ref),
        delivery,
    }
}

/// True when a tier may read scoped workspace intelligence content.
///
/// `Off` owns no cognition partition, so it must never read one. `Baseline` and
/// `Intelligent` both carry the switch and may look; whether a read then returns
/// content is a separate fact about the partition, not about the tier.
pub(crate) fn tier_permits_scoped_read(tier: WorkspaceIntelligenceTier) -> bool {
    !matches!(tier, WorkspaceIntelligenceTier::Off)
}

/// True when the workspace is intelligent but every enhancement domain is off.
///
/// The per-domain configuration schema belongs to a later phase; the count is
/// only a fact here and never enters the derived mode.
pub(crate) fn is_idle(tier: WorkspaceIntelligenceTier, enabled_enhancement_domains: usize) -> bool {
    matches!(tier, WorkspaceIntelligenceTier::Intelligent) && enabled_enhancement_domains == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn model_ref(raw: &str) -> WorkspaceModelRef {
        WorkspaceModelRef::parse(raw).expect("test reference must be non-blank")
    }

    fn facts(enabled: Option<bool>, model_ref: Option<WorkspaceModelRef>) -> ModeFacts {
        ModeFacts {
            enabled,
            model_ref,
            delivery: CapabilityDelivery::Delivered,
        }
    }

    fn panic_resolver(_: &WorkspaceModelRef) -> WorkspaceModelResolution {
        panic!("this tier must not resolve a workspace model reference");
    }

    #[test]
    fn an_absent_switch_is_off_and_never_resolves_a_configured_reference() {
        let derived = derive_mode(
            facts(None, Some(model_ref("workspace-model-a"))),
            panic_resolver,
        );

        assert_eq!(derived.tier, WorkspaceIntelligenceTier::Off);
        assert_eq!(derived.model_state, WorkspaceModelState::NotReferenced);
        assert_eq!(derived.model_ref, None);
        assert!(!derived.is_degraded());
    }

    #[test]
    fn a_disabled_switch_is_off_and_never_resolves_a_configured_reference() {
        let derived = derive_mode(
            facts(Some(false), Some(model_ref("workspace-model-a"))),
            panic_resolver,
        );

        assert_eq!(derived.tier, WorkspaceIntelligenceTier::Off);
        assert_eq!(derived.model_state, WorkspaceModelState::NotReferenced);
        assert_eq!(derived.model_ref, None);
    }

    #[test]
    fn an_enabled_switch_without_a_reference_is_baseline() {
        let derived = derive_mode(facts(Some(true), None), panic_resolver);

        assert_eq!(derived.tier, WorkspaceIntelligenceTier::Baseline);
        assert_eq!(derived.model_state, WorkspaceModelState::NotReferenced);
        assert_eq!(derived.model_ref, None);
        assert_eq!(derived.delivery, CapabilityDelivery::Delivered);
    }

    #[test]
    fn an_enabled_switch_with_a_resolvable_reference_is_intelligent() {
        let derived = derive_mode(
            facts(Some(true), Some(model_ref("workspace-model-a"))),
            |_| WorkspaceModelResolution::Resolved,
        );

        assert_eq!(derived.tier, WorkspaceIntelligenceTier::Intelligent);
        assert_eq!(derived.model_state, WorkspaceModelState::Configured);
        assert!(!derived.is_degraded());
        assert_eq!(derived.model_ref, Some(model_ref("workspace-model-a")));
    }

    #[test]
    fn an_unresolvable_reference_stays_intelligent_and_keeps_the_reference() {
        let derived = derive_mode(
            facts(Some(true), Some(model_ref("workspace-model-a"))),
            |_| WorkspaceModelResolution::Unresolvable,
        );

        assert_eq!(derived.tier, WorkspaceIntelligenceTier::Intelligent);
        assert_eq!(
            derived.model_state,
            WorkspaceModelState::ConfiguredUnresolvable
        );
        assert!(derived.is_degraded());
        assert_eq!(derived.model_ref, Some(model_ref("workspace-model-a")));
    }

    #[test]
    fn the_intelligent_path_resolves_the_reference_exactly_once() {
        let calls = Cell::new(0);
        let derived = derive_mode(facts(Some(true), Some(model_ref("workspace-model-a"))), |_| {
            calls.set(calls.get() + 1);
            WorkspaceModelResolution::Resolved
        });

        assert_eq!(calls.get(), 1);
        assert_eq!(derived.tier, WorkspaceIntelligenceTier::Intelligent);
    }

    #[test]
    fn unavailable_delivery_changes_neither_tier_nor_degradation() {
        for delivery in [
            CapabilityDelivery::Delivered,
            CapabilityDelivery::Unavailable,
        ] {
            let degraded = derive_mode(
                ModeFacts {
                    enabled: Some(true),
                    model_ref: Some(model_ref("workspace-model-a")),
                    delivery,
                },
                |_| WorkspaceModelResolution::Unresolvable,
            );

            assert_eq!(degraded.tier, WorkspaceIntelligenceTier::Intelligent);
            assert!(degraded.is_degraded());
            assert_eq!(degraded.delivery, delivery);

            let baseline = derive_mode(
                ModeFacts {
                    enabled: Some(true),
                    model_ref: None,
                    delivery,
                },
                panic_resolver,
            );

            assert_eq!(baseline.tier, WorkspaceIntelligenceTier::Baseline);
            assert!(!baseline.is_degraded());
            assert_eq!(baseline.delivery, delivery);
        }
    }

    #[test]
    fn blank_references_are_invalid_and_identifiers_are_kept_verbatim() {
        assert_eq!(WorkspaceModelRef::parse(""), None);
        assert_eq!(WorkspaceModelRef::parse("   "), None);
        assert_eq!(WorkspaceModelRef::parse("\t\n "), None);

        let reference = model_ref(" workspace-model-a ");
        assert_eq!(reference.as_str(), " workspace-model-a ");
    }

    #[test]
    fn idle_requires_intelligent_with_every_enhancement_domain_off() {
        assert!(is_idle(WorkspaceIntelligenceTier::Intelligent, 0));
        assert!(!is_idle(WorkspaceIntelligenceTier::Intelligent, 1));
        assert!(!is_idle(WorkspaceIntelligenceTier::Intelligent, 4));
        assert!(!is_idle(WorkspaceIntelligenceTier::Baseline, 0));
        assert!(!is_idle(WorkspaceIntelligenceTier::Off, 0));

        // An intelligent workspace with every enhancement domain off is idle,
        // not off: domain counts never change the tier.
        let derived = derive_mode(
            facts(Some(true), Some(model_ref("workspace-model-a"))),
            |_| WorkspaceModelResolution::Resolved,
        );
        assert!(is_idle(derived.tier, 0));
        assert_eq!(derived.tier, WorkspaceIntelligenceTier::Intelligent);
    }

    #[test]
    fn only_an_enabled_tier_permits_a_scoped_read() {
        assert!(!tier_permits_scoped_read(WorkspaceIntelligenceTier::Off));
        assert!(tier_permits_scoped_read(
            WorkspaceIntelligenceTier::Baseline
        ));
        assert!(tier_permits_scoped_read(
            WorkspaceIntelligenceTier::Intelligent
        ));

        // A missing switch field and an explicit off both derive `Off`, so both
        // refuse the read.
        for enabled in [None, Some(false)] {
            let derived = derive_mode(
                ModeFacts {
                    enabled,
                    model_ref: None,
                    delivery: CapabilityDelivery::Delivered,
                },
                panic_resolver,
            );
            assert_eq!(derived.tier, WorkspaceIntelligenceTier::Off);
            assert!(!tier_permits_scoped_read(derived.tier));
        }
    }
}

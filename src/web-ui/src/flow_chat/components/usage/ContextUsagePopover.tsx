import { useEffect, useRef, useState, type RefObject } from 'react';
import { Card, Empty, Icon, IconButton, OverflowText, Tooltip, createOverlayPortal, useDismissibleLayer } from '@openbitfun/ui';
import { ChartPie, ExternalLink, Minus, Shrink } from 'lucide-react';
import { useI18n } from '@/infrastructure/i18n';
import { getAppearanceOverlayHost } from '@/infrastructure/appearance/runtime/AppearanceOverlayHost';
import type { UsageRequestSnapshot } from '@/infrastructure/api/service-api/SessionAPI';
import type { RequestContextSnapshotReadResult } from '@/flow_chat/services/requestContextSnapshotService';
import {
  REQUEST_CONTEXT_SNAPSHOT_CATEGORIES,
  resolveRequestContextSnapshotView,
  type RequestContextSnapshotView,
} from '@/flow_chat/utils/tokenUsageDisplay';
import { useAnchoredPopoverPosition } from '@/shared/utils/useAnchoredPopoverPosition';
import { formatTokenCount, formatUsagePercent } from './usageReportUtils';
import { useUsageSeriesHighlight } from './useUsageSeriesHighlight';
import { useContextPreview } from './useContextPreview';
import './ContextUsagePopover.scss';

type SnapshotStatus = 'loading' | 'ready' | 'error' | 'unsupported' | 'unavailable';

/** Same recorded request, by the identity core compares. */
function sameRequestIdentity(a: UsageRequestSnapshot, b: UsageRequestSnapshot): boolean {
  return a.request.executionHostId === b.request.executionHostId
    && (a.request.workspaceId ?? '') === (b.request.workspaceId ?? '')
    && a.request.turnId === b.request.turnId
    && a.request.roundId === b.request.roundId
    && a.request.attemptId === b.request.attemptId;
}

const snapshotUsageRank = (state: UsageRequestSnapshot['usageState']): number => (
  state === 'provider_reported' ? 2 : state === 'estimated' ? 1 : 0
);

/** `unavailable` outranks `pending`: the host degrades a dead summary job to it. */
const snapshotSummaryRank = (state: UsageRequestSnapshot['summaryState']): number => (
  state === 'ready' ? 2 : state === 'unavailable' ? 1 : 0
);

/**
 * The reading an open overview should present when the store delivers another
 * one: a newer capture of the same request, or a newer attempt. Equal captures
 * are adopted only when a rank improves without regressing the other (the
 * host's `pending` → `unavailable` degradation keeps `capturedAt`). It never
 * downgrades a provider total to an estimate or a ready summary to a pending
 * one; the store owns the full merge policy, this only picks which capture to
 * show.
 */
function adoptNewerSnapshot(
  current: UsageRequestSnapshot,
  incoming: UsageRequestSnapshot,
): UsageRequestSnapshot {
  if (sameRequestIdentity(current, incoming)) {
    const usageRegresses = snapshotUsageRank(incoming.usageState) < snapshotUsageRank(current.usageState);
    const summaryRegresses = snapshotSummaryRank(incoming.summaryState) < snapshotSummaryRank(current.summaryState);
    if (usageRegresses || summaryRegresses) return current;
    if (incoming.capturedAt > current.capturedAt) return incoming;
    if (incoming.capturedAt < current.capturedAt) return current;
    const improves = snapshotUsageRank(incoming.usageState) > snapshotUsageRank(current.usageState)
      || snapshotSummaryRank(incoming.summaryState) > snapshotSummaryRank(current.summaryState);
    return improves ? incoming : current;
  }
  const newer = incoming.request.startedAt !== current.request.startedAt
    ? incoming.request.startedAt > current.request.startedAt
    : incoming.request.attemptIndex !== current.request.attemptIndex
      ? incoming.request.attemptIndex > current.request.attemptIndex
      : incoming.capturedAt > current.capturedAt;
  return newer ? incoming : current;
}

/**
 * The default context overview.
 *
 * It presents the recorded request snapshot only: a provider-reported total is
 * `inputTotal` (U) with the same-attempt category estimates scaled onto it, an
 * estimated total is labelled as an estimate, and an unknown total is never
 * rendered as zero. Opening the overview never issues a report, an estimate, or
 * a send-path scan.
 */
export function ContextUsagePopover({
  id, anchorRef, triggerRef, currentTokens, maxTokens, snapshot, loadSnapshot, previewSession,
  unsupported = false, compactDisabled = false, onCompact, onClose, onViewReport,
}: {
  id: string;
  anchorRef: RefObject<HTMLElement>;
  triggerRef: RefObject<HTMLButtonElement>;
  /** Last known legacy token total; only shown when no snapshot is recorded. */
  currentTokens: number;
  maxTokens: number;
  /** Stored snapshot for this Session, shared with the ring and side panel. */
  snapshot?: UsageRequestSnapshot;
  loadSnapshot?: () => Promise<RequestContextSnapshotReadResult>;
  previewSession?: { sessionId: string; workspaceId?: string };
  /** The rendered host does not advertise the recorded-snapshot mode. */
  unsupported?: boolean;
  compactDisabled?: boolean;
  onCompact?: () => void;
  onClose: () => void;
  onViewReport: () => void;
}) {
  const { t } = useI18n('flow-chat');
  const popoverRef = useRef<HTMLDivElement>(null);
  const [loaded, setLoaded] = useState<UsageRequestSnapshot | undefined>(snapshot);
  const [status, setStatus] = useState<SnapshotStatus>(
    unsupported ? 'unsupported' : snapshot ? 'ready' : loadSnapshot ? 'loading' : 'ready',
  );
  const [unavailableReason, setUnavailableReason] = useState<string | undefined>();
  const loadedRef = useRef(loaded);
  loadedRef.current = loaded;
  const view = loaded ? resolveRequestContextSnapshotView(loaded, maxTokens) : undefined;
  const { previewLoading, previewContext } = useContextPreview({
    ...previewSession,
    reportSessionId: previewSession?.sessionId,
    request: loaded?.request,
  });
  // Snapshot the loader on open: live token updates must not re-fetch the
  // snapshot. Keep the ref in step with the prop so a later open of another
  // Session can never read through the loader captured for the previous one.
  const loaderRef = useRef(loadSnapshot);
  useEffect(() => {
    loaderRef.current = loadSnapshot;
  }, [loadSnapshot]);
  // The open-time read happens once per open. A live token tick, or a newer
  // recorded reading the store already delivered, must not ask the host again.
  const readIssuedRef = useRef(false);
  useEffect(() => {
    let current = true;
    const loader = loaderRef.current;
    if (!loader || unsupported || readIssuedRef.current) {
      return () => { current = false; };
    }
    readIssuedRef.current = true;
    if (!snapshot) setStatus('loading');
    void loader().then(result => {
      if (!current || result.status === 'stale') return;
      if (result.snapshot) {
        // A reading delivered while this read was in flight may already be
        // newer: never let a slow answer move the overview backwards.
        const next = loadedRef.current
          ? adoptNewerSnapshot(loadedRef.current, result.snapshot)
          : result.snapshot;
        if (next !== loadedRef.current) {
          loadedRef.current = next;
          setLoaded(next);
        }
        setStatus('ready');
        setUnavailableReason(result.unavailableReason);
        return;
      }
      // An already-stored snapshot stays on screen; a failed read only reports
      // a status when there is nothing recorded to show.
      if (result.status === 'unsupported') {
        setStatus('unsupported');
        // A refused read may carry its own reason (a dispatch target owns the
        // record); say that instead of the generic host message.
        setUnavailableReason(result.unavailableReason);
      } else if (result.status === 'unavailable') {
        setStatus('unavailable');
        setUnavailableReason(result.unavailableReason);
      } else if (result.status === 'failed') {
        setStatus('error');
        setUnavailableReason(result.errorMessage);
      }
    }, () => {
      if (current) setStatus('error');
    });
    return () => { current = false; };
  }, [snapshot, unsupported]);

  // The ring, the overview and the side panel present one recorded reading: adopt
  // a newer one the store delivered while this overview is open. This is a
  // presentation update only; it never issues another host read.
  useEffect(() => {
    if (!snapshot) return;
    const next = loadedRef.current ? adoptNewerSnapshot(loadedRef.current, snapshot) : snapshot;
    if (next === loadedRef.current) return;
    loadedRef.current = next;
    setLoaded(next);
    setStatus('ready');
    setUnavailableReason(undefined);
  }, [snapshot]);

  const layout = useAnchoredPopoverPosition({
    open: true, anchorRef, popoverRef, preferredPlacement: 'top',
    matchAnchorWidth: true, gap: 8, layoutRevision: `${status}:${loaded?.request.attemptId ?? ''}`,
  });
  const close = () => { onClose(); triggerRef.current?.focus(); };
  useDismissibleLayer({
    enabled: true, layerRef: popoverRef, branchRefs: [triggerRef],
    onDismiss: reason => {
      if (reason === 'escape-key') close();
      else onClose();
    },
  });
  useEffect(() => { popoverRef.current?.focus(); }, []);

  const categoryValues = new Map((view?.categories ?? []).map(row => [row.key, row.value]));
  const categoriesReady = view?.categoryState === 'ready' && categoryValues.size > 0;
  const rows = categoriesReady
    ? REQUEST_CONTEXT_SNAPSHOT_CATEGORIES.filter(key => (
        key !== 'summarizedConversation' || (categoryValues.get(key) ?? 0) > 0
      ))
    : [];
  const capacity = view?.max;
  const used = view?.used;
  const percentage = used !== undefined && capacity !== undefined ? used / capacity * 100 : undefined;
  const hasDistribution = categoriesReady
    && used !== undefined
    && capacity !== undefined
    && used <= capacity;
  const chartRows = hasDistribution
    ? [
        ...rows.map(key => ({ key, value: categoryValues.get(key) ?? 0 })),
        { key: 'unused', value: capacity - used },
      ]
    : [];
  const series = chartRows.map(row => ({ ...row, share: row.value / capacity! }));
  const { highlight } = useUsageSeriesHighlight(series);
  const legacyUsed = currentTokens > 0 ? currentTokens : undefined;
  const emptyStatus = describeEmptyStatus(status, view, !!loaded, t, unavailableReason);

  return createOverlayPortal(
    <Card ref={popoverRef} id={id} role="dialog" aria-label={t('usage.context.title')}
      tabIndex={-1} appearance="raised" radius="lg" className="context-usage-popover"
      data-openbitfun-product-component="context-usage-popover" data-openbitfun-product-part="root"
      data-testid="context-usage-popover" data-openbitfun-native-webview-occlusion
      style={{ left: layout?.left ?? 0, top: layout?.top ?? 0, width: layout?.width,
        visibility: layout ? 'visible' : 'hidden' }}>
      <div className="context-usage-popover__header"
        data-openbitfun-product-component="context-usage-popover" data-openbitfun-product-part="header">
        <Tooltip content={t('usage.context.estimateHelp')}>
          <span>{t('usage.context.title')}</span>
        </Tooltip>
        <div className="context-usage-popover__header-actions">
          {onCompact && (
            <Tooltip content={t('chatInput.compactAction')}>
              <IconButton size="xs" icon={<Icon glyph={Shrink} size="sm" />}
                aria-label={t('chatInput.compactAction')} onClick={onCompact}
                disabled={compactDisabled} data-testid="context-usage-compact" />
            </Tooltip>
          )}
          <Tooltip content={t('usage.context.viewReport')}>
            <IconButton size="xs" icon={<Icon glyph={ChartPie} size="sm" />}
              aria-label={t('usage.context.viewReport')} onClick={onViewReport}
              data-testid="context-usage-view-report" />
          </Tooltip>
          <Tooltip content={t('usage.context.collapse')}>
            <IconButton size="xs" icon={<Icon glyph={Minus} size="sm" />}
              aria-label={t('usage.context.collapse')} onClick={close} />
          </Tooltip>
        </div>
      </div>
      <div className="context-usage-popover__totals"
        data-openbitfun-product-component="context-usage-popover" data-openbitfun-product-part="totals">
        <span>{percentage !== undefined
          ? t('usage.context.full', { value: formatUsagePercent(percentage, t) }) : t('usage.unavailable')}</span>
        <span>{t('usage.context.tokenCapacity', {
          used: used !== undefined
            ? t(view?.usageState === 'estimated'
              ? 'usage.context.estimatedTokens'
              : 'usage.context.approximateTokens', { value: formatTokenCount(used, t) })
            : t('usage.unavailable'),
          size: formatTokenCount(capacity, t),
        })}</span>
      </div>
      <div className="context-usage-popover__body"
        data-openbitfun-product-component="context-usage-popover" data-openbitfun-product-part="body">
        {loaded && view?.usageState === 'estimated' && (
          <p className="context-usage-popover__status" role="status"
            data-openbitfun-product-component="context-usage-popover" data-openbitfun-product-part="estimateNote">
            {t('usage.context.estimatedNotReported')}
          </p>
        )}
        {hasDistribution && <div className="context-usage-popover__bar" role="img"
          data-openbitfun-product-component="context-usage-popover" data-openbitfun-product-part="bar"
          aria-label={t('usage.context.full', { value: formatUsagePercent(percentage!, t) })}>
          {series.filter(row => row.value > 0).map(row => (
            <span key={row.key} className={`context-usage-popover__segment context-usage-popover__series--${row.key}`}
              data-usage-category={row.key} style={{ flexGrow: row.value }} {...highlight(row)} />
          ))}
        </div>}
        {categoriesReady ? <>
          <dl className="context-usage-popover__legend"
            data-openbitfun-product-component="context-usage-popover" data-openbitfun-product-part="legend">
            {rows.map(key => <div key={key} className="context-usage-popover__row" data-usage-category={key}
              data-openbitfun-product-component="context-usage-popover" data-openbitfun-product-part="item"
              tabIndex={0} {...highlight(series.find(row => row.key === key) ?? { key })}>
              <dt><span aria-hidden="true" className={`context-usage-popover__swatch context-usage-popover__series--${key}`} />
                <OverflowText>{t(`usage.context.categories.${key}`)}</OverflowText>
                {previewSession && loaded && key !== 'summarizedConversation' && key !== 'conversation' && (
                  <Tooltip content={t('usage.context.previewCategory', { category: t(`usage.context.categories.${key}`) })}>
                    <IconButton size="xs" className="context-usage-popover__preview" icon={<Icon glyph={ExternalLink} size="xs" />}
                      aria-label={t('usage.context.previewCategory', { category: t(`usage.context.categories.${key}`) })}
                      loading={previewLoading === key} disabled={previewLoading !== null && previewLoading !== key}
                      onClick={() => { void previewContext(key); }} />
                  </Tooltip>
                )}
              </dt>
              <dd>{formatTokenCount(categoryValues.get(key), t)}</dd>
            </div>)}
          </dl>
          {used !== undefined && capacity !== undefined && !hasDistribution && (
            <p className="context-usage-popover__status" role="status">
              <span data-openbitfun-product-component="context-usage-popover" data-openbitfun-product-part="status">
                {t('usage.context.exceedsCapacity')}
              </span>
            </p>
          )}
          {capacity === undefined && (
            <p className="context-usage-popover__status" role="status">
              <span data-openbitfun-product-component="context-usage-popover" data-openbitfun-product-part="status">
                {t('usage.context.capacityUnavailable')}
              </span>
            </p>
          )}
        </> : (
          <div className="context-usage-popover__empty" role="status" aria-live="polite" aria-busy={status === 'loading'}>
            <Empty icon={<Icon glyph={ChartPie} />} imageSize="sm" title={
              <span data-openbitfun-product-component="context-usage-popover" data-openbitfun-product-part="status">
                {emptyStatus}
              </span>
            } description={view?.unavailableReason ?? unavailableReason} />
            {!loaded && legacyUsed !== undefined && (
              <p className="context-usage-popover__status" role="status">
                <span data-openbitfun-product-component="context-usage-popover" data-openbitfun-product-part="legacyTotal">
                  {t('usage.context.legacyTotal', { value: formatTokenCount(legacyUsed, t) })}
                </span>
              </p>
            )}
          </div>
        )}
      </div>
    </Card>,
    getAppearanceOverlayHost(), undefined, { ownerRef: triggerRef },
  );
}

function describeEmptyStatus(
  status: SnapshotStatus,
  view: RequestContextSnapshotView | undefined,
  hasSnapshot: boolean,
  t: (key: string, params?: Record<string, unknown>) => string,
  unavailableReason?: string,
): string {
  if (status === 'loading') return t('usage.context.loading');
  if (status === 'error') return t('usage.context.loadFailed');
  // A refused read with an explicit host reason (a dispatch target owns the
  // record) names it instead of claiming this host records nothing.
  if (status === 'unsupported') return unavailableReason ?? t('usage.context.snapshotUnsupported');
  if (!hasSnapshot) return t('usage.context.noRecordedRequest');
  if (view?.categoryState === 'pending') return t('usage.context.pendingClassification');
  if (view?.usageState === 'unknown') return t('usage.context.unknownUsage');
  if (view?.categoryState === 'unavailable') return t('usage.context.summaryUnavailable');
  return t('usage.context.unavailable');
}

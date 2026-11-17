import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useI18n } from '@/infrastructure/i18n';
import { MarkdownRenderer } from '@/infrastructure/markdown';
import { Empty, Icon, IconButton, LoadingState, PageHeader, ScrollArea, Tooltip } from '@openbitfun/ui';
import type {
  SessionUsageReport,
  UsageRequestSnapshot,
} from '@/infrastructure/api/service-api/SessionAPI';
import {
  buildSessionUsageExportMarkdown,
  isUnusedSession,
  getUsageFileNameFromPath,
  getUsageExportRedactPathsPreference,
  subscribeUsageExportRedactPathsPreference,
} from './usageReportUtils';
import { SessionUsageSummary } from './SessionUsageSummary';
import { SessionUsageEmptyState } from './SessionUsageEmptyState';
import { useContextPreview } from './useContextPreview';
import type { SessionUsagePanelTab } from './sessionUsagePanelTypes';
import { flowChatStore } from '../../store/FlowChatStore';
import {
  readRequestContextSnapshot,
  surfaceSupportsRequestContextSnapshot,
} from '../../services/requestContextSnapshotService';
import './SessionUsagePanel.scss';

/** Same recorded request, by the identity core compares. */
function sameRequestIdentity(a: UsageRequestSnapshot, b: UsageRequestSnapshot): boolean {
  return a.request.executionHostId === b.request.executionHostId
    && (a.request.workspaceId ?? '') === (b.request.workspaceId ?? '')
    && a.request.sessionId === b.request.sessionId
    && a.request.turnId === b.request.turnId
    && a.request.roundId === b.request.roundId
    && a.request.attemptId === b.request.attemptId;
}

/** Newest attempt wins; a same-attempt answer may replace, never regress. */
function isSnapshotNewerOrEqual(candidate: UsageRequestSnapshot, current: UsageRequestSnapshot): boolean {
  if (sameRequestIdentity(candidate, current)) return true;
  if (candidate.request.startedAt !== current.request.startedAt) {
    return candidate.request.startedAt > current.request.startedAt;
  }
  // A different request with the same order is not newer: the store rejects it,
  // so a same-order snapshot from another Turn may not replace this reading.
  return candidate.request.attemptIndex > current.request.attemptIndex;
}

/**
 * The better of two readings of one session. The store owns the identity/order
 * compare-and-set, so a late report or a slow read may never overwrite the
 * newer reading an event already delivered.
 */
function preferredSnapshot(
  incoming: UsageRequestSnapshot | undefined,
  current: UsageRequestSnapshot | undefined,
): UsageRequestSnapshot | undefined {
  if (!incoming) return current;
  if (!current) return incoming;
  if (sameRequestIdentity(incoming, current)) {
    return incoming.capturedAt >= current.capturedAt ? incoming : current;
  }
  return isSnapshotNewerOrEqual(incoming, current) ? incoming : current;
}

interface SessionUsagePanelProps {
  report?: SessionUsageReport;
  markdown?: string;
  sessionId?: string;
  sessionTitle?: string;
  isLoading?: boolean;
  error?: string;
  /** Calm copy when the executing host does not offer the report. */
  unsupported?: string;
  workspacePath?: string;
  workspaceId?: string;
  onTitleChange?: (title: string) => void;
  /** Accepted for saved panels from versions with detail tabs. */
  initialTab?: SessionUsagePanelTab;
}

export const SessionUsagePanel: React.FC<SessionUsagePanelProps> = ({
  report,
  markdown = '',
  sessionId,
  sessionTitle,
  isLoading = false,
  error,
  unsupported,
  workspacePath,
  workspaceId,
  onTitleChange,
}) => {
  const { t } = useI18n('flow-chat');
  const reportTitle = t('usage.panel.report');
  const [copied, setCopied] = useState(false);
  const effectiveSessionId = sessionId ?? report?.sessionId;
  const effectiveWorkspaceId = workspaceId ?? report?.workspace.workspaceId;
  /**
   * The context section reads the recorded snapshot, never a rebuilt estimate.
   * The report's own echo and the store's live reading are merged by request
   * identity and attempt order, so the panel shows the same reading as the ring
   * and the overview even when an event lands after the panel opened.
   */
  const [snapshot, setSnapshot] = useState<UsageRequestSnapshot | undefined>(
    () => report?.requestSnapshot?.snapshot
      ?? (effectiveSessionId
        ? flowChatStore.getState().sessions.get(effectiveSessionId)?.requestContextSnapshot
        : undefined),
  );
  /** The session the state belongs to: an answer for a previous one is dropped. */
  const snapshotSessionRef = useRef(effectiveSessionId);
  snapshotSessionRef.current = effectiveSessionId;
  /**
   * Why the surface refused a recorded read (an external agent or a dispatch
   * target owns the record). It belongs to one session and one reading, so it
   * resets whenever either changes and is only shown with no snapshot.
   */
  const [snapshotUnavailableReason, setSnapshotUnavailableReason] = useState<string | undefined>();

  useEffect(() => {
    setSnapshotUnavailableReason(undefined);
  }, [effectiveSessionId]);
  useEffect(() => {
    if (snapshot) setSnapshotUnavailableReason(undefined);
  }, [snapshot]);

  const acceptSnapshot = useCallback((
    candidate: UsageRequestSnapshot | undefined,
    sessionId: string | undefined,
  ) => {
    if (!sessionId || sessionId !== snapshotSessionRef.current) return;
    setSnapshot(current => preferredSnapshot(
      candidate,
      // A reading kept from a previous session is not a baseline to compare with.
      current?.request.sessionId === sessionId ? current : undefined,
    ));
  }, []);

  useEffect(() => {
    const currentSessionId = effectiveSessionId;
    snapshotSessionRef.current = currentSessionId;
    const resolved = preferredSnapshot(
      report?.requestSnapshot?.snapshot,
      currentSessionId
        ? flowChatStore.getState().sessions.get(currentSessionId)?.requestContextSnapshot
        : undefined,
    );
    // A session with no reading clears the previous one instead of keeping its
    // numbers on screen.
    setSnapshot(current => preferredSnapshot(
      resolved,
      current?.request.sessionId === currentSessionId ? current : undefined,
    ));
    if (resolved || !currentSessionId || !surfaceSupportsRequestContextSnapshot()) return;
    let live = true;
    void readRequestContextSnapshot({
      sessionId: currentSessionId,
      workspaceId: effectiveWorkspaceId,
    }).then(result => {
      if (!live || currentSessionId !== snapshotSessionRef.current) return;
      const candidate = result.snapshot
        ?? flowChatStore.getState().sessions.get(currentSessionId)?.requestContextSnapshot;
      if (candidate) {
        acceptSnapshot(candidate, currentSessionId);
        return;
      }
      // A refused read explains itself; a plain empty answer does not.
      if (result.status === 'unsupported' && result.unavailableReason) {
        setSnapshotUnavailableReason(result.unavailableReason);
      }
    }, () => undefined);
    return () => { live = false; };
  }, [report, effectiveSessionId, effectiveWorkspaceId, acceptSnapshot]);

  // Follow the same stored reading the ring and the overview use.
  useEffect(() => {
    if (!effectiveSessionId) return;
    const sessionId = effectiveSessionId;
    return flowChatStore.subscribeSelector(
      state => state.sessions.get(sessionId)?.requestContextSnapshot,
      stored => acceptSnapshot(stored, sessionId),
    );
  }, [effectiveSessionId, acceptSnapshot]);

  const { previewLoading, previewContext: handlePreviewContext } = useContextPreview({
    sessionId: effectiveSessionId,
    reportSessionId: report?.sessionId,
    workspaceId: effectiveWorkspaceId,
    request: snapshot?.request,
  });
  const [redactExportPaths, setRedactExportPaths] = useState(getUsageExportRedactPathsPreference);

  useEffect(() => (
    subscribeUsageExportRedactPathsPreference(setRedactExportPaths)
  ), []);

  useEffect(() => {
    onTitleChange?.(reportTitle);
  }, [onTitleChange, reportTitle]);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(buildSessionUsageExportMarkdown(markdown, report, {
        redactPaths: redactExportPaths,
        t,
      }));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
    }
  }, [markdown, redactExportPaths, report, t]);

  if (isLoading || error || unsupported) {
    return (
      <div className="session-usage-panel session-usage-panel--status" data-openbitfun-product-component="session-usage-panel" data-openbitfun-product-part="root">
        {isLoading ? (
          <LoadingState role="status" aria-live="polite">{t('usage.loading.title')}</LoadingState>
        ) : unsupported ? (
          <Empty title={unsupported} />
        ) : (
          <Empty title={t('usage.panel.failed')} description={error} />
        )}
      </div>
    );
  }

  if (!report) {
    return (
      <ScrollArea data-openbitfun-product-component="session-usage-panel" data-openbitfun-product-part="root" data-openbitfun-state="fallback" className="session-usage-panel session-usage-panel--fallback">
        <div className="session-usage-panel__fallback-toolbar" data-openbitfun-product-component="session-usage-panel" data-openbitfun-product-part="header">
          <Tooltip content={copied ? t('usage.actions.copied') : t('usage.actions.copyMarkdown')}>
            <IconButton
              size="sm"
              onClick={handleCopy}
              aria-label={copied ? t('usage.actions.copied') : t('usage.actions.copyMarkdown')}
              icon={copied ? <Icon name="check-line" size="sm" /> : <Icon name="duplicate" size="sm" />}
            />
          </Tooltip>
        </div>
        <MarkdownRenderer content={markdown} />
      </ScrollArea>
    );
  }

  if (isUnusedSession(report)) {
    return (
      <div className="session-usage-panel session-usage-panel--status" data-openbitfun-product-component="session-usage-panel" data-openbitfun-product-part="root">
        <SessionUsageEmptyState />
      </div>
    );
  }

  const effectiveWorkspacePath = workspacePath ?? report.workspace.pathLabel;
  const workspaceName = effectiveWorkspacePath?.trim()
    ? getUsageFileNameFromPath(effectiveWorkspacePath.trim())
    : t('usage.unavailable');
  /**
   * Only the denominator may come from outside the snapshot, and only from the
   * Session's configured model window. The legacy report composition
   * (`context`/`contextEstimate`) never supplies a context number here: its
   * values are a rebuild of the current prompt, not the recorded request.
   */
  const configuredContextWindow = effectiveSessionId
    ? flowChatStore.getState().sessions.get(effectiveSessionId)?.maxContextTokens
    : undefined;
  return (
    <ScrollArea data-openbitfun-product-component="session-usage-panel" data-openbitfun-product-part="root" className="session-usage-panel">
      <div className="session-usage-panel__intro">
        <p className="session-usage-panel__eyebrow">{reportTitle}</p>
        <PageHeader
          className="session-usage-panel__header"
          data-openbitfun-product-component="session-usage-panel"
          data-openbitfun-product-part="header"
          level={2}
          size="lg"
          title={<span className="session-usage-panel__title">{sessionTitle || reportTitle}</span>}
          action={
            <Tooltip content={copied ? t('usage.actions.copied') : t('usage.actions.copyMarkdown')}>
              <IconButton
                size="sm"
                onClick={handleCopy}
                aria-label={copied ? t('usage.actions.copied') : t('usage.actions.copyMarkdown')}
                icon={copied ? <Icon name="check-line" size="sm" /> : <Icon name="duplicate" size="sm" />}
              />
            </Tooltip>
          }
        />
      </div>

      <SessionUsageSummary report={report} snapshot={snapshot}
        snapshotUnavailableReason={snapshotUnavailableReason}
        fallbackContextWindow={configuredContextWindow}
        workspaceName={workspaceName} onPreviewContext={handlePreviewContext} previewLoading={previewLoading} />
    </ScrollArea>
  );
};

SessionUsagePanel.displayName = 'SessionUsagePanel';

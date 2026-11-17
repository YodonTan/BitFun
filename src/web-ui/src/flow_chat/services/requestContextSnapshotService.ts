import {
  sessionAPI,
  type SessionUsageReport,
  type UsageContextCategory,
  type UsageRequestRef,
  type UsageRequestSnapshot,
  type UsageRequestSnapshotPreview,
} from '@/infrastructure/api/service-api/SessionAPI';
import {
  getActiveSurfaceScope,
  isSurfaceChangedError,
  type SurfaceScope,
} from '@/infrastructure/peer-device/deviceSurface';
import { peerConnectionManager } from '@/infrastructure/peer-device/PeerConnectionManager';
import { canReadRequestContextSnapshotOnSurface } from '@/infrastructure/peer-device/peerCapabilityResolution';
import { classifyPeerHostRefusal } from '@/infrastructure/peer-device/peerHostRefusal';
import { createLogger } from '@/shared/utils/logger';
import { flowChatStore } from '../store/FlowChatStore';
import { resolveSessionDriverId } from '../session-drivers/resolve';

const log = createLogger('RequestContextSnapshot');

/**
 * Why a dispatch projection is not read on the controller.
 *
 * The job's snapshot is recorded by the target core and reaches this surface as
 * the target's event; a controller-side read would be a different conversation
 * with no such request recorded, so it must not be reported as "no recorded
 * request" for this session.
 */
const DISPATCH_SNAPSHOT_OWNED_BY_TARGET =
  'This session runs on a dispatch target. Its recorded request snapshot arrives from the target host.';

/**
 * `unsupported` means this surface cannot read the snapshot at all (an older
 * peer host, or a dispatch projection whose target owns the record),
 * `unavailable` means the host advertises the mode but has nothing recorded,
 * and `stale` means the reading belonged to a surface activation that ended.
 */
export type RequestContextSnapshotReadStatus =
  | 'ready'
  | 'unsupported'
  | 'unavailable'
  | 'stale'
  | 'failed';

export interface RequestContextSnapshotReadResult {
  status: RequestContextSnapshotReadStatus;
  snapshot?: UsageRequestSnapshot;
  /** Whether the store accepted the snapshot under its identity/order rules. */
  stored?: boolean;
  unavailableReason?: string;
  errorMessage?: string;
}

export interface ReadRequestContextSnapshotOptions {
  sessionId: string;
  workspaceId?: string;
}

const inFlightReads = new Map<string, Promise<RequestContextSnapshotReadResult>>();

/** Whether the rendered surface can record and read request-context snapshots. */
export function surfaceSupportsRequestContextSnapshot(): boolean {
  const scope = getActiveSurfaceScope();
  const capabilities = scope.surfaceId === 'local'
    ? null
    : peerConnectionManager.get(scope.surfaceId)?.getState().capabilities ?? null;
  return canReadRequestContextSnapshotOnSurface(scope.surfaceId !== 'local', capabilities);
}

function readKey(scope: SurfaceScope, sessionId: string): string {
  return scope.key('request-context-snapshot', sessionId);
}

function echoMatchesRequest(
  actual: UsageRequestRef | undefined | null,
  expected: UsageRequestRef,
): boolean {
  return !!actual
    && actual.executionHostId === expected.executionHostId
    && (actual.workspaceId ?? '') === (expected.workspaceId ?? '')
    && actual.sessionId === expected.sessionId
    && actual.turnId === expected.turnId
    && actual.roundId === expected.roundId
    && actual.attemptId === expected.attemptId;
}

/**
 * Read the latest recorded request-context snapshot of one Session.
 *
 * This is the default context overview's only read: it asks for the snapshot
 * alone (fast metadata path), never the cumulative report or an on-demand
 * context estimate, and never scans the send path. Concurrent callers on the
 * same surface and Session share one request.
 */
export function readRequestContextSnapshot(
  options: ReadRequestContextSnapshotOptions,
): Promise<RequestContextSnapshotReadResult> {
  const scope = getActiveSurfaceScope();
  if (!surfaceSupportsRequestContextSnapshot()) {
    return Promise.resolve({ status: 'unsupported' });
  }
  const key = readKey(scope, options.sessionId);
  const existing = inFlightReads.get(key);
  if (existing) return existing;

  const request = readSnapshot(scope, options)
    .catch((error: unknown): RequestContextSnapshotReadResult => {
      // A surface switch during the read is control flow, not a failure.
      if (isSurfaceChangedError(error) || !scope.isCurrent()) return { status: 'stale' };
      log.warn('Request context snapshot read failed', { sessionId: options.sessionId, error });
      return {
        status: classifyPeerHostRefusal(error) ? 'unsupported' : 'failed',
        errorMessage: error instanceof Error ? error.message : undefined,
      };
    })
    .finally(() => {
      if (inFlightReads.get(key) === request) inFlightReads.delete(key);
    });
  inFlightReads.set(key, request);
  return request;
}

async function readSnapshot(
  scope: SurfaceScope,
  options: ReadRequestContextSnapshotOptions,
): Promise<RequestContextSnapshotReadResult> {
  const session = flowChatStore.getState().sessions.get(options.sessionId);
  // A dispatch projection is owned by its target: its snapshot arrives as the
  // target's event, never from a controller-side read.
  if (resolveSessionDriverId(options.sessionId, session) === 'dispatch') {
    return { status: 'unsupported', unavailableReason: DISPATCH_SNAPSHOT_OWNED_BY_TARGET };
  }
  const workspaceId = options.workspaceId
    || session?.workspaceId
    || session?.config?.workspaceId;
  if (!workspaceId) {
    // Without an owning workspace the host cannot scope the read; this is the
    // same "no recorded request" state as a Session that never sent a request.
    return { status: 'unavailable' };
  }
  const report = await sessionAPI.getSessionUsageReport({
    sessionId: options.sessionId,
    workspaceId,
    includeHiddenSubagents: false,
    requestSnapshot: {},
  });
  if (!scope.isCurrent()) return { status: 'stale' };

  const view = report.requestSnapshot;
  if (!view?.snapshot) {
    return { status: 'unavailable' };
  }
  // A response that describes another Session belongs to a scope this surface
  // no longer renders. Host and workspace scope are enforced by the store's
  // acceptance rules, which own the identity compare-and-set.
  if (view.snapshot.request.sessionId !== options.sessionId) {
    return { status: 'unavailable' };
  }

  const stored = flowChatStore.setRequestContextSnapshot(options.sessionId, view.snapshot);
  // A rejected write (older attempt, another scope) must not hand an outdated
  // reading back to the surface: keep showing what the store accepted.
  const authoritative = flowChatStore.getState().sessions.get(options.sessionId)?.requestContextSnapshot;
  if (!stored) {
    if (!authoritative) return { status: 'unavailable' };
    return { status: 'ready', stored, snapshot: authoritative, unavailableReason: authoritative.unavailableReason };
  }
  return {
    status: 'ready',
    stored,
    snapshot: view.snapshot,
    unavailableReason: view.snapshot.unavailableReason,
  };
}

export interface RequestContextSnapshotPreviewResult {
  status: 'opened' | 'unavailable' | 'stale' | 'unsupported';
  preview?: UsageRequestSnapshotPreview;
  unavailableReason?: string;
}

/**
 * Read one explicit category preview of one fixed recorded request.
 *
 * The response must echo the requested identity and category; a different echo
 * is a stale answer about another request and is discarded rather than shown
 * as if it belonged to this one.
 */
export async function readRequestContextSnapshotPreview(params: {
  sessionId: string;
  workspaceId?: string;
  request: UsageRequestRef;
  category: UsageContextCategory;
}): Promise<RequestContextSnapshotPreviewResult> {
  const scope = getActiveSurfaceScope();
  if (!surfaceSupportsRequestContextSnapshot()) {
    return { status: 'unsupported' };
  }
  const session = flowChatStore.getState().sessions.get(params.sessionId);
  if (resolveSessionDriverId(params.sessionId, session) === 'dispatch') {
    return { status: 'unsupported', unavailableReason: DISPATCH_SNAPSHOT_OWNED_BY_TARGET };
  }
  const workspaceId = params.workspaceId
    || session?.workspaceId
    || session?.config?.workspaceId;
  if (!workspaceId) return { status: 'unavailable' };

  let report: SessionUsageReport;
  try {
    report = await sessionAPI.getSessionUsageReport({
      sessionId: params.sessionId,
      workspaceId,
      includeHiddenSubagents: false,
      requestSnapshot: { request: params.request, category: params.category },
    });
  } catch (error) {
    if (isSurfaceChangedError(error) || !scope.isCurrent()) return { status: 'stale' };
    if (classifyPeerHostRefusal(error)) return { status: 'unsupported' };
    throw error;
  }
  if (!scope.isCurrent()) return { status: 'stale' };

  const view = report.requestSnapshot;
  if (!view || view.snapshot.request.sessionId !== params.sessionId) {
    return { status: 'unavailable' };
  }
  if (!echoMatchesRequest(view.snapshot.request, params.request)) {
    return { status: 'stale' };
  }
  const preview = view.preview;
  if (!preview) {
    return { status: 'unavailable', unavailableReason: view.snapshot.unavailableReason };
  }
  if (preview.category !== params.category || !echoMatchesRequest(preview.request, params.request)) {
    return { status: 'stale' };
  }
  if (preview.unavailableReason) {
    return { status: 'unavailable', unavailableReason: preview.unavailableReason };
  }
  return { status: 'opened', preview };
}

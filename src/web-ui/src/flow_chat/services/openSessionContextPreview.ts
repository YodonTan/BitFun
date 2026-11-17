import {
  sessionAPI,
  type UsageContextCategory,
  type UsageContextEstimate,
  type UsageRequestRef,
} from '@/infrastructure/api/service-api/SessionAPI';
import { getActiveSurfaceScope } from '@/infrastructure/peer-device/deviceSurface';
import { openAgentCanvasTabForSession, useAgentCanvasStore } from '@/app/components/panels/content-canvas/stores/canvasStore';
import { flowChatStore } from '../store/FlowChatStore';
import { resolveSessionDriverId } from '../session-drivers/resolve';
import { classifyPeerHostRefusal } from '@/infrastructure/peer-device/peerHostRefusal';
import { readRequestContextSnapshotPreview } from './requestContextSnapshotService';

const PREVIEW_FILE_NAMES: Record<UsageContextCategory, string> = {
  systemPrompt: 'system-prompt.md',
  toolDefinitions: 'tool-definitions.md',
  rules: 'rules.md',
  skills: 'skills.md',
  mcpTools: 'mcp-and-dynamic-tools.md',
  subagentDefinitions: 'subagent-definitions.md',
};

export async function openSessionContextPreview(params: {
  sessionId: string;
  reportSessionId: string;
  workspaceId?: string;
  title: string;
  category: UsageContextCategory;
  emptyContent: string;
  /**
   * Read the preview from this exact recorded request. The response must echo
   * this identity; a different echo is discarded as stale instead of being
   * shown as if it described this request.
   */
  request?: UsageRequestRef;
  /** Reuse the overview query so numbers and text describe the same instant. */
  estimate?: UsageContextEstimate;
  onEstimate?: (estimate: UsageContextEstimate) => void;
  /** Explicit host reason when a recorded preview is gone or unavailable. */
  onUnavailableReason?: (reason?: string) => void;
}): Promise<'opened' | 'unavailable' | 'stale'> {
  const surface = getActiveSurfaceScope();
  const session = flowChatStore.getState().sessions.get(params.sessionId);
  const workspaceId = params.workspaceId || session?.workspaceId || session?.config?.workspaceId;
  // Dispatch reports belong to the target. Never read the controller's prompt cache.
  if (!workspaceId || params.sessionId !== params.reportSessionId
    || resolveSessionDriverId(params.sessionId, session) !== 'local') return 'unavailable';

  const openPreviewTab = (content: string, capturedAt?: number): void => {
    openAgentCanvasTabForSession(params.sessionId, {
      type: params.category === 'toolDefinitions' ? 'tool-definitions' : 'markdown-editor',
      title: params.title,
      data: params.category === 'toolDefinitions' ? { content, readOnly: true }
        : { initialContent: content.trim() ? content : params.emptyContent, fileName: PREVIEW_FILE_NAMES[params.category], readOnly: true },
      metadata: {
        duplicateCheckKey: params.category === 'systemPrompt' ? `session-system-prompt-${params.sessionId}`
          : `session-context-${params.category}-${params.sessionId}`,
        sessionId: params.sessionId,
        capturedAt,
        resourceScope: { surfaceId: surface.surfaceId, workspaceId },
      },
    });
    if (useAgentCanvasStore.getState().scopeKey === params.sessionId && typeof window !== 'undefined') {
      window.dispatchEvent(new window.CustomEvent('expand-right-panel'));
    }
  };

  if (params.request) {
    const result = await readRequestContextSnapshotPreview({
      sessionId: params.sessionId,
      workspaceId,
      request: params.request,
      category: params.category,
    });
    if (result.status === 'stale') return 'stale';
    if (result.status !== 'opened' || !result.preview) {
      params.onUnavailableReason?.(result.unavailableReason);
      return 'unavailable';
    }
    if (!surface.isCurrent()) return 'stale';
    openPreviewTab(result.preview.content, result.preview.capturedAt);
    return 'opened';
  }

  let estimate = params.estimate;
  if (!estimate) {
    try {
      const report = await sessionAPI.getSessionUsageReport({
        sessionId: params.sessionId, workspaceId, includeHiddenSubagents: false,
        contextEstimate: { includeContents: true, contextOnly: true },
      });
      if (!surface.isCurrent()) return 'stale';
      if (report.sessionId !== params.sessionId) return 'unavailable';
      estimate = report.contextEstimate;
    } catch (error) {
      if (classifyPeerHostRefusal(error)) return surface.isCurrent() ? 'unavailable' : 'stale';
      throw error;
    }
  }
  if (!surface.isCurrent()) return 'stale';
  if (estimate) params.onEstimate?.(estimate);
  const content = estimate?.contents?.[params.category];
  if (typeof content !== 'string') return 'unavailable';

  openPreviewTab(content, estimate?.capturedAt);
  return 'opened';
}

import { useEffect, useRef, useState } from 'react';
import { useI18n } from '@/infrastructure/i18n';
import type {
  UsageContextCategory,
  UsageContextEstimate,
  UsageRequestRef,
} from '@/infrastructure/api/service-api/SessionAPI';
import { openSessionContextPreview } from '../../services/openSessionContextPreview';
import { notificationService } from '@/shared/notification-system';
import { getActiveSurfaceScope, isSurfaceChangedError } from '@/infrastructure/peer-device/deviceSurface';

/**
 * Both usage surfaces open the same session-owned, capability-checked preview.
 *
 * `request` pins the preview to one recorded request. The host echoes that
 * identity back, and a different echo is dropped as stale rather than shown as
 * this request's content.
 */
export function useContextPreview(params: {
  sessionId?: string;
  reportSessionId?: string;
  workspaceId?: string;
  request?: UsageRequestRef;
  estimate?: UsageContextEstimate;
  onEstimate?: (estimate: UsageContextEstimate) => void;
}) {
  const { t } = useI18n('flow-chat');
  const [previewLoading, setPreviewLoading] = useState<UsageContextCategory | null>(null);
  const requestRef = useRef<symbol | null>(null);
  useEffect(() => {
    requestRef.current = null;
    setPreviewLoading(null);
    return () => { requestRef.current = null; };
  }, [params.sessionId, params.reportSessionId, params.workspaceId, params.request?.attemptId]);

  const previewContext = async (category: UsageContextCategory) => {
    if (!params.sessionId || !params.reportSessionId || requestRef.current) return;
    const request = Symbol();
    requestRef.current = request;
    const surface = getActiveSurfaceScope();
    const isCurrent = () => surface.isCurrent() && requestRef.current === request;
    let reasonNotified = false;
    setPreviewLoading(category);
    try {
      const result = await openSessionContextPreview({
        sessionId: params.sessionId, reportSessionId: params.reportSessionId, workspaceId: params.workspaceId,
        title: `${t(`usage.context.categories.${category}`)}${category === 'toolDefinitions' ? '' : '.md'}`,
        category, request: params.request, estimate: params.estimate,
        onEstimate: estimate => { if (isCurrent()) params.onEstimate?.(estimate); },
        onUnavailableReason: reason => {
          if (!isCurrent()) return;
          reasonNotified = true;
          notificationService.warning(t('usage.context.previewUnavailable'), {
            ...(reason ? { title: reason } : {}),
          });
        },
        emptyContent: t('usage.context.previewEmpty'),
      });
      if (isCurrent() && result === 'stale') notificationService.warning(t('usage.context.previewStale'));
      else if (isCurrent() && result === 'unavailable' && !reasonNotified) {
        notificationService.warning(t('usage.context.previewUnavailable'));
      }
    } catch (error) {
      if (isCurrent() && !isSurfaceChangedError(error)) notificationService.error(t('usage.context.previewFailed'));
    } finally {
      if (requestRef.current === request) {
        requestRef.current = null;
        setPreviewLoading(null);
      }
    }
  };
  return { previewLoading, previewContext };
}

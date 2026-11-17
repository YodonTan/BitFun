import { beforeEach, describe, expect, it, vi } from 'vitest';
import { activateSurface } from '@/infrastructure/peer-device/deviceSurface';
import { flowChatStore } from '../store/FlowChatStore';
import type { Session } from '../types/flow-chat';
import type { UsageRequestRef, UsageRequestSnapshot } from '@/infrastructure/api/service-api/SessionAPI';
import { readRequestContextSnapshot, readRequestContextSnapshotPreview } from './requestContextSnapshotService';

const apiMocks = vi.hoisted(() => ({ getSessionUsageReport: vi.fn() }));
vi.mock('@/infrastructure/api/service-api/SessionAPI', () => ({ sessionAPI: apiMocks }));

const sessionId = 'snapshot-session';
const workspaceId = 'workspace-1';

const requestRef = (overrides: Partial<UsageRequestRef> = {}): UsageRequestRef => ({
  executionHostId: 'local', workspaceId, sessionId, turnId: 'turn-1', roundId: 'round-1',
  attemptId: 'round-1:attempt:1', attemptIndex: 1, startedAt: 100, ...overrides,
});

const recordedSnapshot = (overrides: Partial<UsageRequestSnapshot> = {}): UsageRequestSnapshot => ({
  schemaVersion: 1, request: requestRef(), capturedAt: 200, inputSource: 'model_request',
  inputTotal: 1000, usageState: 'provider_reported', estimatedTotal: 1000, summaryState: 'ready',
  categories: {
    systemPrompt: 100, toolDefinitions: 100, rules: 100, skills: 100, mcpTools: 100,
    subagentDefinitions: 100, summarizedConversation: 0, conversation: 400, contextWindow: 8000,
  },
  ...overrides,
});

const reportWith = (snapshot?: UsageRequestSnapshot, preview?: unknown) => ({
  sessionId, requestSnapshot: snapshot ? { snapshot, ...(preview ? { preview } : {}) } : undefined,
});

const session = () => ({ sessionId, workspaceId, config: { workspaceId } } as unknown as Session);
const stored = () => flowChatStore.getState().sessions.get(sessionId)?.requestContextSnapshot;

describe('recorded request context snapshot reads', () => {
  beforeEach(() => {
    activateSurface('local');
    flowChatStore.setState(state => ({
      ...state,
      sessions: new Map([[sessionId, session()]]),
      activeSessionId: sessionId,
    }));
    apiMocks.getSessionUsageReport.mockReset().mockResolvedValue(reportWith(recordedSnapshot()));
  });

  it('reads only the recorded snapshot on the fast metadata path and stores it for every surface', async () => {
    const result = await readRequestContextSnapshot({ sessionId });

    expect(apiMocks.getSessionUsageReport).toHaveBeenCalledExactlyOnceWith({
      sessionId, workspaceId, includeHiddenSubagents: false, requestSnapshot: {},
    });
    expect(result).toMatchObject({ status: 'ready', stored: true });
    expect(result.snapshot?.request.attemptId).toBe('round-1:attempt:1');
    expect(stored()?.request.attemptId).toBe('round-1:attempt:1');
  });

  it('shares one in-flight read between the ring, the overview and the panel', async () => {
    let finish: (value: unknown) => void = () => {};
    apiMocks.getSessionUsageReport.mockReturnValue(new Promise(resolve => { finish = resolve; }));

    const first = readRequestContextSnapshot({ sessionId });
    const second = readRequestContextSnapshot({ sessionId });
    finish(reportWith(recordedSnapshot()));

    await expect(first).resolves.toMatchObject({ status: 'ready' });
    await expect(second).resolves.toBe(await first);
    expect(apiMocks.getSessionUsageReport).toHaveBeenCalledOnce();
  });

  it('refuses a peer host that does not advertise the recorded snapshot mode', async () => {
    activateSurface('peer-without-capability');

    await expect(readRequestContextSnapshot({ sessionId })).resolves.toEqual({ status: 'unsupported' });
    expect(apiMocks.getSessionUsageReport).not.toHaveBeenCalled();
  });

  it('drops a reading whose surface activation ended before it arrived', async () => {
    let finish: (value: unknown) => void = () => {};
    apiMocks.getSessionUsageReport.mockReturnValue(new Promise(resolve => { finish = resolve; }));

    const pending = readRequestContextSnapshot({ sessionId });
    activateSurface('peer-host');
    finish(reportWith(recordedSnapshot()));

    await expect(pending).resolves.toEqual({ status: 'stale' });
    expect(stored()).toBeUndefined();
  });

  it('keeps the newest attempt when the host answers with an older one', async () => {
    const newer = recordedSnapshot({
      request: requestRef({ attemptId: 'round-1:attempt:2', attemptIndex: 2, startedAt: 200 }),
      inputTotal: 2000,
    });
    expect(flowChatStore.setRequestContextSnapshot(sessionId, newer)).toBe(true);
    apiMocks.getSessionUsageReport.mockResolvedValue(reportWith(recordedSnapshot()));

    const result = await readRequestContextSnapshot({ sessionId });

    expect(result.status).toBe('ready');
    expect(result.stored).toBe(false);
    // The older answer is dropped; the surface keeps the accepted reading.
    expect(result.snapshot?.inputTotal).toBe(2000);
    expect(stored()?.request.attemptIndex).toBe(2);
  });

  it('never presents a response for another session or a missing snapshot as recorded data', async () => {
    apiMocks.getSessionUsageReport.mockResolvedValueOnce({
      sessionId: 'another-session',
      requestSnapshot: { snapshot: recordedSnapshot({ request: requestRef({ sessionId: 'another-session' }) }) },
    });
    await expect(readRequestContextSnapshot({ sessionId })).resolves.toEqual({ status: 'unavailable' });
    expect(stored()).toBeUndefined();

    apiMocks.getSessionUsageReport.mockResolvedValueOnce({ sessionId });
    await expect(readRequestContextSnapshot({ sessionId })).resolves.toEqual({ status: 'unavailable' });
    expect(stored()).toBeUndefined();
  });

  it('reports an unreadable session as unavailable instead of guessing a workspace', async () => {
    flowChatStore.setState(state => ({ ...state, sessions: new Map() }));

    await expect(readRequestContextSnapshot({ sessionId })).resolves.toEqual({ status: 'unavailable' });
    expect(apiMocks.getSessionUsageReport).not.toHaveBeenCalled();
  });

  it('names the dispatch target as the owner of a projection it will not read', async () => {
    flowChatStore.setState(state => ({
      ...state,
      sessions: new Map([[sessionId, { sessionId, config: { dispatchJobId: 'job-1', workspaceId } } as unknown as Session]]),
    }));

    const result = await readRequestContextSnapshot({ sessionId });

    expect(result).toMatchObject({ status: 'unsupported' });
    expect(result.unavailableReason).toContain('dispatch target');
    expect(apiMocks.getSessionUsageReport).not.toHaveBeenCalled();
  });

  it('reports a host refusal as unsupported and an ordinary failure as failed', async () => {
    apiMocks.getSessionUsageReport.mockRejectedValueOnce(new Error(
      "command 'get_session_usage_report' is not supported on CLI peer host",
    ));
    await expect(readRequestContextSnapshot({ sessionId })).resolves.toMatchObject({ status: 'unsupported' });

    apiMocks.getSessionUsageReport.mockRejectedValueOnce(new Error('Host offline'));
    await expect(readRequestContextSnapshot({ sessionId })).resolves.toMatchObject({
      status: 'failed', errorMessage: 'Host offline',
    });
  });
});

describe('recorded request context snapshot previews', () => {
  const preview = (overrides: Record<string, unknown> = {}) => ({
    category: 'systemPrompt', content: '# System\n\nRecorded prompt.', capturedAt: 123,
    request: requestRef(), ...overrides,
  });

  beforeEach(() => {
    activateSurface('local');
    flowChatStore.setState(state => ({
      ...state,
      sessions: new Map([[sessionId, session()]]),
      activeSessionId: sessionId,
    }));
    apiMocks.getSessionUsageReport.mockReset();
  });

  it('asks for one explicit request and category and returns only the echo that matches', async () => {
    apiMocks.getSessionUsageReport.mockResolvedValue(reportWith(recordedSnapshot(), preview()));

    const result = await readRequestContextSnapshotPreview({
      sessionId, request: requestRef(), category: 'systemPrompt',
    });

    expect(apiMocks.getSessionUsageReport).toHaveBeenCalledExactlyOnceWith({
      sessionId, workspaceId, includeHiddenSubagents: false,
      requestSnapshot: { request: requestRef(), category: 'systemPrompt' },
    });
    expect(result).toMatchObject({ status: 'opened', preview: { content: '# System\n\nRecorded prompt.' } });
  });

  it.each([
    ['another request', () => reportWith(recordedSnapshot(), preview({ request: requestRef({ attemptId: 'round-1:attempt:2' }) }))],
    ['another category', () => reportWith(recordedSnapshot(), preview({ category: 'rules' }))],
    ['another request snapshot', () => reportWith(recordedSnapshot({ request: requestRef({ attemptId: 'round-1:attempt:2' }) }), preview())],
  ])('discards an echo for %s as stale instead of showing it here', async (_label, response) => {
    apiMocks.getSessionUsageReport.mockResolvedValue(response());

    await expect(readRequestContextSnapshotPreview({
      sessionId, request: requestRef(), category: 'systemPrompt',
    })).resolves.toEqual({ status: 'stale' });
  });

  it('reports the explicit unavailable reason when the recorded content is gone', async () => {
    apiMocks.getSessionUsageReport.mockResolvedValue(reportWith(
      recordedSnapshot({ summaryState: 'unavailable', unavailableReason: 'The request was evicted after a restart.' }),
    ));

    await expect(readRequestContextSnapshotPreview({
      sessionId, request: requestRef(), category: 'systemPrompt',
    })).resolves.toEqual({
      status: 'unavailable', unavailableReason: 'The request was evicted after a restart.',
    });

    apiMocks.getSessionUsageReport.mockResolvedValue(reportWith(
      recordedSnapshot(), preview({ content: '', unavailableReason: 'The category was trimmed.' }),
    ));
    await expect(readRequestContextSnapshotPreview({
      sessionId, request: requestRef(), category: 'systemPrompt',
    })).resolves.toEqual({ status: 'unavailable', unavailableReason: 'The category was trimmed.' });
  });

  it('refuses a host without the snapshot mode before asking for a preview', async () => {
    activateSurface('peer-without-capability');

    await expect(readRequestContextSnapshotPreview({
      sessionId, request: requestRef(), category: 'systemPrompt',
    })).resolves.toEqual({ status: 'unsupported' });
    expect(apiMocks.getSessionUsageReport).not.toHaveBeenCalled();
  });

  it('names the dispatch target as the owner instead of reading the controller content', async () => {
    flowChatStore.setState(state => ({
      ...state,
      sessions: new Map([[sessionId, { sessionId, config: { dispatchJobId: 'job-1', workspaceId } } as unknown as Session]]),
    }));

    const result = await readRequestContextSnapshotPreview({
      sessionId, request: requestRef(), category: 'systemPrompt',
    });

    // A dispatch projection's snapshot comes from the target; saying "nothing is
    // recorded" would describe the wrong host.
    expect(result).toMatchObject({ status: 'unsupported' });
    expect(result.unavailableReason).toContain('dispatch target');
    expect(apiMocks.getSessionUsageReport).not.toHaveBeenCalled();
  });
});

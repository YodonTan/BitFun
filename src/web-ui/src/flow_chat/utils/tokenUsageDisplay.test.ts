import { formatDuration } from '@/shared/utils/format';
import { describe, expect, it } from 'vitest';
import type { DialogTurn, Session, TokenUsage } from '../types/flow-chat';
import {
  buildContextUsageTooltip,
  buildModelSelectorTooltipDetails,
  buildModelRoundCompletionMeta,
  DEFAULT_MAX_CONTEXT_TOKENS,
  deriveContextUsageFromTurns,
  formatCompactTokenCount,
  getCompressionTriggerTokens,
  getSessionContextUsageDisplay,
  resolveRequestContextSnapshotView,
} from './tokenUsageDisplay';
import type { UsageRequestSnapshot } from '@/infrastructure/api/service-api/SessionAPI';

const t = (key: string, params?: Record<string, unknown>): string => {
  const strings: Record<string, string> = {
    'modelSelector.contextUsage.agentPrompt': 'Last request prompt: {{usage}}',
    'modelSelector.contextUsage.acpContext': 'ACP reported context: {{usage}}',
    'modelSelector.contextUsage.agentPromptLabel': 'Last request prompt',
    'modelSelector.contextUsage.acpContextLabel': 'ACP reported context',
    'modelSelector.tooltip.configName': 'Configuration',
    'modelSelector.tooltip.modelName': 'Model name',
    'modelSelector.tooltip.contextWindow': 'Context window',
    'modelSelector.tooltip.compressionTrigger': 'Compression trigger',
    'modelSelector.tooltip.longContextWarning': 'Long context warning',
    'modelRound.meta.completed': 'Completed',
    'modelRound.meta.stopped': 'Stopped',
    'modelRound.meta.duration': 'Duration',
  };

  const template = strings[key] ?? key;
  return Object.entries(params ?? {}).reduce(
    (text, [paramKey, value]) => text.replace(`{{${paramKey}}}`, String(value)),
    template,
  );
};

const makeSession = (overrides: Partial<Session> = {}): Session => ({
  sessionId: 'session-1',
  title: 'Session',
  dialogTurns: [],
  status: 'idle',
  config: { agentType: 'Standard' },
  createdAt: 1,
  lastActiveAt: 1,
  error: null,
  isHistorical: false,
  todos: [],
  mode: 'Standard',
  workspacePath: 'D:/workspace/OpenBitFun',
  isTransient: false,
  maxContextTokens: 4000,
  ...overrides,
});

describe('tokenUsageDisplay', () => {
  it('uses prompt/input tokens for non-ACP context usage instead of spent total tokens', () => {
    const session = makeSession({
      currentTokenUsage: {
        inputTokens: 1200,
        outputTokens: 300,
        totalTokens: 1500,
        timestamp: 10,
      },
      maxContextTokens: 4000,
    });

    expect(getSessionContextUsageDisplay(session)).toEqual({
      current: 1200,
      max: 4000,
      source: 'agent_prompt',
    });
  });

  it('preserves ACP-reported context usage as its own source', () => {
    const session = makeSession({
      currentAcpContextUsage: {
        used: 42000,
        size: 128000,
        timestamp: 10,
      },
      // ACP ranks above the legacy ledger even when the legacy value is
      // compression-derived, because ACP reports its own live context size.
      currentTokenUsage: {
        inputTokens: 1200,
        outputTokens: 300,
        totalTokens: 1500,
        timestamp: 10,
        source: 'context_compression',
      },
    });

    expect(getSessionContextUsageDisplay(session)).toEqual({
      current: 42000,
      max: 128000,
      source: 'acp_context',
    });
  });

  it('labels the context usage source without appending the obsolete tool-output caveat', () => {
    const tooltip = buildContextUsageTooltip({
      baseTooltip: 'Claude Sonnet',
      usage: {
        current: 1200,
        max: 4000,
        source: 'agent_prompt',
      },
      t,
    });

    expect(tooltip).toBe(
      'Claude Sonnet · Last request prompt: 1.2K/4K (30%)',
    );
  });

  it('mirrors the runtime compression trigger budget', () => {
    expect(getCompressionTriggerTokens(128_000)).toBe(86_000);
    expect(getCompressionTriggerTokens(128_000, 16_000)).toBe(102_000);
    expect(getCompressionTriggerTokens(256_000)).toBe(214_000);
    expect(getCompressionTriggerTokens(256_000, 64_000)).toBe(182_000);
    expect(getCompressionTriggerTokens(399_999)).toBe(357_999);
    expect(getCompressionTriggerTokens(400_000)).toBe(326_000);
    expect(getCompressionTriggerTokens(1_000_000)).toBe(926_000);
  });

  it('uses the host pool trigger and hides the bound member trigger', () => {
    const pool = buildModelSelectorTooltipDetails({ configName: '', contextWindow: 128_000,
      compressionTriggerTokens: 86_000, configuredMaxOutputTokens: 8_000, t });
    expect(pool.rows).toEqual([
      { key: 'contextWindow', label: 'Context window', value: '128K' },
      { key: 'compressionTrigger', label: 'Compression trigger', value: '86K' },
    ]);
    const member = buildModelSelectorTooltipDetails({ configName: 'Large member', contextWindow: 160_000,
      compressionTriggerTokens: null, usage: { current: 64_000, max: 128_000, source: 'agent_prompt' }, t });
    expect(member.rows).toEqual([
      { key: 'configName', label: 'Configuration', value: 'Large member' },
      { key: 'contextWindow', label: 'Context window', value: '160K' },
      { key: 'contextUsage', label: 'Last request prompt', value: '64K/128K (50%)' },
    ]);
  });

  it('builds labeled model details and puts the long-context warning last', () => {
    expect(buildModelSelectorTooltipDetails({
      configName: 'OpenAI production',
      modelName: 'gpt-5.6-sol',
      contextWindow: 1_000_000,
      usage: {
        current: 120_000,
        max: 1_000_000,
        source: 'agent_prompt',
      },
      t,
    })).toEqual({
      rows: [
        { key: 'configName', label: 'Configuration', value: 'OpenAI production' },
        { key: 'modelName', label: 'Model name', value: 'gpt-5.6-sol' },
        { key: 'contextWindow', label: 'Context window', value: '1M' },
        { key: 'compressionTrigger', label: 'Compression trigger', value: '926K' },
        { key: 'contextUsage', label: 'Last request prompt', value: '120K/1M (12%)' },
      ],
      warning: 'Long context warning',
    });
  });

  it('does not warn when usage is high but the configured context window is not over 400K', () => {
    expect(buildModelSelectorTooltipDetails({
      configName: 'OpenAI production',
      modelName: 'gpt-5.6-sol',
      contextWindow: 400_000,
      usage: {
        current: 390_000,
        max: 400_000,
        source: 'agent_prompt',
      },
      t,
    }).warning).toBeUndefined();
  });

  it('keeps the Primary tooltip to the configuration name when no concrete model is resolved', () => {
    expect(buildModelSelectorTooltipDetails({
      configName: 'Primary model',
      t,
    })).toEqual({
      rows: [
        { key: 'configName', label: 'Configuration', value: 'Primary model' },
      ],
      warning: undefined,
    });
  });

  it('builds only the compact completion time and duration metadata', () => {
    expect(buildModelRoundCompletionMeta({
      completedAt: 1700000000000,
      durationMs: 323000,
      formatTime: () => '12:00:00 PM',
      t,
    })).toEqual([
      { key: 'completed', label: 'Completed', value: '12:00:00 PM' },
      { key: 'duration', label: 'Duration', value: formatDuration(323000) },
    ]);
  });

  it('keeps a stopped round accessible without adding another visual field', () => {
    expect(buildModelRoundCompletionMeta({
      completedAt: 1700000000000,
      durationMs: 12345,
      status: 'cancelled',
      formatTime: () => '12:00:00',
      t,
    })).toEqual([
      { key: 'completed', label: 'Stopped', value: '12:00:00' },
      { key: 'duration', label: 'Duration', value: formatDuration(12345) },
    ]);
  });

  it('omits missing or invalid completion metadata and preserves reported zero duration', () => {
    const formatTime = () => '12:00:00';
    expect(buildModelRoundCompletionMeta({ formatTime, t })).toEqual([]);
    expect(buildModelRoundCompletionMeta({ completedAt: NaN, durationMs: Infinity, formatTime, t })).toEqual([]);
    expect(buildModelRoundCompletionMeta({ durationMs: -1, formatTime, t })).toEqual([]);
    expect(buildModelRoundCompletionMeta({ durationMs: 0, formatTime, t })).toEqual([
      { key: 'duration', label: 'Duration', value: formatDuration(0) },
    ]);
  });

  it('keeps compact token formatting stable for tooltip strings', () => {
    expect(formatCompactTokenCount(950)).toBe('950');
    expect(formatCompactTokenCount(1234)).toBe('1.23K');
    expect(formatCompactTokenCount(12_345)).toBe('12.35K');
    expect(formatCompactTokenCount(1_000_000_000)).toBe('1B');
  });
});

describe('deriveContextUsageFromTurns', () => {
  const makeTurn = (
    overrides: Partial<DialogTurn> & {
      status: DialogTurn['status'];
      tokenUsage?: TokenUsage;
    },
  ): DialogTurn => ({
    id: 'turn-1',
    sessionId: 'session-1',
    userMessage: {
      id: 'user-1',
      content: 'hello',
      timestamp: 1000,
    },
    modelRounds: [{ id: 'round-1' }],
    status: 'completed',
    startTime: 1000,
    ...overrides,
  });

  const usage = (inputTokens: number): TokenUsage => ({
    inputTokens,
    outputTokens: 100,
    totalTokens: inputTokens + 100,
    timestamp: 2000,
  });

  it('returns the last completed turn usage', () => {
    const turns = [
      makeTurn({ id: 'turn-1', status: 'completed', tokenUsage: usage(1000) }),
      makeTurn({ id: 'turn-2', status: 'completed', tokenUsage: usage(2000) }),
    ];

    expect(deriveContextUsageFromTurns(turns)).toEqual({
      ...usage(2000),
      turnId: 'turn-2',
    });
  });

  it('skips unfinished turns and falls back to the last completed turn', () => {
    const turns = [
      makeTurn({ id: 'turn-1', status: 'completed', tokenUsage: usage(1000) }),
      makeTurn({ id: 'turn-2', status: 'processing', tokenUsage: usage(500) }),
      makeTurn({ id: 'turn-3', status: 'pending', tokenUsage: usage(300) }),
    ];

    expect(deriveContextUsageFromTurns(turns)).toEqual({
      ...usage(1000),
      turnId: 'turn-1',
    });
  });

  it('skips turns without usage and returns the last completed one that has it', () => {
    const turns = [
      makeTurn({ id: 'turn-1', status: 'completed' }),
      makeTurn({ id: 'turn-2', status: 'error', tokenUsage: usage(2500) }),
    ];

    expect(deriveContextUsageFromTurns(turns)).toEqual({
      ...usage(2500),
      turnId: 'turn-2',
    });
  });

  it('uses the latest valid terminal usage even when an older turn is invalid', () => {
    const turns = [
      makeTurn({
        id: 'turn-1',
        status: 'completed',
        tokenUsage: { inputTokens: 0, totalTokens: 0, timestamp: 2000 },
      }),
      makeTurn({
        id: 'turn-2',
        status: 'cancelled',
        tokenUsage: { inputTokens: 420, totalTokens: 500, timestamp: 3000 },
      }),
    ];

    expect(deriveContextUsageFromTurns(turns)).toMatchObject({
      inputTokens: 420,
      turnId: 'turn-2',
    });
  });

  it('does not scan past the latest terminal turn when its usage is invalid', () => {
    const turns = [
      makeTurn({ id: 'turn-1', status: 'completed', tokenUsage: usage(1000) }),
      makeTurn({
        id: 'turn-2',
        status: 'completed',
        tokenUsage: { inputTokens: 0, totalTokens: 0, timestamp: 3000 },
      }),
    ];

    expect(deriveContextUsageFromTurns(turns)).toBeUndefined();
  });

  it('does not scan past the latest terminal turn when its multi-round usage is accumulated', () => {
    const turns = [
      makeTurn({ id: 'turn-1', status: 'completed', tokenUsage: usage(1000) }),
      makeTurn({
        id: 'turn-2',
        status: 'completed',
        modelRounds: [{ id: 'round-1' }, { id: 'round-2' }],
        tokenUsage: usage(8_900_000),
      }),
    ];

    expect(deriveContextUsageFromTurns(turns)).toBeUndefined();
  });

  it('returns undefined for empty input or when no completed single-round turn has usage', () => {
    expect(deriveContextUsageFromTurns([])).toBeUndefined();
    expect(deriveContextUsageFromTurns(undefined)).toBeUndefined();
    expect(deriveContextUsageFromTurns([
      makeTurn({ id: 'turn-1', status: 'processing' }),
    ])).toBeUndefined();
    expect(deriveContextUsageFromTurns([
      makeTurn({
        id: 'turn-1',
        status: 'completed',
        modelRounds: [{ id: 'round-1' }, { id: 'round-2' }],
        tokenUsage: usage(9000),
      }),
    ])).toBeUndefined();
  });
});

describe('recorded request context snapshot display', () => {
  const snapshot = (overrides: Partial<UsageRequestSnapshot> = {}): UsageRequestSnapshot => ({
    schemaVersion: 1,
    request: {
      executionHostId: 'local', workspaceId: 'workspace-1', sessionId: 'session-1', turnId: 'turn-1',
      roundId: 'round-1', attemptId: 'round-1:attempt:1', attemptIndex: 1, startedAt: 100,
    },
    capturedAt: 200,
    inputSource: 'model_request',
    inputTotal: 500,
    usageState: 'provider_reported',
    estimatedTotal: 1000,
    summaryState: 'ready',
    categories: {
      systemPrompt: 100, toolDefinitions: 100, rules: 100, skills: 100,
      mcpTools: 100, subagentDefinitions: 100, summarizedConversation: 0,
      conversation: 400, contextWindow: 8000,
    },
    ...overrides,
  });

  it('presents the provider total and scales the same-attempt category proportions onto it', () => {
    const view = resolveRequestContextSnapshotView(snapshot());

    // The provider said 500; the estimate summed to 1000, so every category is
    // halved instead of the total being replaced by the category sum.
    expect(view.used).toBe(500);
    expect(view.categories?.find(row => row.key === 'conversation')?.value).toBe(200);
    expect(view.categories?.reduce((sum, row) => sum + row.value, 0)).toBe(500);
    expect(view.categoryState).toBe('ready');
  });

  it('labels an estimated total instead of passing it off as provider-reported', () => {
    const view = resolveRequestContextSnapshotView(snapshot({
      inputTotal: undefined, usageState: 'estimated', estimationVersion: 2,
    }));

    expect(view.used).toBe(1000);
    expect(view.usageState).toBe('estimated');
    expect(view.categories?.reduce((sum, row) => sum + row.value, 0)).toBe(1000);
  });

  it('never turns an unknown or legacy zero total into a measurement', () => {
    expect(resolveRequestContextSnapshotView(snapshot({ usageState: 'unknown' })).used).toBeUndefined();
    expect(resolveRequestContextSnapshotView(snapshot({
      inputSource: 'legacy_record', usageState: 'provider_reported', inputTotal: 0, estimatedTotal: 0,
    })).used).toBeUndefined();
    const absent = resolveRequestContextSnapshotView(undefined);
    expect(absent.usageState).toBe('unknown');
    expect(absent.categoryState).toBe('absent');
    expect(absent.used).toBeUndefined();
  });

  it('keeps the provider total while the categories are still pending or gone', () => {
    const pending = resolveRequestContextSnapshotView(snapshot({ summaryState: 'pending', categories: undefined }));
    expect(pending.used).toBe(500);
    expect(pending.categoryState).toBe('pending');
    expect(pending.categories).toBeUndefined();

    const unavailable = resolveRequestContextSnapshotView(snapshot({
      summaryState: 'unavailable', categories: undefined, unavailableReason: 'Evicted after a restart.',
    }));
    expect(unavailable.used).toBe(500);
    expect(unavailable.categoryState).toBe('unavailable');
    expect(unavailable.unavailableReason).toBe('Evicted after a restart.');
  });

  it('prefers the recorded context window over the Session fallback', () => {
    expect(resolveRequestContextSnapshotView(snapshot(), 4000).max).toBe(8000);
    expect(resolveRequestContextSnapshotView(snapshot({ categories: undefined }), 4000).max).toBe(4000);
    expect(resolveRequestContextSnapshotView(snapshot({ categories: undefined }), undefined).max).toBeUndefined();
  });

  it('makes the Session reading follow the recorded snapshot', () => {
    const session = makeSession({
      currentTokenUsage: { inputTokens: 1200, outputTokens: 300, totalTokens: 1500, timestamp: 10 },
      requestContextSnapshot: snapshot(),
    });

    expect(getSessionContextUsageDisplay(session)).toEqual({
      current: 500, max: 8000, source: 'agent_prompt', snapshotState: 'provider_reported',
    });

    const unknown = getSessionContextUsageDisplay(makeSession({
      currentTokenUsage: { inputTokens: 1200, outputTokens: 300, totalTokens: 1500, timestamp: 10 },
      requestContextSnapshot: snapshot({ usageState: 'unknown' }),
    }));
    // A recorded request without a total is not the legacy ledger number.
    expect(unknown.current).toBe(0);
    expect(unknown.snapshotState).toBe('unknown');
  });

  it('never promotes a compression-derived context value to the recorded provider total', () => {
    /*
     * `currentTokenUsage`/`currentContextUsage` may be written by the
     * compression path (`source: 'context_compression'`). That value describes a
     * rebuilt prompt, not the request the host recorded, so it is never the
     * snapshot's provider total — and the legacy fallback refuses it too,
     * reporting an explicit unknown state instead of a compacted prompt total.
     */
    const compressed = {
      inputTokens: 9000, outputTokens: 100, totalTokens: 9100, timestamp: 5,
      turnId: 'turn-1', source: 'context_compression' as const,
    };
    expect(getSessionContextUsageDisplay(makeSession({ currentTokenUsage: compressed }))).toEqual({
      current: 0, max: 4000, source: 'agent_prompt', snapshotState: 'unknown',
    });

    // Without a Session context window the refusal keeps the default ceiling
    // instead of presenting a bare zero-max reading.
    expect(getSessionContextUsageDisplay(makeSession({
      currentTokenUsage: compressed, maxContextTokens: undefined,
    }))).toEqual({
      current: 0, max: DEFAULT_MAX_CONTEXT_TOKENS, source: 'agent_prompt', snapshotState: 'unknown',
    });

    expect(getSessionContextUsageDisplay(makeSession({
      currentTokenUsage: compressed, requestContextSnapshot: snapshot(),
    }))).toEqual({
      current: 500, max: 8000, source: 'agent_prompt', snapshotState: 'provider_reported',
    });

    const unknown = getSessionContextUsageDisplay(makeSession({
      currentTokenUsage: compressed,
      requestContextSnapshot: snapshot({ usageState: 'unknown' }),
    }));
    expect(unknown.current).toBe(0);
    expect(unknown.snapshotState).toBe('unknown');

    const estimated = getSessionContextUsageDisplay(makeSession({
      currentTokenUsage: compressed,
      requestContextSnapshot: snapshot({ inputTotal: undefined, usageState: 'estimated' }),
    }));
    expect(estimated.current).toBe(1000);
    expect(estimated.snapshotState).toBe('estimated');
  });

  it('keeps a legacy model_request reading on the legacy fallback path', () => {
    // The refusal above is scoped to compression-derived data; a runtime
    // recorded model request keeps displaying its provider-reported input.
    expect(getSessionContextUsageDisplay(makeSession({
      currentTokenUsage: {
        inputTokens: 1200, outputTokens: 300, totalTokens: 1500, timestamp: 10,
        turnId: 'turn-1', source: 'model_request',
      },
    }))).toEqual({
      current: 1200, max: 4000, source: 'agent_prompt',
    });
  });
});

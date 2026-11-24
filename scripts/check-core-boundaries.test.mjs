import { access, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  collectCargoMetadataGraph,
  collectCargoMetadataPackages,
  discoverCargoManifestPaths,
  findAppWorkspaceIntelligenceHostFeatureViolations,
  findCargoLayerViolations,
  findFeatureGatedTestTargetViolations,
  findProductEntrypointCoreFeatureViolations,
  findReqwestDependencyFeatureViolations,
  findResolvedThirdPartyCapabilityFeatureViolations,
  findRuntimeServicesTestSupportFeatureViolations,
  findResolvedReqwestNativeTlsViolations,
  findServicesIntegrationsPlatformDependencyFeatureViolations,
  findServicesIntegrationsReqwestFeatureViolations,
  findServicesIntegrationsTokioFeatureViolations,
  findThirdPartyCapabilityFeatureViolations,
  findTokioDependencyFeatureViolations,
} from './core-boundaries/cargo-dependency-boundaries.mjs';
import {
  checkCliIntegrationTestTopology,
  checkExternalSourceIntegrationTestTopologies,
  checkServicesCoreIntegrationTestTopology,
  checkServicesIntegrationsIntegrationTestTopology,
  claudeCodeAdapterIntegrationTestTargets,
  cliIntegrationTestTargets,
  codexAdapterIntegrationTestTargets,
  externalSourcesIntegrationTestTargets,
  opencodeAdapterIntegrationTestTargets,
  validateExplicitIntegrationTestTopology,
} from './core-boundaries/explicit-test-topology.mjs';
import { crateLayoutRules } from './core-boundaries/rules/crate-layout.mjs';
import { findForbiddenContentMatches } from './core-boundaries/source-content-checks.mjs';
import {
  capabilityContractDependencyRules,
  coreClosedFeatureProfileRules,
  coreProductFullFeatureAssemblyRule,
  guardedEmptyInternalDefaultManifestPaths,
  optionalDependencyFeatureOwnerRules,
} from './core-boundaries/rules/feature-rules.mjs';
import {
  agentRuntimeRootPublicModules,
  forbiddenContentRules,
  forbiddenContentUnderRules,
  publicApiAllowlistRules,
  requiredContentRules,
} from './core-boundaries/rules/source-rules.mjs';

const ENTRYPOINT = new URL('./check-core-boundaries.mjs', import.meta.url);
const MODULES = [
  './core-boundaries/checker.mjs',
  './core-boundaries/cargo-dependency-boundaries.mjs',
  './core-boundaries/explicit-test-topology.mjs',
  './core-boundaries/manifest-feature-helpers.mjs',
  './core-boundaries/source-content-checks.mjs',
  './core-boundaries/self-test.mjs',
  './core-boundaries/tui-boundary-ratchet.mjs',
  './core-boundaries/rules/crate-rules.mjs',
  './core-boundaries/rules/feature-rules.mjs',
  './core-boundaries/rules/source-rules.mjs',
  './core-boundaries/rules/source/facade-rules.mjs',
  './core-boundaries/rules/source/forbidden-rules.mjs',
  './core-boundaries/rules/source/public-api-rules.mjs',
  './core-boundaries/rules/source/required-rules.mjs',
];

const TEST_ROOT = join('C:', 'repo');

test('session metadata paging delegates query parameters to the services-core store', async () => {
  const managerRule = requiredContentRules.find(
    rule => rule.path === 'src/crates/assembly/core/src/agentic/persistence/manager.rs',
  );
  const pageRule = managerRule.patterns.find(
    pattern => pattern.message === 'missing metadata page delegation to services-core store',
  );
  const source = await readFile(new URL(`../${managerRule.path}`, import.meta.url), 'utf8');
  const call = '.list_metadata_page_with_query(cursor, limit, query)';
  assert.ok(source.includes(call));
  assert.ok(pageRule.regex.test(source));
  for (const replacement of [
    '.list_metadata_page(cursor, limit)',
    '.list_metadata_page_with_query(cursor, limit, None)',
    '.list_metadata_page_with_query(None, limit, query)',
    '.list_metadata_page_with_query(cursor, 1, query)',
  ]) {
    assert.ok(!pageRule.regex.test(source.replace(call, replacement)), replacement);
  }
  assert.ok(!pageRule.regex.test(source.replaceAll(
    '.session_metadata_store(workspace_path)',
    '.local_metadata_store(workspace_path)',
  )));

  const storeRule = requiredContentRules.find(
    rule => rule.path === 'src/crates/services/services-core/src/session/metadata_store.rs',
  );
  const storeSource = await readFile(new URL(`../${storeRule.path}`, import.meta.url), 'utf8');
  const acceptsStore = text => storeRule.patterns.every(({ regex }) => regex.test(text));
  assert.ok(acceptsStore(storeSource));
  for (const entrypoint of ['list_metadata_page', 'list_metadata_page_with_query']) {
    assert.ok(!acceptsStore(storeSource.replace(
      `pub async fn ${entrypoint}(`,
      'pub async fn removed_entrypoint(',
    )), `must keep ${entrypoint} in the services-core store`);
  }
});

test('workspace instruction owner requires family priority and non-empty fallback regressions', async () => {
  const rule = requiredContentRules.find(
    rule => rule.path === 'src/crates/services/services-core/tests/declarative_workspace_instruction_contracts.rs',
  );
  assert.ok(rule);
  const source = await readFile(new URL(`../${rule.path}`, import.meta.url), 'utf8');
  const accepts = text => rule.patterns.every(({ regex }) => regex.test(text));
  assert.ok(accepts(source));

  for (const name of [
    'workspace_instruction_families_select_agents_then_claude_then_opencode',
    'workspace_instruction_override_skips_empty_files_and_suppresses_claude',
    'opencode_project_instructions_support_local_files_and_globs_only',
  ]) {
    assert.ok(!accepts(source.replace(name, 'removed_regression')), `must require ${name}`);
  }
  assert.ok(!accepts(source.replace(
    'workspace_instruction_families_select_agents_then_claude_then_opencode',
    'workspace_instruction_files_reads_agents_then_claude_and_skips_empty_files',
  )));
});

test('builtin agent catalog requires the GeneralPurpose fast model default', () => {
  const rule = requiredContentRules.find(
    rule => rule.path === 'src/crates/execution/agent-runtime/src/agents.rs'
      && rule.patterns.some(pattern => pattern.message.includes('GeneralPurpose')),
  );
  assert.ok(rule);
  const mapping = `builtin_agent_spec(
    "GeneralPurpose",
    SubAgent,
    "fast",
    SubagentVisibilityPolicy::public(),
  )`;
  const catalog = `fn builtin_agent_definition_specs() {
    ${mapping};
    SubagentVisibilityPolicy::restricted(["Claw"]);
  }`;
  const accepts = text => rule.patterns.every(({ regex }) => regex.test(text));
  assert.ok(accepts(catalog));
  assert.ok(!accepts(catalog.replace(mapping, '')));
  assert.ok(!accepts(catalog.replace('"fast"', '"primary"')));
  assert.ok(!accepts(catalog.replace('SubAgent,', 'Mode,')));
  assert.ok(!accepts(catalog.replace('"GeneralPurpose"', '"Explore"')));
  assert.ok(!accepts(catalog.replace('SubagentVisibilityPolicy::restricted(["Claw"]);', '')));
});

test('tool-runtime search regex stays available without enabling HTML extractors', () => {
  const rule = requiredContentRules.find(
    rule => rule.path === 'src/crates/execution/tool-execution/Cargo.toml',
  );
  assert.ok(rule);
  const manifest = `[features]
default = []
web-readable = ["dep:htmd", "dep:legible", "dep:readability-js"]
[dependencies]
regex = { workspace = true }
htmd = { version = "0.5.4", optional = true }
legible = { version = "0.4.2", optional = true }
readability-js = { version = "0.1.5", optional = true }
`;
  const accepts = text => rule.patterns.every(({ regex }) => regex.test(text));
  assert.ok(accepts(manifest));
  assert.equal(accepts(manifest.replace(
    'regex = { workspace = true }',
    'regex = { workspace = true, optional = true }',
  )), false);
  for (const dependency of ['htmd', 'legible', 'readability-js']) {
    assert.equal(accepts(manifest.replace(
      new RegExp(`(${dependency} = \\{[^}]*), optional = true`), '$1',
    )), false, `${dependency} must remain optional`);
  }
  assert.equal(accepts(manifest.replace(
    'web-readable = [', 'web-readable = ["dep:regex", ',
  )), false);
});

test('workspace file tools reject new per-tool SSH implementations', async () => {
  for (const tool of ['file_read_tool', 'file_write_tool', 'file_edit_tool', 'delete_file_tool', 'ls_tool']) {
    const path = `src/crates/assembly/core/src/agentic/tools/implementations/${tool}.rs`;
    const rule = forbiddenContentRules.find(rule => rule.path === path);
    assert.ok(rule, `${tool} must retain its provider boundary guard`);
    const source = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
    assert.deepEqual(findForbiddenContentMatches(source, rule.patterns), []);
    for (const mutation of [
      'if context.is_remote() { return call_remote(); }',
      'resolved.uses_remote_workspace_backend()',
      'context.ws_shell().unwrap().exec(command)',
      'write_local_file(request)',
      'build_remote_delete_command(path, recursive)',
    ]) {
      assert.ok(findForbiddenContentMatches(`${source}\n${mutation}`, rule.patterns).length > 0,
        `${tool} must reject ${mutation}`);
    }
  }
});

test('Pi Skill discovery may use bounded static-source support without opening other consumers', async () => {
  const rule = forbiddenContentUnderRules.find(
    (rule) => rule.reason === 'shared bounded static-source support is private to reviewed ecosystem source adapters',
  );
  assert.ok(rule);
  const sourcePath = 'src/crates/adapters/pi-adapter/src/skill_source.rs';
  const source = await readFile(new URL(`../${sourcePath}`, import.meta.url), 'utf8');
  assert.match(source, /use openbitfun_static_hook_support::/);
  assert.deepEqual(findForbiddenContentMatches(source, rule.patterns, sourcePath), []);
  for (const rejectedPath of [
    'src/crates/adapters/pi-adapter/src/unreviewed_source.rs',
    'src/crates/assembly/core/src/agentic/tools/implementations/skills/registry.rs',
  ]) {
    assert.ok(findForbiddenContentMatches(source, rule.patterns, rejectedPath).length > 0,
      `static-source support must remain private at ${rejectedPath}`);
  }
});

test('Codex session history imports stay behind reviewed composition roots', async () => {
  const rule = forbiddenContentUnderRules.find(
    (rule) => rule.reason === 'Codex declarative source adapter imports are limited to its fixtures and composition roots',
  );
  assert.ok(rule);
  const sourcePath = 'src/crates/assembly/core/src/external_session_import.rs';
  const source = await readFile(new URL(`../${sourcePath}`, import.meta.url), 'utf8');
  assert.match(source, /use openbitfun_codex_adapter::session/);
  assert.deepEqual(findForbiddenContentMatches(source, rule.patterns, sourcePath), []);
  for (const rejectedPath of [
    'src/crates/assembly/core/src/agentic/persistence/manager.rs',
    'src/apps/desktop/src/api/session.rs',
  ]) {
    assert.ok(findForbiddenContentMatches(source, rule.patterns, rejectedPath).length > 0,
      `Codex transcript translation must remain behind the import facade at ${rejectedPath}`);
  }
  const publicApi = publicApiAllowlistRules.find(
    (rule) => rule.path === 'src/crates/adapters/codex-adapter/src/lib.rs',
  );
  const session = publicApi?.allowedSymbolEntries.find((entry) => entry.symbol === 'session');
  assert.equal(session?.contractSlice, 'external-session-import-contract');
  assert.match(session?.consumer ?? '', /external_session_import/);
});

test('Cargo manifest discovery ignores nested local-agent worktrees', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'openbitfun-core-boundaries-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await Promise.all([
    mkdir(join(root, 'src', 'crate'), { recursive: true }),
    mkdir(join(root, '.claude', 'worktrees', 'other'), { recursive: true }),
    mkdir(join(root, '.cursor', 'worktrees', 'other'), { recursive: true }),
  ]);
  await Promise.all([
    writeFile(join(root, 'Cargo.toml'), '[workspace]\n'),
    writeFile(join(root, 'src', 'crate', 'Cargo.toml'), '[package]\nname="kept"\nversion="0.1.0"\n'),
    writeFile(join(root, '.claude', 'worktrees', 'other', 'Cargo.toml'), '[package]\nname="ignored-claude"\nversion="0.1.0"\n'),
    writeFile(join(root, '.cursor', 'worktrees', 'other', 'Cargo.toml'), '[package]\nname="ignored-cursor"\nversion="0.1.0"\n'),
  ]);

  const manifests = discoverCargoManifestPaths(root)
    .map((manifest) => manifest.slice(root.length + 1).replaceAll('\\', '/'));
  assert.deepEqual(manifests, ['Cargo.toml', 'src/crate/Cargo.toml']);
});

test('App Server TypeScript capability is owned by the protocol crate and independent from RPC', () => {
  const appServerTs = coreClosedFeatureProfileRules.find(
    (rule) => rule.manifestPath === 'src/crates/interfaces/app-server/Cargo.toml'
      && rule.featureName === 'ts',
  );
  assert.deepEqual(appServerTs?.requiredFeatureRefs, [
    'openbitfun-app-server-protocol/ts',
  ]);
  assert.equal(appServerTs?.exact, true);

  const protocolProfiles = new Map(
    coreClosedFeatureProfileRules
      .filter(
        (rule) => rule.manifestPath
          === 'src/crates/interfaces/app-server-protocol/Cargo.toml',
      )
      .map((rule) => [rule.featureName, rule]),
  );

  const protocolDefault = protocolProfiles.get('default');
  assert.deepEqual(protocolDefault?.requiredFeatureRefs, ['rpc']);
  assert.equal(protocolDefault?.exact, true);

  const protocolRpc = protocolProfiles.get('rpc');
  assert.deepEqual(protocolRpc?.requiredFeatureRefs, ['dep:agent-client-protocol']);
  assert.equal(protocolRpc?.exact, true);

  const protocolOptionalOwners = optionalDependencyFeatureOwnerRules.find(
    (rule) => rule.crateName === 'app-server-protocol',
  );
  assert.deepEqual(protocolOptionalOwners?.dependencies, [
    { depName: 'agent-client-protocol', ownerFeatures: ['rpc'] },
  ]);

  const protocolTs = protocolProfiles.get('ts');
  assert.deepEqual(protocolTs?.requiredFeatureRefs, [
    'openbitfun-core-types/ts',
    'openbitfun-product-domains/ts',
    'openbitfun-runtime-ports/ts',
    'dep:ts-rs',
  ]);
  assert.equal(protocolTs?.exact, true);
});

test('Agent Runtime leaf capabilities have one managed feature and source contract', async () => {
  const rule = capabilityContractDependencyRules.find(
    (candidate) => candidate.packageName === 'openbitfun-agent-runtime',
  );
  assert.ok(rule, 'openbitfun-agent-runtime must be a managed capability target');
  assert.deepEqual(Object.keys(rule.featureProfiles).sort(), [
    'account-routing',
    'agent-runtime',
    'default',
    'definition-contracts',
    'native-hook-runtime',
    'native-hook-settings',
  ]);
  assert.equal(rule.consumers.size, 11);
  assert.ok(rule.consumers.has('openbitfun-legacy-migration-adapters'));
  assert.ok(
    guardedEmptyInternalDefaultManifestPaths.includes(
      'src/crates/execution/agent-runtime/Cargo.toml',
    ),
  );
  assert.ok(requiredContentRules.some(
    (sourceRule) => sourceRule.path === 'src/crates/execution/agent-runtime/src/lib.rs'
      && sourceRule.reason.includes('leaf capability modules'),
  ));
  const publicApiRule = publicApiAllowlistRules.find(
    (sourceRule) => sourceRule.path === 'src/crates/execution/agent-runtime/src/lib.rs',
  );
  assert.ok(publicApiRule, 'openbitfun-agent-runtime root must have a closed public module allowlist');
  assert.deepEqual(
    new Set(publicApiRule.allowedSymbols),
    new Set(agentRuntimeRootPublicModules),
  );
  const flatRootRule = forbiddenContentRules.find(
    (sourceRule) => sourceRule.path === 'src/crates/execution/agent-runtime/src/lib.rs'
      && sourceRule.reason.includes('flat feature-owned module wrapper'),
  );
  assert.ok(flatRootRule, 'openbitfun-agent-runtime root must reject non-wrapper source lines');
  const rootSource = await readFile(
    new URL('../src/crates/execution/agent-runtime/src/lib.rs', import.meta.url),
    'utf8',
  );
  assert.equal(flatRootRule.patterns[0].regex.test(rootSource), false);
  const channelRule = requiredContentRules.find(
    (sourceRule) => sourceRule.path === 'src/crates/execution/agent-runtime/src/lib.rs'
      && sourceRule.reason.includes('leaf capability modules'),
  ).patterns.find((pattern) => pattern.message.startsWith('channel_routing '));
  assert.ok(channelRule, 'channel admission must have an exact pure owner gate');
  assert.equal(channelRule.regex.test(rootSource), true);
  assert.equal(channelRule.regex.test(rootSource.replace(
    '#[cfg(feature = "account-routing")]\npub mod channel_routing;',
    '#[cfg(feature = "agent-runtime")]\npub mod channel_routing;',
  )), false);
  for (const mutation of [
    '#[doc(hidden)] pub mod accidental_feature_free_api;',
    'pub union AccidentalFeatureFreeApi { value: u64 }',
    'const DOC: &str = "{";\npub mod accidental_feature_free_api;',
  ]) {
    assert.equal(
      flatRootRule.patterns[0].regex.test(`${rootSource}\n${mutation}`),
      true,
      `Agent Runtime root must reject mutation: ${mutation}`,
    );
  }
});

test('Server canonical Agent Runtime ownership is protected by source boundary rules', async () => {
  const bootstrapPath = 'src/apps/server/src/bootstrap.rs';
  const mainPath = 'src/apps/server/src/main.rs';
  const bootstrapRequired = requiredContentRules.find((rule) => rule.path === bootstrapPath);
  const bootstrapForbidden = forbiddenContentRules.find((rule) => rule.path === bootstrapPath);
  const mainRequired = requiredContentRules.find((rule) => rule.path === mainPath);
  const mainForbidden = forbiddenContentRules.find((rule) => rule.path === mainPath);

  assert.ok(bootstrapRequired, 'Server bootstrap must have a required ownership contract');
  assert.ok(bootstrapForbidden, 'Server bootstrap must reject duplicate Runtime assembly');
  assert.ok(mainRequired, 'Server main must retain the product event owner');
  assert.ok(mainForbidden, 'Server main must reject an unowned event source');

  const [bootstrapSource, mainSource] = await Promise.all([
    readFile(new URL('../src/apps/server/src/bootstrap.rs', import.meta.url), 'utf8'),
    readFile(new URL('../src/apps/server/src/main.rs', import.meta.url), 'utf8'),
  ]);
  for (const pattern of bootstrapRequired.patterns) {
    assert.match(bootstrapSource, pattern.regex, pattern.message);
  }
  for (const pattern of mainRequired.patterns) {
    assert.match(mainSource, pattern.regex, pattern.message);
  }
  assert.match(
    'let queue = EventQueue::new(Default::default());',
    bootstrapForbidden.patterns[0].regex,
  );
  assert.match(
    'let source = AgentEventSource::new(event_queue);',
    mainForbidden.patterns[0].regex,
  );
});

test('TLS source boundaries reject bypasses of the centralized provider owner', () => {
  const integrationsRule = forbiddenContentUnderRules.find((rule) =>
    rule.path === 'src/crates/services/services-integrations/src'
      && rule.reason.includes('provider-initializing Reqwest constructors'));
  const providerRule = forbiddenContentUnderRules.find((rule) =>
    rule.path === 'src'
      && rule.reason.includes('only owner allowed to install'));
  assert.ok(integrationsRule, 'integration Reqwest constructors must be guarded');
  assert.ok(providerRule, 'direct Rustls provider installation must be guarded');

  assert.ok(integrationsRule.patterns.some((pattern) => pattern.regex.test(
    'use reqwest::Client;\nfn client() { let _ = Client::builder(); }',
  )));
  assert.ok(integrationsRule.patterns.some((pattern) => pattern.regex.test(
    'use reqwest::{Client as HttpClient, Url};\nfn client() { let _ = HttpClient::new(); }',
  )));
  assert.ok(integrationsRule.patterns.some((pattern) => pattern.regex.test(
    'fn client() { let _ = reqwest::ClientBuilder::new(); }',
  )));
  assert.ok(integrationsRule.patterns.some((pattern) => pattern.regex.test(
    'use reqwest as http;\nfn client() { let _ = http::Client::new(); }',
  )));
  assert.match(
    'rustls::crypto::ring::default_provider().install_default();',
    providerRule.patterns[0].regex,
  );
  assert.doesNotMatch(
    'unrelated_component.install_default();',
    providerRule.patterns[0].regex,
  );
});

test('standalone Relay TLS exception cannot install a process provider', () => {
  const providerRule = forbiddenContentUnderRules.find(rule => rule.reason.includes('only owner allowed to install'));
  const relayPath = 'src/crates/services/relay-service/src/identity.rs';
  assert.ok(providerRule.patterns[0].allowPaths.includes(relayPath));
  const scopedRule = forbiddenContentUnderRules.find(rule => rule.path === relayPath && rule.reason.includes('client-scoped'));
  assert.ok(scopedRule);
  assert.ok(scopedRule.patterns.some(pattern => pattern.regex.test('provider.install_default()')));
  assert.ok(scopedRule.patterns.every(pattern => !pattern.regex.test('ClientConfig::builder_with_provider(provider)')));
});

test('Core and ACP defaults preserve their explicit assembly contracts', async () => {
  const [coreManifest, acpManifest] = await Promise.all([
    readFile(new URL('../src/crates/assembly/core/Cargo.toml', import.meta.url), 'utf8'),
    readFile(new URL('../src/crates/interfaces/acp/Cargo.toml', import.meta.url), 'utf8'),
  ]);

  assert.deepEqual(parseManifestFeatures(coreManifest).default, []);
  assert.deepEqual(
    new Set(parseManifestFeatures(acpManifest).default),
    new Set(['client', 'server']),
  );
});

test('consumers do not repeat guarded empty internal defaults', async () => {
  const cargoBoundaries = await import(
    './core-boundaries/cargo-dependency-boundaries.mjs'
  );
  assert.equal(
    typeof cargoBoundaries.findRedundantInternalDefaultFeatureDisables,
    'function',
  );

  const emptyOwner = {
    ...packageAt('empty-owner', 'src/crates/contracts/empty-owner/Cargo.toml'),
    features: { default: [] },
  };
  const compatibilityOwner = {
    ...packageAt('compatibility-owner', 'src/crates/interfaces/compatibility-owner/Cargo.toml'),
    features: { default: ['client', 'server'] },
  };
  const unguardedEmptyOwner = {
    ...packageAt('unguarded-empty-owner', 'src/crates/contracts/unguarded-empty-owner/Cargo.toml'),
    features: { default: [] },
  };
  const consumer = packageAt('consumer', 'src/apps/consumer/Cargo.toml', [
    pathDependency('src/crates/contracts/empty-owner', {
      name: 'empty-owner',
      usesDefaultFeatures: false,
    }),
    pathDependency('src/crates/interfaces/compatibility-owner', {
      name: 'compatibility-owner',
      usesDefaultFeatures: false,
    }),
    pathDependency('src/crates/contracts/unguarded-empty-owner', {
      name: 'unguarded-empty-owner',
      usesDefaultFeatures: false,
    }),
  ]);

  const violations = cargoBoundaries.findRedundantInternalDefaultFeatureDisables(
    [emptyOwner, compatibilityOwner, unguardedEmptyOwner, consumer],
    {
      root: TEST_ROOT,
      guardedManifests: ['src/crates/contracts/empty-owner/Cargo.toml'],
    },
  );
  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /empty-owner.*redundant/);
});

test('guarded internal defaults stay explicitly empty', async () => {
  const cargoBoundaries = await import(
    './core-boundaries/cargo-dependency-boundaries.mjs'
  );
  const manifestPath = 'src/crates/contracts/empty-owner/Cargo.toml';
  const owner = {
    ...packageAt('empty-owner', manifestPath),
    features: { default: [] },
  };
  assert.deepEqual(
    cargoBoundaries.findGuardedInternalDefaultFeatureViolations(
      [owner],
      { root: TEST_ROOT, guardedManifests: [manifestPath] },
    ),
    [],
  );

  owner.features.default = ['expanded'];
  const violations = cargoBoundaries.findGuardedInternalDefaultFeatureViolations(
    [owner],
    { root: TEST_ROOT, guardedManifests: [manifestPath] },
  );
  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /guarded default feature must stay explicitly empty/);
});

test('portable contract crates expose only capability-local feature slices', async () => {
  const [runtimePortsManifest, agentToolsManifest] = await Promise.all([
    readFile(new URL('../src/crates/contracts/runtime-ports/Cargo.toml', import.meta.url), 'utf8'),
    readFile(new URL('../src/crates/execution/tool-contracts/Cargo.toml', import.meta.url), 'utf8'),
  ]);

  const runtimePortFeatures = parseManifestFeatures(runtimePortsManifest);
  assert.deepEqual(runtimePortFeatures.default, []);
  assert.deepEqual(
    new Set(Object.keys(runtimePortFeatures)),
    new Set([
      'default',
      'agent-api',
      'git-port',
      'hook-function-runtime',
      'permission',
      'plugin-runtime',
      'product-search',
      'ptc-runtime',
      'remote-exec-port',
      'remote-workspace-ports',
      'runtime-event-port',
      'script-tool-runtime',
      'terminal-port',
      'tool-runtime-handles',
      'ts',
      'web-search-port',
      'workspace-ports',
    ]),
  );
  assert.deepEqual(runtimePortFeatures['agent-api'], ['dep:openbitfun-core-types']);
  assert.deepEqual(runtimePortFeatures['hook-function-runtime'], []);
  assert.deepEqual(runtimePortFeatures['plugin-runtime'], []);
  assert.deepEqual(runtimePortFeatures['product-search'], ['dep:openbitfun-product-domains']);
  assert.deepEqual(runtimePortFeatures['script-tool-runtime'], []);
  assert.deepEqual(runtimePortFeatures['ptc-runtime'], []);
  assert.deepEqual(runtimePortFeatures['web-search-port'], []);
  // Workspace byte readers expose AsyncRead/AsyncSeek without selecting a
  // process, network, scheduler, or full Tokio runtime at the contract layer.
  assert.deepEqual(new Set(runtimePortFeatures['workspace-ports']), new Set(['dep:anyhow', 'dep:tokio-util', 'dep:tokio', 'tokio/io-util']));
  assert.deepEqual(runtimePortFeatures['terminal-port'], ['dep:tokio']);
  assert.deepEqual(runtimePortFeatures['remote-exec-port'], ['dep:tokio']);
  assert.deepEqual(
    new Set(runtimePortFeatures['tool-runtime-handles']),
    new Set([
      'workspace-ports',
      'terminal-port',
      'remote-exec-port',
    ]),
  );

  const agentToolFeatures = parseManifestFeatures(agentToolsManifest);
  assert.deepEqual(agentToolFeatures.default, []);
  assert.deepEqual(agentToolFeatures['acp-bridge'], []);
  assert.deepEqual(agentToolFeatures['computer-use-contract'], []);
  assert.deepEqual(agentToolFeatures['element-token'], []);
  assert.deepEqual(agentToolFeatures['mcp-bridge'], []);
});

test('runtime-port capability source gates protect modules and public exports', async () => {
  const { requiredContentRules } = await import(
    './core-boundaries/rules/source/required-rules.mjs'
  );
  const sourceRule = requiredContentRules.find(
    (rule) => rule.path === 'src/crates/contracts/runtime-ports/src/lib.rs'
      && rule.reason.includes('capability features'),
  );
  const patterns = sourceRule?.patterns.map(({ regex }) => regex.source).join('\n') ?? '';

  for (const [feature, moduleName] of [
    ['workspace-ports', 'workspace_ports'],
    ['terminal-port', 'terminal_port'],
    ['remote-exec-port', 'remote_exec_port'],
    ['remote-workspace-ports', 'remote_workspace_ports'],
    ['runtime-event-port', 'runtime_event_port'],
    ['git-port', 'git_port'],
    ['product-search', 'product_search'],
    ['tool-runtime-handles', 'tool_runtime_handles'],
  ]) {
    assert.match(patterns, new RegExp(`${feature}.*mod ${moduleName}`));
    assert.match(patterns, new RegExp(`${feature}.*pub use ${moduleName}`));
  }
});

test('runtime-ports async dependencies stay behind their exact port owners', () => {
  const ownerRule = optionalDependencyFeatureOwnerRules.find(
    (rule) => rule.crateName === 'runtime-ports',
  );
  const ownersByDependency = new Map(
    ownerRule.dependencies.map((dependency) => [
      dependency.depName,
      new Set(dependency.ownerFeatures),
    ]),
  );

  assert.deepEqual(
    ownersByDependency.get('anyhow'),
    new Set(['workspace-ports']),
  );
  assert.deepEqual(
    ownersByDependency.get('tokio-util'),
    new Set(['permission', 'ts', 'workspace-ports']),
  );
  assert.deepEqual(
    ownersByDependency.get('tokio'),
    // WorkspaceReader exposes AsyncRead/AsyncSeek through the workspace IO port.
    new Set(['remote-exec-port', 'terminal-port', 'workspace-ports']),
  );
});

test('Core feature-free dependencies stay attached to their exact runtime owners', () => {
  const coreOwnerRule = optionalDependencyFeatureOwnerRules.find(
    (rule) => rule.crateName === 'core',
  );
  const ownersByDependency = new Map(
    coreOwnerRule.dependencies.map((dependency) => [
      dependency.depName,
      new Set(dependency.ownerFeatures),
    ]),
  );

  assert.deepEqual(ownersByDependency.get('base64'), new Set(['agent-runtime', 'dispatch-store']));
  assert.deepEqual(ownersByDependency.get('futures'), new Set(['agent-runtime']));
  assert.deepEqual(ownersByDependency.get('regex'), new Set(['agent-runtime']));
  assert.deepEqual(
    ownersByDependency.get('openbitfun-agent-tools'),
    new Set(['agent-runtime', 'local-storage', 'mcp-runtime']),
  );
  assert.deepEqual(ownersByDependency.get('fluent-bundle'), new Set(['i18n-runtime']));
  assert.deepEqual(ownersByDependency.get('unic-langid'), new Set(['i18n-runtime']));
  assert.deepEqual(
    ownersByDependency.get('tokio-util'),
    new Set(['agent-runtime']),
  );
});

test('Services Core feature-free dependencies stay behind exact text and async IO owners', () => {
  const ownerRule = optionalDependencyFeatureOwnerRules.find(
    (rule) => rule.crateName === 'services-core',
  );
  const ownersByDependency = new Map(
    ownerRule.dependencies.map((dependency) => [
      dependency.depName,
      new Set(dependency.ownerFeatures),
    ]),
  );

  assert.deepEqual(
    ownersByDependency.get('regex'),
    new Set(['diagnostics', 'filesystem', 'local-storage', 'markdown', 'workspace-instructions']),
  );
  assert.deepEqual(ownersByDependency.get('similar'), new Set(['diff', 'local-storage']));
  assert.deepEqual(
    ownersByDependency.get('tokio'),
    new Set([
      'credential-vault',
      'diff',
      'filesystem',
      'json-io',
      'local-storage',
      'permission',
      'process-runtime',
      'session-search',
      'workspace-instructions',
      'workspace-runtime',
      'workspace-text-runtime',
      'workspace-transfer',
    ]),
  );
});

test('Services Core text runtime features keep independent exact owner profiles', () => {
  const profiles = new Map(
    coreClosedFeatureProfileRules
      .filter((rule) => rule.manifestPath === 'src/crates/services/services-core/Cargo.toml')
      .map((rule) => [rule.featureName, rule.requiredFeatureRefs]),
  );

  assert.deepEqual(profiles.get('diagnostics'), ['dep:regex']);
  assert.deepEqual(profiles.get('diff'), [
    'dep:similar',
    'dep:tokio',
    'tokio/rt',
    'tokio/time',
  ]);
  assert.deepEqual(profiles.get('workspace-text-runtime'), [
    'dep:tokio',
    'tokio/rt',
  ]);
});

test('image inspection, image generation, and office documents keep independent exact feature closures', async () => {
  const manifestPath = 'src/crates/assembly/core/Cargo.toml';
  const manifest = await readFile(new URL(`../${manifestPath}`, import.meta.url), 'utf8');
  const features = parseManifestFeatures(manifest);
  for (const [name, refs] of [
    ['tools-image-analysis', ['openbitfun-tool-packs/image-analysis']],
    ['tools-office-documents', ['openbitfun-tool-packs/office-documents', 'dep:openbitfun-office-documents']],
    ['tools-image-generation', [
      'openbitfun-tool-packs/image-generation',
      'ai-adapter-runtime',
      'openbitfun-ai-adapters/image-generation',
    ]],
  ]) {
    const rule = coreClosedFeatureProfileRules.find(candidate => candidate.manifestPath === manifestPath && candidate.featureName === name);
    assert.equal(rule?.exact, true);
    assert.deepEqual(rule.requiredFeatureRefs, refs);
    assert.deepEqual(features[name], refs);
  }
});

test('system proxy discovery owns registry access without process or storage capabilities', async () => {
  const manifestPath = 'src/crates/services/services-core/Cargo.toml';
  const manifest = await readFile(new URL(`../${manifestPath}`, import.meta.url), 'utf8');
  const expected = ['dep:windows', 'windows/Win32_Foundation', 'windows/Win32_System_Registry'];
  assert.deepEqual(parseManifestFeatures(manifest)['system-proxy'], expected);
  const rule = coreClosedFeatureProfileRules.find(candidate => candidate.manifestPath === manifestPath && candidate.featureName === 'system-proxy');
  assert.equal(rule?.exact, true);
  assert.deepEqual(rule.requiredFeatureRefs, expected);
  const windows = optionalDependencyFeatureOwnerRules.find(candidate => candidate.crateName === 'services-core')
    .dependencies.find(dependency => dependency.depName === 'windows');
  assert.ok(windows.ownerFeatures.includes('system-proxy'));
});

function parseManifestFeatures(manifest) {
  const section = manifest.match(/^\[features\]\s*$([\s\S]*?)(?=^\[|(?![\s\S]))/m)?.[1] ?? '';
  const features = {};

  for (const match of section.matchAll(/^([a-zA-Z0-9_-]+)\s*=\s*\[([\s\S]*?)\]/gm)) {
    features[match[1]] = [...match[2].matchAll(/["']([^"']+)["']/g)].map((value) => value[1]);
  }

  return features;
}

function removeFeatureValue(manifest, feature, value) {
  const featurePattern = new RegExp(`^${feature}\\s*=\\s*\\[([\\s\\S]*?)\\]`, 'm');
  return manifest.replace(featurePattern, (definition) =>
    definition.replace(new RegExp(`\\s*["']${value}["'],?`), ''));
}

function servicesIntegrationsPackage(manifest) {
  return {
    name: 'openbitfun-services-integrations',
    manifest_path: join(TEST_ROOT, 'src', 'crates', 'services', 'services-integrations', 'Cargo.toml'),
    features: parseManifestFeatures(manifest),
  };
}

function packageAt(name, repoManifestPath, dependencies = []) {
  return {
    id: name,
    name,
    manifest_path: join(TEST_ROOT, ...repoManifestPath.split('/')),
    dependencies,
  };
}

function pathDependency(repoCratePath, options = {}) {
  return {
    name: options.name ?? repoCratePath.split('/').at(-1),
    rename: options.rename ?? null,
    path: join(TEST_ROOT, ...repoCratePath.split('/')),
    kind: options.kind ?? null,
    optional: options.optional ?? false,
    target: options.target ?? null,
    uses_default_features: options.usesDefaultFeatures ?? true,
    features: options.features ?? [],
  };
}

const RUNTIME_PORT_FEATURE_PROFILES = {
  default: [],
  'agent-api': ['dep:openbitfun-core-types'],
  'git-port': [],
  'hook-function-runtime': [],
  permission: ['dep:openbitfun-product-domains', 'dep:tokio-util'],
  'plugin-runtime': [],
  'product-search': ['dep:openbitfun-product-domains'],
  'ptc-runtime': [],
  'remote-exec-port': ['dep:tokio'],
  'remote-workspace-ports': ['dep:openbitfun-core-types'],
  'runtime-event-port': [],
  'script-tool-runtime': [],
  'terminal-port': ['dep:tokio'],
  'tool-runtime-handles': ['workspace-ports', 'terminal-port', 'remote-exec-port'],
  ts: [
    'dep:ts-rs',
    'dep:tokio-util',
    'agent-api',
    'permission',
    'openbitfun-core-types/ts',
    'openbitfun-product-domains?/ts',
  ],
  'web-search-port': [],
  'workspace-ports': ['dep:anyhow', 'dep:tokio-util', 'dep:tokio', 'tokio/io-util'],
};

const AGENT_TOOL_FEATURE_PROFILES = {
  default: [],
  'acp-bridge': [],
  'computer-use-contract': [],
  'element-token': [],
  'mcp-bridge': [],
};

function capabilityPackage(name, repoManifestPath, featureProfiles) {
  return {
    ...packageAt(name, repoManifestPath),
    features: structuredClone(featureProfiles),
  };
}

function agentToolsCapabilityPackage() {
  return {
    ...capabilityPackage(
      'openbitfun-agent-tools',
      'src/crates/execution/tool-contracts/Cargo.toml',
      AGENT_TOOL_FEATURE_PROFILES,
    ),
    dependencies: [pathDependency('src/crates/contracts/runtime-ports', {
      name: 'openbitfun-runtime-ports',
      usesDefaultFeatures: false,
    })],
  };
}

function findTestCapabilityViolations(finder, packages, rules) {
  return finder(packages, rules, { root: TEST_ROOT });
}

function integrationTarget(name, sourcePath, requiredFeatures = []) {
  return {
    kind: ['test'],
    name,
    src_path: sourcePath,
    'required-features': requiredFeatures,
  };
}

test('feature-gated integration targets require every positive crate feature', () => {
  const sourcePath = join(TEST_ROOT, 'tests', 'remote.rs');
  const pkg = {
    ...packageAt('example', 'src/crates/services/example/Cargo.toml'),
    targets: [integrationTarget('remote', sourcePath, ['remote-ssh'])],
  };
  const sources = new Map([[
    sourcePath,
    '#![cfg(all(feature = "remote-ssh", feature = "workspace-search", not(feature = "remote-ssh-concrete")))]\n',
  ]]);

  const violations = findFeatureGatedTestTargetViolations([pkg], {
    readSource: (path) => sources.get(path),
  });

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /workspace-search/);
  assert.doesNotMatch(violations[0].message, /remote-ssh-concrete.*missing/);
});

test('matching integration target requirements cover all positive crate features', () => {
  const sourcePath = join(TEST_ROOT, 'tests', 'remote.rs');
  const pkg = {
    ...packageAt('example', 'src/crates/services/example/Cargo.toml'),
    targets: [integrationTarget(
      'remote',
      sourcePath,
      ['remote-ssh', 'workspace-search'],
    )],
  };

  assert.deepEqual(
    findFeatureGatedTestTargetViolations([pkg], {
      readSource: () => '#![cfg(all(feature = "remote-ssh", feature = "workspace-search", not(feature = "remote-ssh-concrete")))]\n',
    }),
    [],
  );
});

test('runtime-services test support stays dev-only across dependency and feature edges', () => {
  const runtimeServicesPath = 'src/crates/execution/runtime-services';
  const packages = [
    packageAt('normal-consumer', 'src/apps/normal/Cargo.toml', [
      pathDependency(runtimeServicesPath, {
        name: 'openbitfun-runtime-services',
        features: ['test-support'],
      }),
    ]),
    packageAt('build-consumer', 'src/apps/build/Cargo.toml', [
      pathDependency(runtimeServicesPath, {
        name: 'openbitfun-runtime-services',
        kind: 'build',
        features: ['test-support'],
      }),
    ]),
    {
      ...packageAt('feature-forwarder', 'src/apps/forwarder/Cargo.toml'),
      features: {
        preview: ['openbitfun-runtime-services/test-support'],
      },
    },
    {
      ...packageAt('weak-forwarder', 'src/apps/weak/Cargo.toml'),
      features: {
        preview: ['openbitfun-runtime-services?/test-support'],
      },
    },
    {
      ...packageAt('renamed-forwarder', 'src/apps/renamed/Cargo.toml', [{
        ...pathDependency(runtimeServicesPath, {
          name: 'openbitfun-runtime-services',
          optional: true,
        }),
        rename: 'runtime_services',
      }]),
      features: {
        preview: ['runtime_services?/test-support'],
      },
    },
    {
      ...packageAt(
        'openbitfun-runtime-services',
        'src/crates/execution/runtime-services/Cargo.toml',
      ),
      features: {
        default: ['test-support'],
        'test-support': [],
      },
    },
    packageAt('test-consumer', 'src/apps/test/Cargo.toml', [
      pathDependency(runtimeServicesPath, {
        name: 'openbitfun-runtime-services',
        kind: 'dev',
        features: ['test-support'],
      }),
    ]),
  ];

  const violations = findRuntimeServicesTestSupportFeatureViolations(packages);

  assert.equal(violations.length, 6);
  assert.match(violations[0].message, /normal-consumer.*normal dependency/);
  assert.match(violations[1].message, /build-consumer.*build dependency/);
  assert.match(violations[2].message, /feature-forwarder:preview/);
  assert.match(violations[3].message, /weak-forwarder:preview/);
  assert.match(violations[4].message, /renamed-forwarder:preview/);
  assert.match(violations[5].message, /openbitfun-runtime-services:default/);
});

test('runtime-services feature aliases cannot hide test support from default builds', () => {
  const owner = {
    ...packageAt(
      'openbitfun-runtime-services',
      'src/crates/execution/runtime-services/Cargo.toml',
    ),
    features: {
      default: ['testing'],
      testing: ['test-support'],
      'test-support': [],
    },
  };

  const messages = findRuntimeServicesTestSupportFeatureViolations([owner])
    .map((violation) => violation.message)
    .join('\n');

  assert.match(messages, /openbitfun-runtime-services:default/);
  assert.match(messages, /default -> testing -> test-support/);
  assert.match(messages, /openbitfun-runtime-services:testing/);
});

test('CLI integration tests keep the reviewed four-target topology', () => {
  const repositoryRoot = fileURLToPath(new URL('..', import.meta.url));

  assert.deepEqual(cliIntegrationTestTargets, [
    { name: 'acp_stdio_cli', path: 'tests/acp_stdio_cli.rs' },
    { name: 'app_server_stdio_cli', path: 'tests/app_server_stdio_cli.rs' },
    { name: 'cli_command_contracts', path: 'tests/cli_command_contracts.rs' },
    { name: 'terminal_process_contracts', path: 'tests/terminal_process_contracts.rs' },
  ]);
  assert.deepEqual(checkCliIntegrationTestTopology(repositoryRoot), []);
});

test('service integration tests keep their reviewed explicit target topology', () => {
  const repositoryRoot = fileURLToPath(new URL('..', import.meta.url));

  assert.deepEqual(checkServicesCoreIntegrationTestTopology(repositoryRoot), []);
  assert.deepEqual(checkServicesIntegrationsIntegrationTestTopology(repositoryRoot), []);
});

test('contract and AI adapter tests keep reviewed feature and failure-domain topology', async () => {
  const repositoryRoot = fileURLToPath(new URL('..', import.meta.url));
  const topology = await import('./core-boundaries/explicit-test-topology.mjs');

  assert.deepEqual(topology.coreTypesIntegrationTestTargets, [
    {
      name: 'core_type_contracts',
      path: 'tests/core_type_contracts.rs',
      leaves: [
        'tests/core_type_contracts/agent_identity.rs',
        'tests/core_type_contracts/session_contracts.rs',
        'tests/core_type_contracts/session_usage_contracts.rs',
        'tests/core_type_contracts/surface_contracts.rs',
      ],
      forbidRequiredFeatures: true,
    },
  ]);
  assert.deepEqual(topology.runtimePortsIntegrationTestTargets, [
    {
      name: 'plugin_runtime_contracts',
      path: 'tests/runtime_port_contracts.rs',
      leaves: [
        'tests/runtime_port_contracts/plugin_runtime_contracts.rs',
        'tests/runtime_port_contracts/plugin_runtime_diagnostics_contracts.rs',
      ],
      requiredFeatures: ['plugin-runtime'],
    },
    {
      name: 'git_port_contracts',
      path: 'tests/git_port_contracts.rs',
      requiredFeatures: ['git-port'],
    },
    {
      name: 'hook_function_runtime_contracts',
      path: 'tests/hook_function_runtime_contracts.rs',
      requiredFeatures: ['hook-function-runtime'],
    },
    {
      name: 'script_tool_port_contracts',
      path: 'tests/script_tool_port_contracts.rs',
      requiredFeatures: ['script-tool-runtime'],
    },
    {
      name: 'ptc_tool_port_contracts',
      path: 'tests/ptc_tool_port_contracts.rs',
      requiredFeatures: ['ptc-runtime'],
    },
    {
      name: 'session_store_contracts',
      path: 'tests/session_store_contracts.rs',
      requiredFeatures: ['workspace-ports'],
    },
  ]);
  assert.deepEqual(topology.productDomainsIntegrationTestTargets, [
    {
      name: 'product_domain_contracts',
      path: 'tests/product_domain_contracts.rs',
      leaves: [
        'tests/product_domain_contracts/tool_permission_contracts.rs',
      ],
      forbidRequiredFeatures: true,
    },
    {
      name: 'external_source_contracts',
      path: 'tests/external_source_contracts.rs',
      leaves: [
        'tests/external_source_contracts/external_hook_catalog_contracts.rs',
        'tests/external_source_contracts/external_hook_contribution_contracts.rs',
        'tests/external_source_contracts/external_source_contracts.rs',
        'tests/external_source_contracts/plugin_capability_contracts.rs',
        'tests/external_source_contracts/workspace_reference_contracts.rs',
      ],
      requiredFeatures: ['external-sources'],
    },
    {
      name: 'function_agent_contracts',
      path: 'tests/function_agent_contracts.rs',
      requiredFeatures: ['function-agents'],
    },
    {
      name: 'miniapp_contracts',
      path: 'tests/miniapp_contracts.rs',
      requiredFeatures: ['miniapp'],
    },
    {
      name: 'legacy_migration_contracts',
      path: 'tests/legacy_migration_contracts.rs',
      requiredFeatures: ['legacy-migration'],
    },
    {
      name: 'plugin_source_contracts',
      path: 'tests/plugin_source_contracts.rs',
      requiredFeatures: ['plugin-source'],
    },
  ]);
  assert.deepEqual(topology.aiAdaptersIntegrationTestTargets, [
    {
      name: 'ai_protocol_contracts',
      path: 'tests/ai_protocol_contracts.rs',
      leaves: [
        'tests/ai_protocol_contracts/model_selector.rs',
        'tests/ai_protocol_contracts/openai_empty_content_parts.rs',
      ],
      forbidRequiredFeatures: true,
    },
    {
      name: 'ai_stream_contracts',
      path: 'tests/ai_stream_contracts.rs',
      leaves: [
        'tests/ai_stream_contracts/common.rs',
        'tests/ai_stream_contracts/stream_processor_anthropic.rs',
        'tests/ai_stream_contracts/stream_processor_openai.rs',
        'tests/ai_stream_contracts/stream_processor_tool_arguments.rs',
        'tests/ai_stream_contracts/stream_replay_regressions.rs',
        'tests/ai_stream_contracts/stream_test_harness.rs',
      ],
      forbidRequiredFeatures: true,
    },
  ]);
  assert.deepEqual(topology.productCapabilitiesIntegrationTestTargets, [
    {
      name: 'product_capability_contracts',
      path: 'tests/product_capability_contracts.rs',
      leaves: [
        'tests/product_capability_contracts/plugin_product_shape.rs',
        'tests/product_capability_contracts/product_capabilities.rs',
        'tests/product_capability_contracts/product_sdk_assembly.rs',
        'tests/product_capability_contracts/runtime_boundary.rs',
      ],
      forbidRequiredFeatures: true,
    },
  ]);
  assert.deepEqual(topology.agentWorkflowsIntegrationTestTargets, [
    {
      name: 'deep_research_contracts',
      path: 'tests/deep_research_contracts.rs',
      forbidRequiredFeatures: true,
    },
  ]);
  assert.deepEqual(topology.checkBuildGraphContractIntegrationTestTopologies(repositoryRoot), []);

  const widenedOwnerErrors = validateExplicitIntegrationTestTopology({
    manifestText: [
      '[package]',
      'autotests = false',
      '[[test]]',
      'name = "external_source_contracts"',
      'path = "tests/external_source_contracts.rs"',
      'required-features = ["product-full"]',
    ].join('\n'),
    expectedTargets: [{
      name: 'external_source_contracts',
      path: 'tests/external_source_contracts.rs',
      requiredFeatures: ['external-sources'],
    }],
    topLevelRustFiles: ['tests/external_source_contracts.rs'],
    rootSources: new Map([[
      'tests/external_source_contracts.rs',
      '#![cfg(feature = "product-full")]\n',
    ]]),
    leafRustFiles: [],
    leafSources: new Map(),
  });
  assert.match(widenedOwnerErrors.join('\n'), /required-features.*external-sources/);
});

test('external source integration tests keep reviewed owner and process boundaries', () => {
  const repositoryRoot = fileURLToPath(new URL('..', import.meta.url));

  assert.deepEqual(opencodeAdapterIntegrationTestTargets, [
    { name: 'opencode_mcp_adapter', path: 'tests/opencode_mcp_adapter.rs' },
    { name: 'opencode_source_adapter', path: 'tests/opencode_source_adapter.rs' },
    {
      name: 'opencode_static_source_contracts',
      path: 'tests/opencode_static_source_contracts.rs',
      leaves: [
        'tests/opencode_static_source_contracts/hook_source.rs',
        'tests/opencode_static_source_contracts/opencode_command_adapter.rs',
        'tests/opencode_static_source_contracts/opencode_skill_roots.rs',
        'tests/opencode_static_source_contracts/opencode_subagent_adapter.rs',
        'tests/opencode_static_source_contracts/opencode_workspace_references.rs',
      ],
      forbidRequiredFeatures: true,
    },
    { name: 'tool_source_contracts', path: 'tests/tool_source_contracts.rs' },
  ]);
  assert.deepEqual(claudeCodeAdapterIntegrationTestTargets, [
    {
      name: 'claude_code_source_contracts',
      path: 'tests/claude_code_source_contracts.rs',
      leaves: [
        'tests/claude_code_source_contracts/command_source.rs',
        'tests/claude_code_source_contracts/hook_source.rs',
        'tests/claude_code_source_contracts/mcp_source.rs',
        'tests/claude_code_source_contracts/subagent_source.rs',
      ],
      forbidRequiredFeatures: true,
    },
  ]);
  assert.deepEqual(codexAdapterIntegrationTestTargets, [
    {
      name: 'codex_source_contracts',
      path: 'tests/codex_source_contracts.rs',
      leaves: [
        'tests/codex_source_contracts/hook_source.rs',
        'tests/codex_source_contracts/mcp_source.rs',
        'tests/codex_source_contracts/subagent_source.rs',
      ],
      forbidRequiredFeatures: true,
    },
  ]);
  assert.deepEqual(externalSourcesIntegrationTestTargets, [
    {
      name: 'external_source_coordination_contracts',
      path: 'tests/external_source_coordination_contracts.rs',
      leaves: [
        'tests/external_source_coordination_contracts/control_plane.rs',
        'tests/external_source_coordination_contracts/coordinator_contracts.rs',
        'tests/external_source_coordination_contracts/hook_coordinator.rs',
        'tests/external_source_coordination_contracts/mcp_coordinator.rs',
        'tests/external_source_coordination_contracts/subagent_coordinator.rs',
        'tests/external_source_coordination_contracts/tool_coordinator_contracts.rs',
        'tests/external_source_coordination_contracts/workspace_reference.rs',
      ],
      forbidRequiredFeatures: true,
    },
  ]);
  assert.deepEqual(
    checkExternalSourceIntegrationTestTopologies(repositoryRoot),
    [],
  );
});

test('Web UI command contracts do not become Rust compilation inputs', async () => {
  const webApiPath = 'src/web-ui/src/infrastructure/api/service-api/ExternalSourcesAPI.ts';
  const webCommandRule = requiredContentRules.find(
    (rule) => rule.path === webApiPath
      && rule.reason.includes('stable Desktop command'),
  );
  assert.ok(webCommandRule, 'Web API must retain a boundary-owned stable command contract');

  const webCommandPattern = webCommandRule.patterns.find(
    (pattern) => pattern.message.includes('external-source control snapshot'),
  )?.regex;
  assert.ok(webCommandPattern, 'Web API command contract must name the control snapshot');

  const webApi = await readFile(new URL(`../${webApiPath}`, import.meta.url), 'utf8');
  assert.equal(webCommandPattern.test(webApi), true);
  assert.equal(
    webCommandPattern.test(
      webApi.replace('get_external_source_control_snapshot', 'get_renamed_snapshot'),
    ),
    false,
    'renaming the invoked command must break the cross-surface contract',
  );

  const rustSourceRule = forbiddenContentUnderRules.find(
    (rule) => rule.path === '.'
      && rule.reason.includes('Rust source must not reference the Web UI source tree'),
  );
  assert.ok(rustSourceRule, 'all tracked Rust sources must reject Web UI file inputs');
  for (const mutation of [
    'let web = include_str!(\n  "../../web-ui/src/infrastructure/api.ts"\n);',
    'let web = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../web-ui/src/api.ts"));',
    'let web = include!("../../web-ui/public/generated.rs");',
    'let web = include_dir!("../../web-ui/src");',
    'let path = PathBuf::from("../../web-ui/src/api.ts");',
    'let path = PathBuf::from("../../").join("web-ui").join("src");',
    'const WEB_UI_DIR: &str = "web-ui"; let body = fs::read_to_string(WEB_UI_DIR);',
    'let example = r#"include_str!(\"../../web-ui/src/api.ts\")"#;',
  ]) {
    assert.equal(
      findForbiddenContentMatches(mutation, rustSourceRule.patterns, 'src/example.rs').length,
      1,
      `Rust/Web input guard must reject: ${mutation}`,
    );
  }
  for (const allowed of [
    '// include_str!("../../web-ui/src/comment-only.ts")',
    '/* PathBuf::from("../../web-ui/public/comment-only.json") */',
    'const REVIEW_SCOPE: &str = "src/frontend/src/**/*.ts";',
  ]) {
    assert.deepEqual(
      findForbiddenContentMatches(allowed, rustSourceRule.patterns, 'src/example.rs'),
      [],
      `Rust/Web input guard must ignore non-input text: ${allowed}`,
    );
  }
  assert.deepEqual(
    findForbiddenContentMatches(
      'allowed\nforbidden',
      [{ regex: /forbidden/, message: 'line-based guard' }],
      'src/example.rs',
    ),
    [{ line: 2, message: 'line-based guard' }],
  );
});

test('runtime-services test support is absent from ordinary library builds', async () => {
  const [manifest, library] = await Promise.all([
    readFile(
      new URL('../src/crates/execution/runtime-services/Cargo.toml', import.meta.url),
      'utf8',
    ),
    readFile(
      new URL('../src/crates/execution/runtime-services/src/lib.rs', import.meta.url),
      'utf8',
    ),
  ]);

  assert.match(manifest, /^test-support\s*=\s*\[\]\s*$/m);
  assert.doesNotMatch(manifest, /^required-features\s*=.*test-support.*$/m);
  assert.match(
    library,
    /#\[cfg\(any\(test, feature = "test-support"\)\)\]\s*pub mod test_support;/,
  );
  assert.match(library, /#\[cfg\(test\)\]\s*mod runtime_services_contracts;/);
  assert.equal((library.match(/^pub mod test_support;\s*$/gm) ?? []).length, 1);
});

test('feature-gated integration targets reject extra umbrella requirements', () => {
  const sourcePath = join(TEST_ROOT, 'tests', 'focused.rs');
  const pkg = {
    ...packageAt('example', 'src/crates/services/example/Cargo.toml'),
    targets: [integrationTarget('focused', sourcePath, ['focused', 'product-full'])],
  };

  const violations = findFeatureGatedTestTargetViolations([pkg], {
    readSource: () => '#![cfg(feature = "focused")]\n',
  });

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /unexpected required-features: product-full/);
});

test('target guard ignores module cfg and non-integration targets', () => {
  const moduleSourcePath = join(TEST_ROOT, 'tests', 'module.rs');
  const binarySourcePath = join(TEST_ROOT, 'src', 'main.rs');
  const pkg = {
    ...packageAt('example', 'src/crates/services/example/Cargo.toml'),
    targets: [
      integrationTarget('module', moduleSourcePath),
      {
        ...integrationTarget('binary', binarySourcePath),
        kind: ['bin'],
      },
    ],
  };
  const sources = new Map([
    [moduleSourcePath, '#[cfg(feature = "serde")]\nmod serde_tests {}\n'],
    [binarySourcePath, '#![cfg(feature = "cli")]\nfn main() {}\n'],
  ]);

  assert.deepEqual(
    findFeatureGatedTestTargetViolations([pkg], {
      readSource: (path) => sources.get(path),
    }),
    [],
  );
});

test('target guard ignores crate cfg examples in comments and strings', () => {
  const sourcePath = join(TEST_ROOT, 'tests', 'documented.rs');
  const pkg = {
    ...packageAt('example', 'src/crates/services/example/Cargo.toml'),
    targets: [integrationTarget('documented', sourcePath)],
  };

  assert.deepEqual(
    findFeatureGatedTestTargetViolations([pkg], {
      readSource: () => [
        '// Example: #![cfg(feature = "commented")]',
        'const EXAMPLE: &str = r#"',
        '#![cfg(feature = "string-literal")]',
        '"#;',
      ].join('\n'),
    }),
    [],
  );
});

test('target guard rejects feature OR gates that Cargo cannot express', () => {
  const sourcePath = join(TEST_ROOT, 'tests', 'provider.rs');
  const pkg = {
    ...packageAt('example', 'src/crates/services/example/Cargo.toml'),
    targets: [integrationTarget('provider', sourcePath, ['provider-a'])],
  };

  const violations = findFeatureGatedTestTargetViolations([pkg], {
    readSource: () => '#![cfg(any(feature = "provider-a", feature = "provider-b"))]\n',
  });

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /cannot express.*split the target/);
});

test('multiple crate feature gates combine as required feature AND conditions', () => {
  const sourcePath = join(TEST_ROOT, 'tests', 'combined.rs');
  const pkg = {
    ...packageAt('example', 'src/crates/services/example/Cargo.toml'),
    targets: [integrationTarget('combined', sourcePath, ['first'])],
  };

  const violations = findFeatureGatedTestTargetViolations([pkg], {
    readSource: () => '#![cfg(feature = "first")]\n#![cfg(feature = "second")]\n',
  });

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /second/);
});

test('product entrypoints may inherit the guarded empty openbitfun-core default', () => {
  const core = packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml');
  const app = packageAt('entry', 'src/apps/example/Cargo.toml', [
    pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      features: ['plugin-source'],
    }),
  ]);

  const violations = findProductEntrypointCoreFeatureViolations(
    [app, core],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.deepEqual(violations, []);
});

test('Core Agent Runtime baseline excludes concrete capability unions', () => {
  const agentRuntime = coreClosedFeatureProfileRules.find(
    (rule) => rule.featureName === 'agent-runtime',
  );
  assert.ok(agentRuntime, 'agent-runtime closed profile must exist');

  for (const forbidden of [
    'openbitfun-services-integrations/browser-control',
    'openbitfun-services-integrations/deep-research',
    'openbitfun-services-integrations/mcp',
    'openbitfun-services-integrations/models-dev',
    'openbitfun-services-integrations/remote-connect',
    'openbitfun-services-integrations/script-tool-runtime',
    'openbitfun-services-integrations/web-tools',
    'openbitfun-services-integrations/workspace-search',
    'dep:cron',
    'dep:semver',
    'dep:tokio-tungstenite',
    'git',
    'review-platform',
  ]) {
    assert.ok(
      !agentRuntime.requiredFeatureRefs.includes(forbidden),
      `agent-runtime must not own ${forbidden}`,
    );
  }
});

test('Core optional document and subscription capabilities have independent modifiers', () => {
  const ruleByFeature = new Map(
    coreClosedFeatureProfileRules.map((rule) => [rule.featureName, rule]),
  );
  assert.deepEqual(ruleByFeature.get('document-read')?.requiredFeatureRefs, [
    'tool-runtime?/document-read',
  ]);
  assert.deepEqual(ruleByFeature.get('subscription-auth')?.requiredFeatureRefs, [
    'openbitfun-ai-adapters?/subscription-auth',
  ]);
  assert.deepEqual(ruleByFeature.get('ai-adapter-runtime')?.requiredFeatureRefs, [
    'dep:openbitfun-ai-adapters',
    'dep:openbitfun-agent-runtime',
    'openbitfun-agent-runtime/account-routing',
    'openbitfun-services-core/routing-state',
  ]);
  assert.ok(
    !ruleByFeature.get('tools-basic')?.requiredFeatureRefs.includes('tool-runtime/document-read'),
    'baseline tools must not activate document conversion',
  );
});

test('Core product-full explicitly assembles service and tool capability owners', () => {
  for (const required of [
    'document-read',
    'subscription-auth',
    'i18n-runtime',
    'model-catalog',
    'mcp-runtime',
    'remote-connect',
    'workspace-search',
    'browser-control',
    'web-tools',
    'deep-research',
    'scheduled-jobs',
    'tools-basic',
    'tools-git',
    'tools-mcp',
    'tools-browser-web',
    'tools-computer-use',
    'tools-creation',
    'tools-image-analysis',
    'tools-image-generation',
    'tools-office-documents',
    'tools-miniapp',
    'tools-agent-control',
  ]) {
    assert.ok(
      coreProductFullFeatureAssemblyRule.requiredFeatureRefs.includes(required),
      `product-full must explicitly assemble ${required}`,
    );
  }
});

test('product entrypoints must select explicit openbitfun-core features', () => {
  const core = packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml');
  const interfacePackage = packageAt(
    'interface',
    'src/crates/interfaces/acp/Cargo.toml',
    [pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      usesDefaultFeatures: false,
    })],
  );

  const violations = findProductEntrypointCoreFeatureViolations(
    [interfacePackage, core],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /at least one explicit feature/);
});

test('explicit product entrypoint openbitfun-core feature selections pass', () => {
  const core = packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml');
  const consumers = [
    packageAt('app', 'src/apps/example/Cargo.toml'),
    packageAt('interface', 'src/crates/interfaces/acp/Cargo.toml'),
    packageAt('installer', 'OpenBitFun-Installer/src-tauri/Cargo.toml'),
  ].map((pkg) => ({
    ...pkg,
    dependencies: [pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      usesDefaultFeatures: false,
      features: ['plugin-source'],
    })],
  }));

  assert.deepEqual(
    findProductEntrypointCoreFeatureViolations(
      [...consumers, core, packageAt('no-core', 'src/apps/no-core/Cargo.toml')],
      { root: TEST_ROOT, crateLayoutRules },
    ),
    [],
  );
});

test('Desktop and Server must retain the full product Core capability closure', () => {
  const core = packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml');

  for (const [name, manifestPath] of [
    ['openbitfun-desktop', 'src/apps/desktop/Cargo.toml'],
    ['openbitfun-server', 'src/apps/server/Cargo.toml'],
  ]) {
    const product = packageAt(name, manifestPath, [
      pathDependency('src/crates/assembly/core', {
        name: 'openbitfun-core',
        usesDefaultFeatures: false,
        features: ['i18n-runtime'],
      }),
    ]);
    const messages = findProductEntrypointCoreFeatureViolations(
      [product, core],
      { root: TEST_ROOT, crateLayoutRules },
    ).map((violation) => violation.message);

    assert.deepEqual(messages, [
      `${name} Core capability closure must select exactly product-full`,
    ]);
  }
});

test('Desktop and Server must retain their Core product dependency', () => {
  const core = packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml');
  for (const [name, manifestPath] of [
    ['openbitfun-desktop', 'src/apps/desktop/Cargo.toml'],
    ['openbitfun-server', 'src/apps/server/Cargo.toml'],
  ]) {
    const product = packageAt(name, manifestPath);
    assert.deepEqual(
      findProductEntrypointCoreFeatureViolations(
        [product, core],
        { root: TEST_ROOT, crateLayoutRules },
      ).map((violation) => violation.message),
      [`${name} Core capability closure must keep the openbitfun-core dependency`],
    );
  }
});

test('Desktop must select only the ACP client role', () => {
  const acp = {
    ...packageAt('openbitfun-acp', 'src/crates/interfaces/acp/Cargo.toml'),
    features: {
      default: ['client', 'server'],
      client: [],
      server: [],
    },
  };
  const desktop = packageAt('openbitfun-desktop', 'src/apps/desktop/Cargo.toml', [
    pathDependency('src/crates/interfaces/acp', {
      name: 'openbitfun-acp',
      usesDefaultFeatures: false,
      features: ['client', 'server'],
    }),
  ]);

  const violations = findProductEntrypointCoreFeatureViolations(
    [desktop, acp],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /Desktop ACP role selection must not include server/);
});

test('ACP consumers must disable compatibility default roles', () => {
  const acp = {
    ...packageAt('openbitfun-acp', 'src/crates/interfaces/acp/Cargo.toml'),
    features: { default: ['client', 'server'], client: [], server: [] },
  };
  const desktop = packageAt('openbitfun-desktop', 'src/apps/desktop/Cargo.toml', [
    pathDependency('src/crates/interfaces/acp', {
      name: 'openbitfun-acp',
      usesDefaultFeatures: true,
      features: ['client'],
    }),
  ]);

  const violations = findProductEntrypointCoreFeatureViolations(
    [desktop, acp],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /must set default-features = false on every dependency/);
});

test('CLI must select both ACP roles explicitly', () => {
  const acp = {
    ...packageAt('openbitfun-acp', 'src/crates/interfaces/acp/Cargo.toml'),
    features: {
      default: ['client', 'server'],
      client: [],
      server: [],
    },
  };
  const cli = packageAt('openbitfun-cli', 'src/apps/cli/Cargo.toml', [
    pathDependency('src/crates/interfaces/acp', {
      name: 'openbitfun-acp',
      usesDefaultFeatures: false,
      features: ['client'],
    }),
  ]);

  const violations = findProductEntrypointCoreFeatureViolations(
    [cli, acp],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /CLI ACP role selection must include server/);
});

test('new product entrypoints must register an explicit ACP role selection', () => {
  const acp = {
    ...packageAt('openbitfun-acp', 'src/crates/interfaces/acp/Cargo.toml'),
    features: {
      default: ['client', 'server'],
      client: [],
      server: [],
    },
  };
  const newHost = packageAt('openbitfun-new-host', 'src/apps/new-host/Cargo.toml', [
    pathDependency('src/crates/interfaces/acp', {
      name: 'openbitfun-acp',
      usesDefaultFeatures: false,
      features: ['client'],
    }),
  ]);

  const violations = findProductEntrypointCoreFeatureViolations(
    [newHost, acp],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /must register an explicit role selection/);
});

test('ACP roles must be selected by an unconditional normal dependency', () => {
  const acp = {
    ...packageAt('openbitfun-acp', 'src/crates/interfaces/acp/Cargo.toml'),
    features: {
      default: ['client', 'server'],
      client: [],
      server: [],
    },
  };
  const desktop = packageAt('openbitfun-desktop', 'src/apps/desktop/Cargo.toml', [
    pathDependency('src/crates/interfaces/acp', {
      name: 'openbitfun-acp',
      kind: 'dev',
      usesDefaultFeatures: false,
      features: ['client'],
    }),
  ]);

  const violations = findProductEntrypointCoreFeatureViolations(
    [desktop, acp],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.equal(violations.length, 1);
  assert.match(
    violations[0].message,
    /Desktop ACP role selection must keep an unconditional normal openbitfun-acp dependency/,
  );
});

test('reviewed ACP roles require an unconditional normal dependency', () => {
  const acp = {
    ...packageAt('openbitfun-acp', 'src/crates/interfaces/acp/Cargo.toml'),
    features: { default: ['client', 'server'], client: [], server: [] },
  };
  const desktop = packageAt('openbitfun-desktop', 'src/apps/desktop/Cargo.toml', [
    pathDependency('src/crates/interfaces/acp', {
      name: 'openbitfun-acp',
      target: 'cfg(windows)',
      usesDefaultFeatures: false,
      features: ['client'],
    }),
  ]);

  const violations = findProductEntrypointCoreFeatureViolations(
    [desktop, acp],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /must keep an unconditional normal openbitfun-acp dependency/);
});

test('target-specific ACP edges cannot expand a reviewed product role', () => {
  const acp = {
    ...packageAt('openbitfun-acp', 'src/crates/interfaces/acp/Cargo.toml'),
    features: { default: ['client', 'server'], client: [], server: [] },
  };
  const desktop = packageAt('openbitfun-desktop', 'src/apps/desktop/Cargo.toml', [
    pathDependency('src/crates/interfaces/acp', {
      name: 'openbitfun-acp',
      usesDefaultFeatures: false,
      features: ['client'],
    }),
    pathDependency('src/crates/interfaces/acp', {
      name: 'openbitfun-acp',
      target: 'cfg(windows)',
      usesDefaultFeatures: false,
      features: ['server'],
    }),
  ]);

  const violations = findProductEntrypointCoreFeatureViolations(
    [desktop, acp],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /Desktop ACP role selection must not include server/);
});

test('dev and build ACP edges cannot expand a reviewed product role', () => {
  const acp = {
    ...packageAt('openbitfun-acp', 'src/crates/interfaces/acp/Cargo.toml'),
    features: { default: ['client', 'server'], client: [], server: [] },
  };

  for (const kind of ['dev', 'build']) {
    const desktop = packageAt('openbitfun-desktop', 'src/apps/desktop/Cargo.toml', [
      pathDependency('src/crates/interfaces/acp', {
        name: 'openbitfun-acp',
        usesDefaultFeatures: false,
        features: ['client'],
      }),
      pathDependency('src/crates/interfaces/acp', {
        name: 'openbitfun-acp',
        kind,
        usesDefaultFeatures: false,
        features: ['server'],
      }),
    ]);

    const violations = findProductEntrypointCoreFeatureViolations(
      [desktop, acp],
      { root: TEST_ROOT, crateLayoutRules },
    );

    assert.equal(violations.length, 1, `${kind} dependency must not widen Desktop ACP roles`);
    assert.match(violations[0].message, /Desktop ACP role selection must not include server/);
  }
});

test('reviewed ACP product dependencies must not become optional', () => {
  const acp = {
    ...packageAt('openbitfun-acp', 'src/crates/interfaces/acp/Cargo.toml'),
    features: { default: ['client', 'server'], client: [], server: [] },
  };
  const desktop = packageAt('openbitfun-desktop', 'src/apps/desktop/Cargo.toml', [
    pathDependency('src/crates/interfaces/acp', {
      name: 'openbitfun-acp',
      optional: true,
      usesDefaultFeatures: false,
      features: ['client'],
    }),
  ]);

  const violations = findProductEntrypointCoreFeatureViolations(
    [desktop, acp],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.equal(violations.length, 2);
  assert.match(violations[0].message, /must keep an unconditional normal openbitfun-acp dependency/);
  assert.match(violations[1].message, /must not make a openbitfun-acp dependency optional/);
});

test('target, dev, and build ACP consumers must still register their role selection', () => {
  const acp = {
    ...packageAt('openbitfun-acp', 'src/crates/interfaces/acp/Cargo.toml'),
    features: { default: ['client', 'server'], client: [], server: [] },
  };
  for (const dependency of [
    { target: 'cfg(windows)' },
    { kind: 'dev' },
    { kind: 'build' },
  ]) {
    const newHost = packageAt('openbitfun-new-host', 'src/apps/new-host/Cargo.toml', [
      pathDependency('src/crates/interfaces/acp', {
        name: 'openbitfun-acp',
        ...dependency,
        usesDefaultFeatures: false,
        features: ['client'],
      }),
    ]);

    const violations = findProductEntrypointCoreFeatureViolations(
      [newHost, acp],
      { root: TEST_ROOT, crateLayoutRules },
    );

    assert.equal(violations.length, 1);
    assert.match(violations[0].message, /must register an explicit role selection/);
  }
});

const SDK_HOST_REVIEWED_CORE_FEATURES = [
  'agent-runtime',
  'document-read',
  'subscription-auth',
  'external-sources',
  'tools-basic',
  'tools-git',
  'tools-mcp',
  'tools-browser-web',
  'tools-computer-use',
  'tools-image-analysis',
  'tools-image-generation',
  'tools-office-documents',
  'tools-agent-control',
];

const ACP_REVIEWED_CORE_FEATURES = [
  ...SDK_HOST_REVIEWED_CORE_FEATURES,
  'ssh-remote',
];

const CLI_REVIEWED_CORE_FEATURES = [
  'workspace-icons',
  'tools-pages',
  ...ACP_REVIEWED_CORE_FEATURES,
  'decision-model-credentials',
  'product-search',
  'remote-connect',
  'file-watch',
  'plugin-runtime',
  'opencode-plugin-host',
  'dispatch-store',
  'workspace-intelligence-host',
];

const APP_SERVER_REVIEWED_CORE_FEATURES = [
  'external-sources',
  'git',
  'i18n-runtime',
  'remote-connect',
  'web-tools',
];

test('OpenCode Plugin Host keeps retired LSP outside its feature closure', () => {
  const rule = coreClosedFeatureProfileRules.find(
    (candidate) => candidate.manifestPath === 'src/crates/assembly/core/Cargo.toml'
      && candidate.featureName === 'opencode-plugin-host',
  );

  assert.ok(rule, 'opencode-plugin-host feature closure rule');
  assert.equal(rule.requiredFeatureRefs.includes('lsp'), false);
});

test('SDK Host Core capability closure keeps every reviewed owner', () => {
  const core = packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml');
  const sdkHost = packageAt(
    'openbitfun-sdk-host-app',
    'src/apps/sdk-host/Cargo.toml',
    [pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      usesDefaultFeatures: false,
      features: SDK_HOST_REVIEWED_CORE_FEATURES.filter(
        (feature) => feature !== 'external-sources',
      ),
    })],
  );

  const violations = findProductEntrypointCoreFeatureViolations(
    [sdkHost, core],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.deepEqual(violations.map((violation) => violation.message), [
    'openbitfun-sdk-host-app Core capability closure must include external-sources',
  ]);
});

test('SDK Host closure rejects unreviewed capability owners below Core', () => {
  const cases = [
    ['openbitfun-services-integrations', 'src/crates/services/services-integrations/Cargo.toml', 'remote-connect'],
    ['openbitfun-services-integrations', 'src/crates/services/services-integrations/Cargo.toml', 'remote-ssh'],
    ['openbitfun-services-integrations', 'src/crates/services/services-integrations/Cargo.toml', 'remote-ssh-concrete'],
    ['openbitfun-services-integrations', 'src/crates/services/services-integrations/Cargo.toml', 'function-agents'],
    ['openbitfun-services-integrations', 'src/crates/services/services-integrations/Cargo.toml', 'product-full'],
    ['openbitfun-product-domains', 'src/crates/contracts/product-domains/Cargo.toml', 'function-agents'],
    ['openbitfun-product-domains', 'src/crates/contracts/product-domains/Cargo.toml', 'product-full'],
    ['openbitfun-services-core', 'src/crates/services/services-core/Cargo.toml', 'dispatch-workspace'],
  ];

  for (const [ownerName, ownerManifest, forbiddenFeature] of cases) {
    const core = packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml');
    const owner = {
      ...packageAt(ownerName, ownerManifest),
      features: { [forbiddenFeature]: [] },
    };
    const bridge = packageAt('bridge', 'src/crates/assembly/bridge/Cargo.toml', [
      pathDependency(ownerManifest.replace('/Cargo.toml', ''), {
        name: ownerName,
        usesDefaultFeatures: false,
        features: [forbiddenFeature],
      }),
    ]);
    const sdkHost = packageAt(
      'openbitfun-sdk-host-app',
      'src/apps/sdk-host/Cargo.toml',
      [
        pathDependency('src/crates/assembly/core', {
          name: 'openbitfun-core',
          usesDefaultFeatures: false,
          features: SDK_HOST_REVIEWED_CORE_FEATURES,
        }),
        pathDependency('src/crates/assembly/bridge', { name: 'bridge' }),
      ],
    );

    const violations = findProductEntrypointCoreFeatureViolations(
      [sdkHost, bridge, core, owner],
      { root: TEST_ROOT, crateLayoutRules },
    );

    const forbiddenOwner = `${ownerName}/${forbiddenFeature}`;
    assert.equal(violations.length, 1, forbiddenOwner);
    assert.match(
      violations[0].message,
      new RegExp(forbiddenOwner),
    );
  }
});

test('SDK Host closure inspects lower owners forwarded by reviewed Core features', () => {
  const ownerManifest = 'src/crates/services/services-integrations/Cargo.toml';
  const core = {
    ...packageAt(
      'openbitfun-core',
      'src/crates/assembly/core/Cargo.toml',
      [pathDependency('src/crates/services/services-integrations', {
        name: 'openbitfun-services-integrations',
        optional: true,
        usesDefaultFeatures: false,
      })],
    ),
    features: {
      'external-sources': ['openbitfun-services-integrations/remote-connect'],
    },
  };
  const owner = {
    ...packageAt('openbitfun-services-integrations', ownerManifest),
    features: { 'remote-connect': [] },
  };
  const sdkHost = packageAt(
    'openbitfun-sdk-host-app',
    'src/apps/sdk-host/Cargo.toml',
    [pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      usesDefaultFeatures: false,
      features: SDK_HOST_REVIEWED_CORE_FEATURES,
    })],
  );

  const violations = findProductEntrypointCoreFeatureViolations(
    [sdkHost, core, owner],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.equal(violations.length, 1);
  assert.match(
    violations[0].message,
    /openbitfun-services-integrations\/remote-connect/,
  );
});

test('App Server Core capability closure keeps its production Git owner', () => {
  const core = packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml');
  const appServer = packageAt(
    'openbitfun-app-server',
    'src/crates/interfaces/app-server/Cargo.toml',
    [pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      usesDefaultFeatures: false,
      features: APP_SERVER_REVIEWED_CORE_FEATURES.filter((feature) => feature !== 'git'),
    })],
  );

  const violations = findProductEntrypointCoreFeatureViolations(
    [appServer, core],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.deepEqual(violations.map((violation) => violation.message), [
    'openbitfun-app-server Core capability closure must include git',
  ]);
});

test('App Server Core capability closure keeps its backend i18n runtime', () => {
  const core = packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml');
  const appServer = packageAt(
    'openbitfun-app-server',
    'src/crates/interfaces/app-server/Cargo.toml',
    [pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      usesDefaultFeatures: false,
      features: APP_SERVER_REVIEWED_CORE_FEATURES.filter(
        (feature) => feature !== 'i18n-runtime',
      ),
    })],
  );

  const violations = findProductEntrypointCoreFeatureViolations(
    [appServer, core],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.deepEqual(violations.map((violation) => violation.message), [
    'openbitfun-app-server Core capability closure must include i18n-runtime',
  ]);
});

test('App Server reviewed Core capability closure remains independently valid', () => {
  const core = packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml');
  const appServer = packageAt(
    'openbitfun-app-server',
    'src/crates/interfaces/app-server/Cargo.toml',
    [pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      usesDefaultFeatures: false,
      features: APP_SERVER_REVIEWED_CORE_FEATURES,
    })],
  );

  assert.deepEqual(
    findProductEntrypointCoreFeatureViolations(
      [appServer, core],
      { root: TEST_ROOT, crateLayoutRules },
    ),
    [],
  );
});

test('ACP Core capability closure rejects the unreviewed MiniApp tool owner', () => {
  const core = packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml');
  const acp = packageAt('openbitfun-acp', 'src/crates/interfaces/acp/Cargo.toml', [
    pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      usesDefaultFeatures: false,
      features: [...ACP_REVIEWED_CORE_FEATURES, 'tools-miniapp'],
    }),
  ]);

  const violations = findProductEntrypointCoreFeatureViolations(
    [acp, core],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /must not include unreviewed feature tools-miniapp/);
});

test('ACP Core capability closure validation cannot be disabled by removing an owner', () => {
  const core = packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml');
  const acp = packageAt('openbitfun-acp', 'src/crates/interfaces/acp/Cargo.toml', [
    pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      usesDefaultFeatures: false,
      features: ACP_REVIEWED_CORE_FEATURES.filter((feature) => feature !== 'agent-runtime'),
    }),
  ]);

  const violations = findProductEntrypointCoreFeatureViolations(
    [acp, core],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.deepEqual(violations.map((violation) => violation.message), [
    'openbitfun-acp Core capability closure must include agent-runtime',
  ]);
});

test('CLI Core capability closure requires every reviewed owner', () => {
  const core = packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml');
  const cli = packageAt('openbitfun-cli', 'src/apps/cli/Cargo.toml', [
    pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      usesDefaultFeatures: false,
      features: CLI_REVIEWED_CORE_FEATURES.filter((feature) => feature !== 'plugin-runtime'),
    }),
  ]);

  const violations = findProductEntrypointCoreFeatureViolations(
    [cli, core],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /must include plugin-runtime/);
});

test('CLI openbitfun-core dev-dependency may select only test-support', () => {
  const core = packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml');
  const cli = packageAt('openbitfun-cli', 'src/apps/cli/Cargo.toml', [
    pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      usesDefaultFeatures: false,
      features: CLI_REVIEWED_CORE_FEATURES,
    }),
    pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      kind: 'dev',
      usesDefaultFeatures: false,
      features: ['test-support'],
    }),
  ]);

  assert.deepEqual(
    findProductEntrypointCoreFeatureViolations(
      [cli, core],
      { root: TEST_ROOT, crateLayoutRules },
    ),
    [],
  );
});

test('CLI openbitfun-core dev-dependency cannot widen the product capability closure', () => {
  const core = packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml');
  const cli = packageAt('openbitfun-cli', 'src/apps/cli/Cargo.toml', [
    pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      usesDefaultFeatures: false,
      features: CLI_REVIEWED_CORE_FEATURES,
    }),
    pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      kind: 'dev',
      usesDefaultFeatures: false,
      features: ['test-support', 'tools-miniapp'],
    }),
  ]);

  const violations = findProductEntrypointCoreFeatureViolations(
    [cli, core],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.equal(violations.length, 1);
  assert.match(
    violations[0].message,
    /openbitfun-core dev-dependency may select only test-support, not \[test-support, tools-miniapp\]/,
  );
});

test('CLI entrypoint must not select the product-full Core feature', () => {
  const core = packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml');
  const cli = packageAt('openbitfun-cli', 'src/apps/cli/Cargo.toml', [
    pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      usesDefaultFeatures: false,
      features: ['product-full'],
    }),
  ]);

  const violations = findProductEntrypointCoreFeatureViolations(
    [cli, core],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.ok(violations.some((violation) =>
    /openbitfun-cli -> openbitfun-core\/product-full/.test(violation.message)));
});

test('CLI entrypoint must not reach product-full through a Core owner feature', () => {
  const core = {
    ...packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml'),
    features: {
      'agent-runtime': ['runtime-services', 'product-full'],
      'runtime-services': ['dep:openbitfun-runtime-services'],
      'product-full': ['dep:openbitfun-agent-runtime'],
    },
  };
  const cli = packageAt('openbitfun-cli', 'src/apps/cli/Cargo.toml', [
    pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      usesDefaultFeatures: false,
      features: ['agent-runtime'],
    }),
  ]);

  const violations = findProductEntrypointCoreFeatureViolations(
    [cli, core],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.ok(violations.some((violation) =>
    /openbitfun-cli -> openbitfun-core\/product-full/.test(violation.message)));
});

test('CLI dependency closure must not re-enable product-full through an interface crate', () => {
  const core = packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml');
  const acp = packageAt('openbitfun-acp', 'src/crates/interfaces/acp/Cargo.toml', [
    pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      usesDefaultFeatures: false,
      features: ['product-full'],
    }),
  ]);
  const cli = packageAt('openbitfun-cli', 'src/apps/cli/Cargo.toml', [
    pathDependency('src/crates/interfaces/acp', { name: 'openbitfun-acp' }),
  ]);

  const violations = findProductEntrypointCoreFeatureViolations(
    [cli, acp, core],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.ok(violations.some((violation) =>
    /openbitfun-cli -> openbitfun-acp -> openbitfun-core\/product-full/.test(violation.message)));
});

test('CLI dependency closure rejects indirect Core default features', () => {
  const core = {
    ...packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml'),
    features: { default: ['product-full'], 'product-full': [] },
  };
  const bridge = packageAt('bridge', 'src/crates/assembly/bridge/Cargo.toml', [
    pathDependency('src/crates/assembly/core', { name: 'openbitfun-core' }),
  ]);
  const cli = packageAt('openbitfun-cli', 'src/apps/cli/Cargo.toml', [
    pathDependency('src/crates/assembly/bridge', { name: 'bridge' }),
  ]);

  const violations = findProductEntrypointCoreFeatureViolations(
    [cli, bridge, core],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /openbitfun-cli -> bridge -> openbitfun-core\/product-full/);
});

test('CLI dependency closure resolves active intermediate feature forwarding', () => {
  const core = {
    ...packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml'),
    features: { default: ['product-full'], 'product-full': [] },
  };
  const bridge = {
    ...packageAt('bridge', 'src/crates/assembly/bridge/Cargo.toml', [
      pathDependency('src/crates/assembly/core', {
        name: 'openbitfun-core',
        optional: true,
        usesDefaultFeatures: false,
      }),
    ]),
    features: {
      default: ['full'],
      full: ['dep:openbitfun-core', 'openbitfun-core/product-full'],
    },
  };
  const cli = packageAt('openbitfun-cli', 'src/apps/cli/Cargo.toml', [
    pathDependency('src/crates/assembly/bridge', { name: 'bridge' }),
  ]);

  const violations = findProductEntrypointCoreFeatureViolations(
    [cli, bridge, core],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /openbitfun-cli -> bridge -> openbitfun-core\/product-full/);
});

test('CLI dependency closure resolves renamed optional dependency forwarding', () => {
  const core = {
    ...packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml'),
    features: { 'product-full': [] },
  };
  const bridge = {
    ...packageAt('bridge', 'src/crates/assembly/bridge/Cargo.toml', [
      pathDependency('src/crates/assembly/core', {
        name: 'openbitfun-core',
        rename: 'core-alias',
        optional: true,
        usesDefaultFeatures: false,
      }),
    ]),
    features: {
      full: ['dep:core-alias', 'core-alias/product-full'],
    },
  };
  const cli = packageAt('openbitfun-cli', 'src/apps/cli/Cargo.toml', [
    pathDependency('src/crates/assembly/bridge', {
      name: 'bridge',
      usesDefaultFeatures: false,
      features: ['full'],
    }),
  ]);

  const violations = findProductEntrypointCoreFeatureViolations(
    [cli, bridge, core],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /openbitfun-core\/product-full/);
});

test('CLI dependency closure unions weak forwarding and optional activation per package', () => {
  const core = {
    ...packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml'),
    features: { 'product-full': [] },
  };
  const bridge = {
    ...packageAt('bridge', 'src/crates/assembly/bridge/Cargo.toml', [
      pathDependency('src/crates/assembly/core', {
        name: 'openbitfun-core',
        optional: true,
        usesDefaultFeatures: false,
      }),
    ]),
    features: {
      forward: ['openbitfun-core?/product-full'],
      activate: ['dep:openbitfun-core'],
    },
  };
  const left = packageAt('left', 'src/crates/assembly/left/Cargo.toml', [
    pathDependency('src/crates/assembly/bridge', {
      name: 'bridge',
      usesDefaultFeatures: false,
      features: ['forward'],
    }),
  ]);
  const right = packageAt('right', 'src/crates/assembly/right/Cargo.toml', [
    pathDependency('src/crates/assembly/bridge', {
      name: 'bridge',
      usesDefaultFeatures: false,
      features: ['activate'],
    }),
  ]);
  const cli = packageAt('openbitfun-cli', 'src/apps/cli/Cargo.toml', [
    pathDependency('src/crates/assembly/left', { name: 'left' }),
    pathDependency('src/crates/assembly/right', { name: 'right' }),
  ]);

  const violations = findProductEntrypointCoreFeatureViolations(
    [cli, left, right, bridge, core],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /openbitfun-core\/product-full/);
});

test('CLI dependency closure keeps normal and build feature unions separate', () => {
  const core = {
    ...packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml'),
    features: { 'product-full': [] },
  };
  const bridge = {
    ...packageAt('bridge', 'src/crates/assembly/bridge/Cargo.toml', [
      pathDependency('src/crates/assembly/core', {
        name: 'openbitfun-core',
        optional: true,
        usesDefaultFeatures: false,
      }),
    ]),
    features: {
      forward: ['openbitfun-core?/product-full'],
      activate: ['dep:openbitfun-core'],
    },
  };
  const normalParent = packageAt('normal-parent', 'src/crates/assembly/normal-parent/Cargo.toml', [
    pathDependency('src/crates/assembly/bridge', {
      name: 'bridge',
      usesDefaultFeatures: false,
      features: ['forward'],
    }),
  ]);
  const buildParent = packageAt('build-parent', 'src/crates/assembly/build-parent/Cargo.toml', [
    pathDependency('src/crates/assembly/bridge', {
      name: 'bridge',
      usesDefaultFeatures: false,
      features: ['activate'],
    }),
  ]);
  const cli = packageAt('openbitfun-cli', 'src/apps/cli/Cargo.toml', [
    pathDependency('src/crates/assembly/normal-parent', { name: 'normal-parent' }),
    pathDependency('src/crates/assembly/build-parent', {
      name: 'build-parent',
      kind: 'build',
    }),
  ]);

  assert.deepEqual(
    findProductEntrypointCoreFeatureViolations(
      [cli, normalParent, buildParent, bridge, core],
      { root: TEST_ROOT, crateLayoutRules },
    ),
    [],
  );
});

test('CLI dependency closure keeps proc-macro and normal feature unions separate', () => {
  const core = {
    ...packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml'),
    features: { 'product-full': [] },
  };
  const shared = {
    ...packageAt('shared', 'src/crates/assembly/shared/Cargo.toml', [
      pathDependency('src/crates/assembly/core', {
        name: 'openbitfun-core',
        optional: true,
        usesDefaultFeatures: false,
      }),
    ]),
    features: {
      forward: ['openbitfun-core?/product-full'],
      activate: ['dep:openbitfun-core'],
    },
  };
  const normalParent = packageAt('normal-parent', 'src/crates/assembly/normal-parent/Cargo.toml', [
    pathDependency('src/crates/assembly/shared', {
      name: 'shared',
      usesDefaultFeatures: false,
      features: ['forward'],
    }),
  ]);
  const macroParent = {
    ...packageAt('macro-parent', 'src/crates/assembly/macro-parent/Cargo.toml', [
      pathDependency('src/crates/assembly/shared', {
        name: 'shared',
        usesDefaultFeatures: false,
        features: ['activate'],
      }),
    ]),
    targets: [{ kind: ['proc-macro'] }],
  };
  const cli = packageAt('openbitfun-cli', 'src/apps/cli/Cargo.toml', [
    pathDependency('src/crates/assembly/normal-parent', { name: 'normal-parent' }),
    pathDependency('src/crates/assembly/macro-parent', { name: 'macro-parent' }),
  ]);

  assert.deepEqual(
    findProductEntrypointCoreFeatureViolations(
      [cli, normalParent, macroParent, shared, core],
      { root: TEST_ROOT, crateLayoutRules },
    ),
    [],
  );
});

test('CLI dependency architecture closure cannot hide features behind target cfgs', () => {
  const core = {
    ...packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml'),
    features: { 'product-full': [] },
  };
  const bridge = {
    ...packageAt('bridge', 'src/crates/assembly/bridge/Cargo.toml', [
      pathDependency('src/crates/assembly/core', {
        name: 'openbitfun-core',
        optional: true,
        usesDefaultFeatures: false,
      }),
    ]),
    features: {
      forward: ['openbitfun-core?/product-full'],
      activate: ['dep:openbitfun-core'],
    },
  };
  const cli = packageAt('openbitfun-cli', 'src/apps/cli/Cargo.toml', [
    pathDependency('src/crates/assembly/bridge', {
      name: 'bridge',
      target: 'cfg(windows)',
      usesDefaultFeatures: false,
      features: ['forward'],
    }),
    pathDependency('src/crates/assembly/bridge', {
      name: 'bridge',
      target: 'cfg(unix)',
      usesDefaultFeatures: false,
      features: ['activate'],
    }),
  ]);

  const violations = findProductEntrypointCoreFeatureViolations(
    [cli, bridge, core],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /openbitfun-core\/product-full/);
});

test('CLI dependency architecture closure unions unconditional and target-specific declarations', () => {
  const core = {
    ...packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml'),
    features: { 'product-full': [] },
  };
  const bridge = {
    ...packageAt('bridge', 'src/crates/assembly/bridge/Cargo.toml', [
      pathDependency('src/crates/assembly/core', {
        name: 'openbitfun-core',
        optional: true,
        usesDefaultFeatures: false,
      }),
    ]),
    features: {
      forward: ['openbitfun-core?/product-full'],
      activate: ['dep:openbitfun-core'],
    },
  };
  const cli = packageAt('openbitfun-cli', 'src/apps/cli/Cargo.toml', [
    pathDependency('src/crates/assembly/bridge', {
      name: 'bridge',
      usesDefaultFeatures: false,
      features: ['forward'],
    }),
    pathDependency('src/crates/assembly/bridge', {
      name: 'bridge',
      target: 'cfg(windows)',
      usesDefaultFeatures: false,
      features: ['activate'],
    }),
  ]);

  const violations = findProductEntrypointCoreFeatureViolations(
    [cli, bridge, core],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /openbitfun-core\/product-full/);
});

function reviewedCoreFeaturesFor(rootName) {
  return rootName === 'openbitfun-cli'
    ? CLI_REVIEWED_CORE_FEATURES
    : ACP_REVIEWED_CORE_FEATURES;
}

function targetedWeakForwardingGraph(rootName, forwardTarget, activateTarget, reverse = false) {
  const reviewedFeatures = reviewedCoreFeaturesFor(rootName);
  const core = {
    ...packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml'),
    features: Object.fromEntries([
      ...reviewedFeatures.map((feature) => [feature, []]),
      ['product-full', []],
    ]),
  };
  const bridge = {
    ...packageAt('bridge', 'src/crates/assembly/bridge/Cargo.toml', [
      pathDependency('src/crates/assembly/core', {
        name: 'openbitfun-core',
        optional: true,
        usesDefaultFeatures: false,
      }),
    ]),
    features: {
      forward: ['openbitfun-core?/product-full'],
      activate: ['dep:openbitfun-core'],
    },
  };
  const root = packageAt(rootName, rootName === 'openbitfun-cli'
    ? 'src/apps/cli/Cargo.toml'
    : 'src/crates/interfaces/acp/Cargo.toml', [
    pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      usesDefaultFeatures: false,
      features: reviewedFeatures,
    }),
    pathDependency('src/crates/assembly/bridge', {
      name: 'bridge',
      target: forwardTarget,
      usesDefaultFeatures: false,
      features: [reverse ? 'activate' : 'forward'],
    }),
    pathDependency('src/crates/assembly/bridge', {
      name: 'bridge',
      target: activateTarget,
      usesDefaultFeatures: false,
      features: [reverse ? 'forward' : 'activate'],
    }),
  ]);

  return { root, bridge, core };
}

test('CLI dependency architecture closure ignores Windows target spelling differences', () => {
  for (const reverse of [false, true]) {
    const { root, bridge, core } = targetedWeakForwardingGraph(
      'openbitfun-cli',
      'cfg(windows)',
      'cfg(target_os = "windows")',
      reverse,
    );
    const violations = findProductEntrypointCoreFeatureViolations(
      [root, bridge, core],
      { root: TEST_ROOT, crateLayoutRules },
    );

    assert.equal(violations.length, 1);
    assert.match(violations[0].message, /openbitfun-core\/product-full/);
  }
});

test('CLI dependency architecture closure includes Unix and not-Windows declarations', () => {
  for (const reverse of [false, true]) {
    const { root, bridge, core } = targetedWeakForwardingGraph(
      'openbitfun-cli',
      'cfg(not(windows))',
      'cfg(unix)',
      reverse,
    );
    const violations = findProductEntrypointCoreFeatureViolations(
      [root, bridge, core],
      { root: TEST_ROOT, crateLayoutRules },
    );

    assert.equal(violations.length, 1);
    assert.match(violations[0].message, /openbitfun-core\/product-full/);
  }
});

test('CLI dependency architecture closure includes nested target-specific declarations', () => {
  const reviewedFeatures = reviewedCoreFeaturesFor('openbitfun-cli');
  const core = {
    ...packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml'),
    features: Object.fromEntries([
      ...reviewedFeatures.map((feature) => [feature, []]),
      ['product-full', []],
    ]),
  };
  const bridge = packageAt('bridge', 'src/crates/assembly/bridge/Cargo.toml', [
    pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      target: 'cfg(unix)',
      usesDefaultFeatures: false,
      features: ['product-full'],
    }),
  ]);
  const cli = packageAt('openbitfun-cli', 'src/apps/cli/Cargo.toml', [
    pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      usesDefaultFeatures: false,
      features: reviewedFeatures,
    }),
    pathDependency('src/crates/assembly/bridge', {
      name: 'bridge',
      target: 'cfg(windows)',
    }),
  ]);

  const violations = findProductEntrypointCoreFeatureViolations(
    [cli, bridge, core],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /openbitfun-core\/product-full/);
});

test('CLI dependency architecture closure includes target-specific build dependencies', () => {
  const reviewedFeatures = reviewedCoreFeaturesFor('openbitfun-cli');
  const core = {
    ...packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml'),
    features: Object.fromEntries([
      ...reviewedFeatures.map((feature) => [feature, []]),
      ['product-full', []],
    ]),
  };
  const bridge = packageAt('bridge', 'src/crates/assembly/bridge/Cargo.toml', [
    pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      kind: 'build',
      target: 'cfg(unix)',
      usesDefaultFeatures: false,
      features: ['product-full'],
    }),
  ]);
  const cli = packageAt('openbitfun-cli', 'src/apps/cli/Cargo.toml', [
    pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      usesDefaultFeatures: false,
      features: reviewedFeatures,
    }),
    pathDependency('src/crates/assembly/bridge', {
      name: 'bridge',
      target: 'cfg(windows)',
    }),
  ]);

  const violations = findProductEntrypointCoreFeatureViolations(
    [cli, bridge, core],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /openbitfun-core\/product-full/);
});

test('CLI dependency closure inspects non-default root features', () => {
  const reviewedFeatures = reviewedCoreFeaturesFor('openbitfun-cli');
  const core = {
    ...packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml'),
    features: Object.fromEntries([
      ...reviewedFeatures.map((feature) => [feature, []]),
      ['product-full', []],
    ]),
  };
  const bridge = packageAt('bridge', 'src/crates/assembly/bridge/Cargo.toml', [
    pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      usesDefaultFeatures: false,
      features: ['product-full'],
    }),
  ]);
  const cli = {
    ...packageAt('openbitfun-cli', 'src/apps/cli/Cargo.toml', [
      pathDependency('src/crates/assembly/core', {
        name: 'openbitfun-core',
        usesDefaultFeatures: false,
        features: reviewedFeatures,
      }),
      pathDependency('src/crates/assembly/bridge', {
        name: 'bridge',
        optional: true,
      }),
    ]),
    features: {
      default: [],
      bad: ['dep:bridge'],
    },
  };

  const violations = findProductEntrypointCoreFeatureViolations(
    [cli, bridge, core],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /openbitfun-core\/product-full/);
});

test('ACP dependency closure rejects indirect unreviewed Core features', () => {
  const reviewedFeatures = reviewedCoreFeaturesFor('openbitfun-acp');
  const core = {
    ...packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml'),
    features: Object.fromEntries([
      ...reviewedFeatures.map((feature) => [feature, []]),
      ['product-full', []],
    ]),
  };
  const bridge = packageAt('bridge', 'src/crates/assembly/bridge/Cargo.toml', [
    pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      usesDefaultFeatures: false,
      features: ['product-full'],
    }),
  ]);
  const acp = packageAt('openbitfun-acp', 'src/crates/interfaces/acp/Cargo.toml', [
    pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      usesDefaultFeatures: false,
      features: reviewedFeatures,
    }),
    pathDependency('src/crates/assembly/bridge', { name: 'bridge' }),
  ]);

  const violations = findProductEntrypointCoreFeatureViolations(
    [acp, bridge, core],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /openbitfun-core\/product-full/);
});

test('ACP active closure cannot be expanded by a reviewed owner definition', () => {
  const reviewedFeatures = reviewedCoreFeaturesFor('openbitfun-acp');
  const core = {
    ...packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml'),
    features: {
      ...Object.fromEntries(reviewedFeatures.map((feature) => [feature, []])),
      'tools-git': ['plugin-runtime'],
      'plugin-runtime': [],
    },
  };
  const acp = packageAt('openbitfun-acp', 'src/crates/interfaces/acp/Cargo.toml', [
    pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      usesDefaultFeatures: false,
      features: reviewedFeatures,
    }),
  ]);

  const violations = findProductEntrypointCoreFeatureViolations(
    [acp, core],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /openbitfun-core\/plugin-runtime/);
});

test('CLI dependency closure includes build dependencies and excluded capabilities', () => {
  const core = {
    ...packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml'),
    features: {
      'cli-everything': ['product-full'],
      'product-full': [],
    },
  };
  const bridge = packageAt('bridge', 'src/crates/assembly/bridge/Cargo.toml', [
    pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      kind: 'build',
      usesDefaultFeatures: false,
      features: ['cli-everything'],
    }),
  ]);
  const cli = packageAt('openbitfun-cli', 'src/apps/cli/Cargo.toml', [
    pathDependency('src/crates/assembly/bridge', { name: 'bridge' }),
  ]);

  const violations = findProductEntrypointCoreFeatureViolations(
    [cli, bridge, core],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /openbitfun-core\/product-full/);
});

test('only the CLI dependency closure may select the Core dispatch store', () => {
  const core = {
    ...packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml'),
    features: { 'dispatch-store': [] },
  };
  const bridge = packageAt('bridge', 'src/crates/assembly/bridge/Cargo.toml', [
    pathDependency('src/crates/assembly/core', {
      name: 'openbitfun-core',
      usesDefaultFeatures: false,
      features: ['dispatch-store'],
    }),
  ]);
  const closureViolations = (rootName, manifestPath) => findProductEntrypointCoreFeatureViolations(
    [
      packageAt(rootName, manifestPath, [
        pathDependency('src/crates/assembly/bridge', { name: 'bridge' }),
      ]),
      bridge,
      core,
    ],
    { root: TEST_ROOT, crateLayoutRules },
  );

  // The CLI is the reviewed outbound dispatch controller.
  assert.deepEqual(
    closureViolations('openbitfun-cli', 'src/apps/cli/Cargo.toml')
      .filter((violation) => /dispatch-store/.test(violation.message)),
    [],
  );

  const acpViolations = closureViolations(
    'openbitfun-acp',
    'src/crates/interfaces/acp/Cargo.toml',
  );
  assert.equal(acpViolations.length, 1);
  assert.match(acpViolations[0].message, /openbitfun-core\/dispatch-store/);
});

test('cargo layer checker rejects reverse edges across dependency kinds', () => {
  const packages = [
    packageAt('entry', 'src/apps/example/Cargo.toml'),
    packageAt('adapter', 'src/crates/adapters/transport/Cargo.toml'),
    packageAt('assembly', 'src/crates/assembly/core/Cargo.toml', [
      pathDependency('src/apps/example', { optional: true }),
    ]),
    packageAt('service', 'src/crates/services/services-core/Cargo.toml', [
      pathDependency('src/crates/adapters/transport'),
      pathDependency('src/crates/assembly/core', {
        kind: 'dev',
        target: 'cfg(windows)',
      }),
    ]),
    packageAt('runtime', 'src/crates/execution/agent-runtime/Cargo.toml', [
      pathDependency('src/crates/adapters/transport'),
      pathDependency('src/crates/services/services-core'),
    ]),
    packageAt('contract', 'src/crates/contracts/core-types/Cargo.toml', [
      pathDependency('src/crates/services/services-core', { kind: 'build' }),
    ]),
  ];

  const violations = findCargoLayerViolations(packages, {
    root: TEST_ROOT,
    crateLayoutRules,
  });

  assert.equal(violations.length, 6);
  assert.match(violations[0].message, /assembly.*->.*entry.*apps.*normal optional dependency/);
  assert.match(violations[1].message, /service.*services.*->.*adapter.*adapters.*normal dependency/);
  assert.match(violations[2].message, /service.*services.*->.*assembly.*dev dependency.*cfg\(windows\)/);
  assert.match(violations[3].message, /runtime.*execution.*->.*adapter.*adapters.*normal dependency/);
  assert.match(violations[4].message, /runtime.*execution.*->.*service.*services.*normal dependency/);
  assert.match(violations[5].message, /contract.*contracts.*->.*service.*services.*build dependency/);
});

test('workspace Tokio capabilities stay crate-owned', async () => {
  const repositoryRoot = fileURLToPath(new URL('..', import.meta.url));
  const workspaceManifest = await readFile(new URL('../Cargo.toml', import.meta.url), 'utf8');
  const workspaceTokio = workspaceManifest.match(/^tokio\s*=\s*\{[^}]+\}/m)?.[0];

  assert.ok(workspaceTokio, 'workspace dependencies must declare Tokio once');
  assert.match(workspaceTokio, /default-features\s*=\s*false/);
  assert.doesNotMatch(workspaceTokio, /(?:^|,\s*)features\s*=/);
  const packages = collectCargoMetadataPackages({ root: repositoryRoot });
  assert.deepEqual(findTokioDependencyFeatureViolations(packages), []);

  const integrations = packages.find((pkg) => pkg.name === 'openbitfun-services-integrations');
  const mutatedPackages = packages.map((pkg) => pkg === integrations
    ? {
        ...pkg,
        dependencies: pkg.dependencies.map((dependency) =>
          dependency.name === 'tokio' && (dependency.kind ?? null) === null
            ? { ...dependency, features: ['net'] }
            : dependency),
      }
    : pkg);
  assert.ok(
    findTokioDependencyFeatureViolations(mutatedPackages).some((violation) =>
      violation.message === 'openbitfun-services-integrations has unexpected base Tokio capabilities: net'),
  );
});

test('services integrations Tokio owner contracts reject feature-union masking', async () => {
  const manifest = await readFile(
    new URL('../src/crates/services/services-integrations/Cargo.toml', import.meta.url),
    'utf8',
  );
  const mutations = [
    ['browser-control', 'tokio/rt', /browser-control missing effective Tokio capabilities: rt/],
    ['plugin-source', 'tokio/time', /plugin-source missing effective Tokio capabilities: time/],
    ['mcp', 'tokio/process', /mcp missing effective Tokio capabilities: process/],
    ['miniapp-market', 'miniapp-runtime', /miniapp-market missing effective Tokio capabilities: fs/],
    ['function-agents', 'git', /function-agents missing effective Tokio capabilities: fs/],
    ['remote-ssh-concrete', 'remote-ssh', /remote-ssh-concrete missing effective Tokio capabilities: fs/],
  ];

  for (const [feature, value, expected] of mutations) {
    const mutated = removeFeatureValue(manifest, feature, value);
    assert.notEqual(mutated, manifest, `${feature} must own ${value} in the fixture`);
    const messages = findServicesIntegrationsTokioFeatureViolations(
      servicesIntegrationsPackage(mutated),
    ).map((violation) => violation.message).join('\n');
    assert.match(messages, expected);
  }
});

test('services integrations Reqwest policy uses Cargo-decoded feature references', () => {
  const pkg = servicesIntegrationsPackage(`
[features]
reqwest = ["dep:reqwest"]
browser-control = ["reqwest", "reqwest/rustls-no-provider"]
file-watch = ["reqwest?/__native-tls"]
mcp = ["reqwest", "reqwest/rustls-no-provider", "reqwest/json"]
models-dev = ["reqwest", "reqwest/rustls-no-provider", "reqwest/system-proxy"]
speech = ["reqwest", "reqwest/rustls-no-provider", "reqwest/http3"]
`);

  const messages = findServicesIntegrationsReqwestFeatureViolations(pkg)
    .map((violation) => violation.message)
    .join('\n');
  assert.match(messages, /browser-control.*missing Reqwest feature reference reqwest\/json/);
  assert.match(messages, /file-watch.*outside its reviewed owner features/);
  assert.match(messages, /mcp.*missing Reqwest feature reference reqwest\/stream/);
  assert.doesNotMatch(messages, /models-dev.*system-proxy/);
  assert.match(messages, /speech.*unreviewed Reqwest feature reference reqwest\/http3/);
  assert.doesNotMatch(messages, /missing reqwest\/rustls\b/);
  assert.doesNotMatch(messages, /unreviewed.*reqwest\/rustls-no-provider/);
});

test('every services integrations Reqwest owner activates the reviewed TLS provider', async () => {
  const manifest = await readFile(
    new URL('../src/crates/services/services-integrations/Cargo.toml', import.meta.url),
    'utf8',
  );
  const mutated = removeFeatureValue(
    manifest,
    'review-platform',
    'openbitfun-services-core/tls-provider',
  );
  assert.notEqual(mutated, manifest, 'review-platform must own the TLS provider in the fixture');

  const messages = findServicesIntegrationsReqwestFeatureViolations(
    servicesIntegrationsPackage(mutated),
  ).map((violation) => violation.message).join('\n');
  assert.match(messages, /review-platform.*missing openbitfun-services-core\/tls-provider/);
});

test('direct Reqwest clients reject extra decoded dependency and package features', () => {
  const pkg = {
    ...packageAt('openbitfun-cli', 'src/apps/cli/Cargo.toml', [{
      name: 'reqwest',
      kind: null,
      optional: false,
      uses_default_features: false,
      features: [
        'http2',
        'stream',
        'rustls-no-provider',
        '__native-tls',
      ],
    }]),
    features: { default: ['reqwest?/http3'] },
  };

  const messages = findReqwestDependencyFeatureViolations([pkg])
    .map((violation) => violation.message)
    .join('\n');
  assert.match(messages, /openbitfun-cli.*unexpected dependency features: __native-tls/);
  assert.match(messages, /openbitfun-cli:default.*unreviewed Reqwest feature reference reqwest\?\/http3/);

  const installerMessages = findReqwestDependencyFeatureViolations([{
    ...pkg,
    name: 'openbitfun-installer',
    manifest_path: join(TEST_ROOT, 'OpenBitFun-Installer', 'src-tauri', 'Cargo.toml'),
  }]).map((violation) => violation.message).join('\n');
  assert.match(installerMessages, /openbitfun-installer.*missing a reviewed owner profile/);
});

test('AI adapters Reqwest profile owns the supported SOCKS transport', () => {
  const baseFeatures = ['http2', 'json', 'stream'];
  const valid = {
    ...packageAt('openbitfun-ai-adapters', 'src/crates/adapters/ai-adapters/Cargo.toml', [
      {
        name: 'reqwest',
        kind: null,
        optional: false,
        uses_default_features: false,
        features: [...baseFeatures, 'rustls-no-provider', 'socks'],
      },
      {
        name: 'openbitfun-services-core',
        kind: null,
        optional: false,
        features: ['tls-provider'],
      },
    ]),
    features: { 'subscription-auth': ['reqwest/form'] },
  };
  const missingSocks = {
    ...packageAt(
    'openbitfun-ai-adapters',
    'src/crates/adapters/ai-adapters/Cargo.toml',
    [
      {
        name: 'reqwest',
        kind: null,
        optional: false,
        uses_default_features: false,
        features: [...baseFeatures, 'rustls-no-provider'],
      },
      {
        name: 'openbitfun-services-core',
        kind: null,
        optional: false,
        features: ['tls-provider'],
      },
    ],
    ),
    features: { 'subscription-auth': ['reqwest/form'] },
  };

  assert.deepEqual(findReqwestDependencyFeatureViolations([valid]), []);
  const messages = findReqwestDependencyFeatureViolations([missingSocks])
    .map((violation) => violation.message)
    .join('\n');
  assert.match(messages, /openbitfun-ai-adapters.*missing features: socks/);
});

test('Reqwest metadata policy covers URL-only and future dependency owners', () => {
  const coreFeatures = [];
  const core = {
    ...packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml', [{
      name: 'reqwest',
      kind: null,
      optional: true,
      uses_default_features: false,
      features: coreFeatures,
    }]),
    features: { product: ['dep:reqwest', 'reqwest/__native-tls'] },
  };
  const future = packageAt('future-client', 'src/crates/services/future-client/Cargo.toml', [{
    name: 'reqwest',
    kind: null,
    optional: false,
    uses_default_features: false,
    features: ['http2', 'rustls', 'stream'],
  }]);
  const duplicate = packageAt(
    'openbitfun-services-integrations',
    'src/crates/services/services-integrations/Cargo.toml',
    [
      {
        name: 'reqwest',
        kind: null,
        optional: true,
        uses_default_features: false,
        features: ['http2'],
      },
      {
        name: 'reqwest',
        rename: 'windows_reqwest',
        kind: null,
        optional: true,
        target: 'cfg(windows)',
        uses_default_features: false,
        features: ['http2', '__native-tls'],
      },
    ],
  );

  const messages = findReqwestDependencyFeatureViolations([core, future, duplicate])
    .map((violation) => violation.message)
    .join('\n');
  assert.match(messages, /openbitfun-core:product.*reqwest\/__native-tls/);
  assert.match(messages, /future-client.*missing a reviewed owner profile/);
  assert.match(messages, /openbitfun-services-integrations.*exactly one normal Reqwest dependency/);
});

test('Reqwest consumers inherit the workspace version without duplicating feature rules', async () => {
  const { requiredContentRules } = await import(
    './core-boundaries/rules/source/required-rules.mjs'
  );
  const rules = requiredContentRules.filter((rule) =>
    rule.reason.includes('Reqwest consumers must inherit the workspace-owned compatible version')
  );

  assert.equal(rules.length, 6);
  for (const rule of rules) {
    const pattern = rule.patterns[0].regex;
    assert.match('reqwest = { workspace = true, features = ["rustls-no-provider"] }', pattern);
    assert.doesNotMatch(
      'reqwest = { version = "99", features = ["rustls-no-provider"] }',
      pattern,
    );
  }
});

test('third-party capability profiles reject ambient feature unions and unreviewed owners', () => {
  const validPackages = [
    packageAt('openbitfun-cli', 'src/apps/cli/Cargo.toml', [{
      name: 'image',
      kind: null,
      optional: false,
      uses_default_features: false,
      features: ['gif', 'jpeg', 'png', 'webp'],
    }]),
    packageAt('openbitfun-server', 'src/apps/server/Cargo.toml', [{
      name: 'axum',
      kind: null,
      optional: false,
      uses_default_features: true,
      features: ['json', 'ws'],
    }]),
    packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml', [{
      name: 'tokio-tungstenite',
      kind: null,
      optional: true,
      uses_default_features: true,
      features: [],
    }]),
    packageAt('openbitfun-services-core', 'src/crates/services/services-core/Cargo.toml', [{
      name: 'git2',
      kind: null,
      optional: true,
      uses_default_features: false,
      features: ['vendored-libgit2'],
    }]),
    packageAt('openbitfun-webdriver', 'src/crates/adapters/webdriver/Cargo.toml', [{
      name: 'image', kind: null, optional: false, uses_default_features: false,
      features: ['jpeg', 'png'],
    }]),
  ];

  assert.deepEqual(findThirdPartyCapabilityFeatureViolations(validPackages), []);

  const mutatedPackages = structuredClone(validPackages);
  mutatedPackages[0].dependencies[0].features.push('bmp');
  mutatedPackages[1].dependencies[0].features = ['json'];
  mutatedPackages[2].dependencies[0].features.push('rustls-tls-native-roots');
  mutatedPackages[3].dependencies[0].features.push('https');
  mutatedPackages[3].dependencies[0].rename = 'private-git2';
  mutatedPackages[4].dependencies[0].features = ['png', 'webp'];
  mutatedPackages.push(packageAt('future-image-owner', 'src/apps/future/Cargo.toml', [{
    name: 'image',
    kind: null,
    optional: false,
    uses_default_features: false,
    features: ['png'],
  }]));

  const messages = findThirdPartyCapabilityFeatureViolations(mutatedPackages)
    .map((violation) => violation.message)
    .join('\n');
  assert.match(messages, /openbitfun-cli Image dependency has unexpected features: bmp/);
  assert.match(messages, /openbitfun-server Axum dependency missing features: ws/);
  assert.match(messages, /openbitfun-core Tokio Tungstenite dependency has unexpected features: rustls-tls-native-roots/);
  assert.match(messages, /openbitfun-services-core Git2 dependency has unexpected features: https/);
  assert.match(messages, /openbitfun-services-core Git2 dependency does not match its reviewed owner shape/);
  assert.match(messages, /openbitfun-webdriver Image dependency missing features: jpeg/);
  assert.match(messages, /openbitfun-webdriver Image dependency has unexpected features: webp/);
  assert.match(messages, /future-image-owner Image dependency is missing a reviewed owner profile/);
});

test('relay WebSocket lifecycle client stays test-only without TLS or defaults', () => {
  const pkg = packageAt('openbitfun-relay-service', 'src/crates/services/relay-service/Cargo.toml', [{
    name: 'tokio-tungstenite', kind: 'dev', optional: false, uses_default_features: false,
    features: ['connect', 'handshake'],
  }]);
  assert.deepEqual(findThirdPartyCapabilityFeatureViolations([pkg]), []);
  for (const change of [
    { kind: null }, { uses_default_features: true },
    { features: ['connect', 'handshake', 'rustls-tls-native-roots'] },
  ]) {
    const mutated = structuredClone(pkg);
    Object.assign(mutated.dependencies[0], change);
    assert.ok(findThirdPartyCapabilityFeatureViolations([mutated]).length > 0);
  }
});

test('services integrations image codecs stay attached to exact product owners', () => {
  const pkg = {
    ...packageAt('openbitfun-services-integrations', 'src/crates/services/services-integrations/Cargo.toml', [{
      name: 'image',
      kind: null,
      optional: true,
      uses_default_features: false,
      features: [],
    }]),
    features: {
      image: ['dep:image'],
      'miniapp-market': ['image', 'image/gif', 'image/jpeg', 'image/png', 'image/webp'],
      'remote-connect': [
        'image',
        'image/bmp',
        'image/gif',
        'image/jpeg',
        'image/png',
        'image/webp',
      ],
    },
  };

  assert.deepEqual(findThirdPartyCapabilityFeatureViolations([pkg]), []);

  const mutated = structuredClone(pkg);
  mutated.features.image.push('image/png');
  mutated.features['miniapp-market'].push('image/bmp');
  mutated.features['remote-connect'] = mutated.features['remote-connect']
    .filter((reference) => reference !== 'image/gif');
  mutated.features.default = ['image/png'];
  const messages = findThirdPartyCapabilityFeatureViolations([mutated])
    .map((violation) => violation.message)
    .join('\n');
  assert.match(messages, /miniapp-market.*unexpected Image capabilities: bmp/);
  assert.match(messages, /remote-connect.*missing Image capabilities: gif/);
  assert.match(messages, /default enables Image outside its reviewed owner features/);
  assert.match(messages, /image shared Image activation alias must not select capabilities: png/);
});

test('services integrations WebSocket TLS stays attached to reviewed realtime owners', () => {
  const pkg = {
    ...packageAt('openbitfun-services-integrations', 'src/crates/services/services-integrations/Cargo.toml', [{
      name: 'tokio-tungstenite',
      kind: null,
      optional: true,
      uses_default_features: true,
      features: [],
    }]),
    features: {
      'remote-connect': [
        'dep:tokio-tungstenite',
        'tokio-tungstenite?/rustls-tls-native-roots',
      ],
      'speech-realtime': [
        'dep:tokio-tungstenite',
        'tokio-tungstenite?/rustls-tls-native-roots',
      ],
    },
  };

  assert.deepEqual(findThirdPartyCapabilityFeatureViolations([pkg]), []);

  const mutated = structuredClone(pkg);
  mutated.features['tokio-tungstenite'] = ['dep:tokio-tungstenite'];
  mutated.features['future-non-remote-owner'] = ['dep:tokio-tungstenite'];
  const messages = findThirdPartyCapabilityFeatureViolations([mutated])
    .map((violation) => violation.message)
    .join('\n');
  assert.match(messages, /future-non-remote-owner enables Tokio Tungstenite outside its reviewed owner features/);
  assert.match(messages, /tokio-tungstenite enables Tokio Tungstenite outside its reviewed owner features/);
});

test('resolved third-party feature unions reject global capability regressions', () => {
  const validRecords = [
    {
      name: 'git2',
      version: '0.21.0',
      features: ['vendored-libgit2'],
    },
    {
      name: 'image',
      version: '0.24.9',
      features: ['default', 'exr', 'tiff'],
    },
    {
      name: 'image',
      version: '0.25.10',
      features: ['bmp', 'gif', 'jpeg', 'png', 'tiff', 'webp'],
    },
    {
      name: 'libgit2-sys',
      version: '0.18.7+1.9.6',
      features: ['vendored'],
    },
  ];

  assert.deepEqual(
    findResolvedThirdPartyCapabilityFeatureViolations(validRecords, { root: TEST_ROOT }),
    [],
  );

  const mutated = structuredClone(validRecords);
  mutated[0].features.push('https', 'vendored-openssl');
  mutated[2].features.push('exr');
  mutated[3].features.push('https', 'openssl-sys', 'vendored-openssl');
  mutated.push({
    name: 'image',
    version: '0.26.0',
    features: ['avif', 'default', 'exr'],
  });
  const messages = findResolvedThirdPartyCapabilityFeatureViolations(
    mutated,
    { root: TEST_ROOT },
  ).map((violation) => violation.message).join('\n');
  assert.match(messages, /resolved git2.*https, vendored-openssl/);
  assert.match(messages, /resolved image 0\.25\.10.*exr/);
  assert.match(messages, /resolved libgit2-sys.*https, openssl-sys, vendored-openssl/);
  assert.match(messages, /resolved image 0\.26\.0 uses an unreviewed version family/);
});

test('resolved Reqwest feature union rejects every native TLS backend alias', () => {
  const violations = findResolvedReqwestNativeTlsViolations(
    [
      {
        name: 'reqwest',
        version: '0.13.4',
        features: ['rustls', 'rustls-no-provider', '__native-tls', 'native-tls-vendored-no-alpn'],
      },
      {
        name: 'reqwest',
        version: '0.12.28',
        features: ['rustls-tls', 'default-tls'],
      },
      {
        name: 'rustls',
        version: '0.23.42',
        features: ['ring', 'std'],
      },
    ],
    { root: TEST_ROOT },
  );

  assert.equal(violations.length, 2);
  const messages = violations.map((violation) => violation.message).join('\n');
  assert.match(messages, /__native-tls, native-tls-vendored-no-alpn/);
  assert.match(messages, /reqwest 0\.12\.28.*default-tls/);
});

test('resolved Reqwest feature union rejects the AWS-LC selecting Rustls alias', () => {
  const violations = findResolvedReqwestNativeTlsViolations(
    [{
      name: 'reqwest',
      version: '0.13.4',
      features: ['rustls', 'rustls-no-provider'],
    }, {
      name: 'rustls',
      version: '0.23.42',
      features: ['ring', 'std'],
    }],
    { root: TEST_ROOT },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /rustls.*AWS-LC/);
});

test('resolved Rustls feature union rejects multiple crypto providers', () => {
  const violations = findResolvedReqwestNativeTlsViolations(
    [
      {
        name: 'reqwest',
        version: '0.13.4',
        features: ['rustls-no-provider'],
      },
      {
        name: 'rustls',
        version: '0.23.42',
        features: ['aws_lc_rs', 'ring', 'std'],
      },
    ],
    { root: TEST_ROOT },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /only the ring crypto provider.*aws_lc_rs, ring/);
});

test('resolved Rustls feature union normalizes and rejects AWS-LC aliases once', () => {
  const violations = findResolvedReqwestNativeTlsViolations(
    [
      {
        name: 'reqwest',
        version: '0.13.4',
        features: ['rustls-no-provider'],
      },
      {
        name: 'rustls',
        version: '0.23.42',
        features: ['aws-lc-rs', 'aws_lc_rs', 'std'],
      },
    ],
    { root: TEST_ROOT },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /selects aws_lc_rs$/);
});

test('resolved Rustls feature union rejects providers split across Rustls versions', () => {
  const violations = findResolvedReqwestNativeTlsViolations(
    [
      {
        name: 'reqwest',
        version: '0.13.4',
        features: ['rustls-no-provider'],
      },
      {
        name: 'rustls',
        version: '0.23.42',
        features: ['ring', 'std'],
      },
      {
        name: 'rustls',
        version: '0.22.4',
        features: ['aws_lc_rs', 'std'],
      },
    ],
    { root: TEST_ROOT },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /only the ring crypto provider.*aws_lc_rs, ring/);
});

test('resolved Reqwest Rustls closure rejects a missing crypto provider', () => {
  const violations = findResolvedReqwestNativeTlsViolations(
    [{
      name: 'reqwest',
      version: '0.13.4',
      features: ['rustls-no-provider'],
    }],
    { root: TEST_ROOT },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /selects \(no provider\)/);
});

test('resolved Reqwest Rustls closure rejects linked AWS-LC packages', () => {
  const violations = findResolvedReqwestNativeTlsViolations(
    [
      {
        name: 'reqwest',
        version: '0.13.4',
        features: ['rustls-no-provider'],
      },
      {
        name: 'rustls',
        version: '0.23.42',
        features: ['ring', 'std'],
      },
      {
        name: 'aws-lc-rs',
        version: '1.13.3',
        features: [],
      },
    ],
    { root: TEST_ROOT },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /aws_lc_rs, ring/);
});

test('Cargo metadata Tokio policy catches table-style and renamed full dependencies', () => {
  const pkg = packageAt('table-style', 'src/crates/services/table-style/Cargo.toml', [{
    name: 'tokio',
    rename: 'async_runtime',
    kind: null,
    optional: false,
    features: ['full'],
  }]);
  const violations = findTokioDependencyFeatureViolations([pkg]);

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /table-style must not enable tokio\/full/);

  const installerViolations = findTokioDependencyFeatureViolations([{
    ...pkg,
    name: 'openbitfun-installer',
    manifest_path: join(TEST_ROOT, 'OpenBitFun-Installer', 'src-tauri', 'Cargo.toml'),
  }]);
  assert.equal(installerViolations.length, 1);
  assert.match(installerViolations[0].message, /openbitfun-installer must not enable tokio\/full/);
});

test('cargo layer checker allows documented downward and peer dependencies', () => {
  const packages = [
    packageAt('entry', 'src/apps/example/Cargo.toml', [
      pathDependency('src/crates/interfaces/acp'),
      pathDependency('src/crates/assembly/core'),
    ]),
    packageAt('interface', 'src/crates/interfaces/acp/Cargo.toml', [
      pathDependency('src/crates/assembly/core'),
    ]),
    packageAt('assembly', 'src/crates/assembly/core/Cargo.toml', [
      pathDependency('src/crates/services/services-core'),
      pathDependency('src/crates/execution/agent-runtime'),
    ]),
    packageAt('service', 'src/crates/services/services-core/Cargo.toml', [
      pathDependency('src/crates/execution/agent-runtime'),
      pathDependency('src/crates/contracts/core-types'),
    ]),
    packageAt('runtime', 'src/crates/execution/agent-runtime/Cargo.toml', [
      pathDependency('src/crates/contracts/core-types'),
    ]),
    packageAt('contract', 'src/crates/contracts/core-types/Cargo.toml'),
  ];

  assert.deepEqual(
    findCargoLayerViolations(packages, {
      root: TEST_ROOT,
      crateLayoutRules,
    }),
    [],
  );
});

test('cargo layer checker uses resolved edges for locally patched dependencies', () => {
  const entry = packageAt('entry', 'src/apps/example/Cargo.toml');
  const assembly = packageAt('assembly', 'src/crates/assembly/core/Cargo.toml', [
    { name: 'entry', path: null, kind: null, optional: false, target: null },
  ]);

  const violations = findCargoLayerViolations(
    [entry, assembly],
    { root: TEST_ROOT, crateLayoutRules },
    [{
      sourceManifestPath: assembly.manifest_path,
      targetManifestPath: entry.manifest_path,
      name: 'entry',
      kind: null,
      optional: false,
      target: null,
    }],
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /assembly.*->.*entry.*apps.*normal dependency/);
});

test('cargo layer checker combines declared path dependencies with resolved edges', () => {
  const entry = packageAt('entry', 'src/apps/example/Cargo.toml');
  const assembly = packageAt('assembly', 'src/crates/assembly/core/Cargo.toml', [
    pathDependency('src/apps/example', { optional: true }),
  ]);

  const violations = findCargoLayerViolations(
    [entry, assembly],
    { root: TEST_ROOT, crateLayoutRules },
    [],
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /assembly.*->.*entry.*apps.*normal optional dependency/);
});

test('cargo layer checker deduplicates renamed declared and resolved edges', () => {
  const entry = packageAt('entry', 'src/apps/example/Cargo.toml');
  const assembly = packageAt('assembly', 'src/crates/assembly/core/Cargo.toml', [{
    ...pathDependency('src/apps/example', { name: 'entry', optional: true }),
    rename: 'legacy_entry',
  }]);

  const violations = findCargoLayerViolations(
    [entry, assembly],
    { root: TEST_ROOT, crateLayoutRules },
    [{
      sourceManifestPath: assembly.manifest_path,
      targetManifestPath: entry.manifest_path,
      name: 'legacy_entry',
      kind: null,
      optional: true,
      target: null,
    }],
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /assembly.*->.*entry.*apps.*normal optional dependency/);
});

test('cargo layer checker rejects repository packages without a known layer', () => {
  const violations = findCargoLayerViolations(
    [packageAt('mystery', 'tools/mystery/Cargo.toml')],
    { root: TEST_ROOT, crateLayoutRules },
  );

  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /unknown crate layer.*tools\/mystery\/Cargo\.toml/);
});

test('cargo metadata collection scans standalone manifests not covered by the workspace', () => {
  const workspaceManifest = join(TEST_ROOT, 'Cargo.toml');
  const memberManifest = join(TEST_ROOT, 'src', 'apps', 'example', 'Cargo.toml');
  const installerManifest = join(TEST_ROOT, 'OpenBitFun-Installer', 'src-tauri', 'Cargo.toml');
  const calls = [];

  const packages = collectCargoMetadataPackages({
    root: TEST_ROOT,
    manifestPaths: [workspaceManifest, memberManifest, installerManifest],
    loadMetadata(manifestPath, options) {
      calls.push([manifestPath, options]);
      if (manifestPath === workspaceManifest) {
        const entry = packageAt('entry', 'src/apps/example/Cargo.toml');
        return { packages: [entry], workspace_members: [entry.id] };
      }
      if (manifestPath === installerManifest) {
        return { packages: [packageAt('installer', 'OpenBitFun-Installer/src-tauri/Cargo.toml')] };
      }
      throw new Error(`workspace member metadata should not be loaded twice: ${manifestPath}`);
    },
  });

  assert.deepEqual(calls, [
    [workspaceManifest, { noDeps: false }],
    [installerManifest, { noDeps: true }],
  ]);
  assert.deepEqual(packages.map((pkg) => pkg.name), ['entry', 'installer']);
});

test('cargo metadata collection rescans standalone packages discovered by the workspace', () => {
  const workspaceManifest = join(TEST_ROOT, 'Cargo.toml');
  const serviceManifest = join(TEST_ROOT, 'src', 'crates', 'services', 'services-core', 'Cargo.toml');
  const assembly = packageAt('assembly', 'src/crates/assembly/core/Cargo.toml', [
    pathDependency('src/crates/services/services-core'),
  ]);
  const service = packageAt('service', 'src/crates/services/services-core/Cargo.toml', [
    pathDependency('src/apps/example', { optional: true }),
  ]);
  const entry = packageAt('example', 'src/apps/example/Cargo.toml');
  const calls = [];

  const graph = collectCargoMetadataGraph({
    root: TEST_ROOT,
    manifestPaths: [workspaceManifest, serviceManifest],
    loadMetadata(manifestPath, options) {
      calls.push([manifestPath, options]);
      if (manifestPath === workspaceManifest) {
        return {
          packages: [assembly, service, entry],
          workspace_members: [assembly.id],
          resolve: {
            nodes: [{
              id: assembly.id,
              deps: [{
                name: 'service',
                pkg: service.id,
                dep_kinds: [{ kind: null, target: null }],
              }],
            }],
          },
        };
      }
      return {
        packages: [service, entry],
        workspace_members: [service.id],
        resolve: {
          nodes: [{
            id: service.id,
            deps: [{
              name: 'example',
              pkg: entry.id,
              dep_kinds: [{ kind: null, target: null }],
            }],
          }],
        },
      };
    },
  });

  const violations = findCargoLayerViolations(
    graph.packages,
    { root: TEST_ROOT, crateLayoutRules },
    graph.resolvedDependencies,
  );

  assert.deepEqual(calls, [
    [workspaceManifest, { noDeps: false }],
    [serviceManifest, { noDeps: true }],
  ]);
  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /service.*services.*->.*example.*apps.*normal optional dependency/);
});

test('cargo metadata collection preserves resolved repository edges', () => {
  const workspaceManifest = join(TEST_ROOT, 'Cargo.toml');
  const assembly = packageAt('assembly', 'src/crates/assembly/core/Cargo.toml', [{
    name: 'entry',
    rename: null,
    path: null,
    kind: 'dev',
    optional: true,
    target: 'cfg(windows)',
  }]);
  const entry = packageAt('entry', 'src/apps/example/Cargo.toml');

  const graph = collectCargoMetadataGraph({
    root: TEST_ROOT,
    manifestPaths: [workspaceManifest],
    loadMetadata() {
      return {
        packages: [assembly, entry],
        resolve: {
          nodes: [{
            id: assembly.id,
            deps: [{
              name: 'entry',
              pkg: entry.id,
              dep_kinds: [{ kind: 'dev', target: 'cfg(windows)' }],
            }],
          }],
        },
      };
    },
  });

  assert.deepEqual(graph.packages.map((pkg) => pkg.name), ['assembly', 'entry']);
  assert.equal(graph.resolvedDependencies.length, 1);
  assert.equal(graph.resolvedDependencies[0].sourceManifestPath, assembly.manifest_path);
  assert.equal(graph.resolvedDependencies[0].targetManifestPath, entry.manifest_path);
  assert.equal(graph.resolvedDependencies[0].kind, 'dev');
  assert.equal(graph.resolvedDependencies[0].optional, true);
  assert.equal(graph.resolvedDependencies[0].target, 'cfg(windows)');
});

test('core boundary check is split into focused modules', async () => {
  const entrypoint = await readFile(ENTRYPOINT, 'utf8');
  assert.ok(
    entrypoint.split(/\r?\n/).length <= 20,
    'entrypoint should stay a thin wrapper around core-boundaries modules',
  );
  assert.match(entrypoint, /core-boundaries\/checker\.mjs/);

  for (const modulePath of MODULES) {
    await access(new URL(modulePath, import.meta.url));
  }

  const checker = await readFile(new URL('./core-boundaries/checker.mjs', import.meta.url), 'utf8');
  assert.ok(
    checker.split(/\r?\n/).length <= 1200,
    'checker should stay focused on orchestration and shared check helpers',
  );
  assert.match(
    checker,
    /listTrackedRustRepoPaths/,
    'recursive source boundary checks must inspect tracked Rust files only',
  );

  const sourceRuleEntry = await readFile(
    new URL('./core-boundaries/rules/source-rules.mjs', import.meta.url),
    'utf8',
  );
  assert.ok(
    sourceRuleEntry.split(/\r?\n/).length <= 40,
    'source rule entrypoint should delegate to focused source-rule modules',
  );
});

test('core checker runs the unified cargo dependency boundary check', async () => {
  const checker = await readFile(
    new URL('./core-boundaries/checker.mjs', import.meta.url),
    'utf8',
  );

  assert.match(checker, /checkCargoDependencyBoundariesSafely/);
  assert.doesNotMatch(checker, /checkCargoDependencyLayersSafely/);
});

test('product entrypoint feature policy does not pin product-full per manifest', async () => {
  const [checker, featureRules] = await Promise.all([
    readFile(new URL('./core-boundaries/checker.mjs', import.meta.url), 'utf8'),
    readFile(
      new URL('./core-boundaries/rules/feature-rules.mjs', import.meta.url),
      'utf8',
    ),
  ]);

  assert.doesNotMatch(checker, /checkProductCoreFeatureAssembly/);
  assert.doesNotMatch(featureRules, /productCoreFeatureAssemblyRules/);
});

test('Rust build dependency boundary policy stays discoverable', async () => {
  const policyUrl = new URL(
    '../docs/architecture/rust-build-dependency-boundaries.md',
    import.meta.url,
  );
  await assert.doesNotReject(
    () => access(policyUrl),
    'the Rust build dependency boundary policy must exist',
  );
  const [agents, productArchitecture, policy] = await Promise.all([
    readFile(new URL('../AGENTS.md', import.meta.url), 'utf8'),
    readFile(new URL('../docs/architecture/product-architecture.md', import.meta.url), 'utf8'),
    readFile(policyUrl, 'utf8'),
  ]);

  assert.match(agents, /docs\/architecture\/rust-build-dependency-boundaries\.md/);
  assert.match(productArchitecture, /rust-build-dependency-boundaries\.md/);
  assert.match(policy, /Cargo feature/);
  assert.match(policy, /Delivery Profile/);
  assert.match(policy, /Runtime Config/);
  assert.match(policy, /Capability Availability/);
  assert.match(policy, /pnpm run check:core-boundaries:test/);
});

test('transport contract stays limited to current delivery needs', async () => {
  const [workspaceManifest, transportTrait] = await Promise.all([
      readFile(new URL('../Cargo.toml', import.meta.url), 'utf8'),
      readFile(
        new URL('../src/crates/adapters/transport/src/traits.rs', import.meta.url),
        'utf8',
      ),
    ]);

  assert.doesNotMatch(workspaceManifest, /src\/crates\/adapters\/api-layer/);
  assert.doesNotMatch(
    transportTrait,
    /\b(?:emit_text_chunk|emit_tool_event|emit_stream_start|emit_stream_end|adapter_type|TextChunk|ToolEventPayload|ToolEventType|StreamEvent)\b/,
  );
  assert.doesNotMatch(
    transportTrait,
    /emit_event\s*\(\s*&self,\s*session_id:\s*&str/,
  );
});

test('public event projection stays limited to current host needs', async () => {
  const frontendProjection = await readFile(
    new URL(
      '../src/crates/contracts/events/src/frontend_projection.rs',
      import.meta.url,
    ),
    'utf8',
  );

  assert.doesNotMatch(
    frontendProjection,
    /\b(?:into_)?legacy_flat_message\b|\bpub event_type\b/,
  );
});

test('embedded relay concrete lifecycle stays desktop-owned', async () => {
  const [coreManifest, corePort, desktopManifest, desktopHost] = await Promise.all([
    readFile(new URL('../src/crates/assembly/core/Cargo.toml', import.meta.url), 'utf8'),
    readFile(
      new URL(
        '../src/crates/assembly/core/src/service/remote_connect/embedded_relay_host.rs',
        import.meta.url,
      ),
      'utf8',
    ),
    readFile(new URL('../src/apps/desktop/Cargo.toml', import.meta.url), 'utf8'),
    readFile(
      new URL('../src/apps/desktop/src/embedded_relay_host.rs', import.meta.url),
      'utf8',
    ),
  ]);

  assert.doesNotMatch(coreManifest, /openbitfun-relay-service/);
  assert.doesNotMatch(corePort, /\b(?:axum|TcpListener|ServeDir|build_relay_router)\b/);
  assert.match(desktopManifest, /openbitfun-relay-service/);
  assert.match(desktopHost, /impl EmbeddedRelayHost for DesktopEmbeddedRelayHost/);
  assert.match(desktopHost, /TcpListener::bind/);
  assert.match(desktopHost, /ServeDir::new/);
});

test('desktop preview rebuild inputs use the current crate layout', async () => {
  const devScript = await readFile(new URL('./dev.cjs', import.meta.url), 'utf8');

  assert.match(
    devScript,
    /path\.join\(ROOT_DIR, 'src', 'crates'\)/,
  );
  assert.doesNotMatch(
    devScript,
    /'src', 'crates', '(?:core|transport|events|ai-adapters|webdriver|api-layer|assembly|adapters|contracts|execution|interfaces|services)'/,
  );
  assert.match(devScript, /prompts\$\{path\.sep\}/);
});

test('split core boundary check keeps self-test execution behavior', () => {
  const selfTest = spawnSync(
    process.execPath,
    ['scripts/check-core-boundaries.mjs'],
    {
      cwd: new URL('..', import.meta.url),
      env: { ...process.env, OPENBITFUN_BOUNDARY_CHECK_SELF_TEST: '1' },
      encoding: 'utf8',
    },
  );
  assert.equal(selfTest.status, 0, selfTest.stderr || selfTest.stdout);
  assert.match(selfTest.stdout, /Core boundary check self-test passed\./);
});

test('Task execution boundary requires policy-aware child delegation', () => {
  const executionRule = requiredContentRules.find(
    (rule) => rule.path
      === 'src/crates/assembly/core/src/agentic/tools/implementations/task/execution.rs'
      && rule.patterns.some((pattern) => pattern.message.includes('background launches')),
  );
  assert.ok(executionRule, 'Task execution must have a required-content rule');

  const backgroundRule = executionRule.patterns.find(
    (pattern) => pattern.message.includes('background launches'),
  );
  const foregroundRule = executionRule.patterns.find(
    (pattern) => pattern.message.includes('foreground execution'),
  );
  assert.ok(backgroundRule, 'background child delegation must be protected');
  assert.ok(foregroundRule, 'foreground child delegation must be protected');
  assert.match(
    'let delegation_policy = child_delegation_policy(context, coordinator).await?;',
    backgroundRule.regex,
  );
  assert.match(
    'delegation_policy: child_delegation_policy(context, coordinator).await?',
    foregroundRule.regex,
  );
  assert.doesNotMatch(
    'delegation_policy: context.delegation_policy().spawn_child()',
    backgroundRule.regex,
  );
  assert.doesNotMatch(
    'delegation_policy: context.delegation_policy().spawn_child()',
    foregroundRule.regex,
  );
});

test('optional dependency ownership rejects undeclared direct feature owners', async () => {
  const {
    featureReferencesOptionalDependencyOwner,
    unexpectedDependencyOwnerFeatures,
  } = await import(
    './core-boundaries/manifest-feature-helpers.mjs'
  );
  const features = new Map([
    ['declared', { refs: ['dep:example'], line: 1 }],
    ['missing', { refs: ['example'], line: 2 }],
    ['feature-ref', { refs: ['example/subfeature'], line: 3 }],
    ['weak-ref', { refs: ['example?/subfeature'], line: 4 }],
    ['unrelated', { refs: ['other'], line: 5 }],
  ]);

  assert.deepEqual(
    unexpectedDependencyOwnerFeatures(features, {
      depName: 'example',
      ownerFeatures: ['declared'],
    }).map(([featureName]) => featureName),
    ['missing', 'feature-ref', 'weak-ref'],
  );
  assert.equal(featureReferencesOptionalDependencyOwner(features.get('declared'), 'example'), true);
  assert.equal(featureReferencesOptionalDependencyOwner(features.get('weak-ref'), 'example'), true);
  assert.equal(featureReferencesOptionalDependencyOwner(features.get('unrelated'), 'example'), false);
});

test('optional dependency ownership rejects hidden aliases but permits reviewed aggregates', async () => {
  const { unexpectedDependencyOwnerFeatures } = await import(
    './core-boundaries/manifest-feature-helpers.mjs'
  );
  const features = new Map([
    ['owner', { refs: ['dep:example'], line: 1 }],
    ['reviewed-aggregate', { refs: ['owner'], line: 2 }],
    ['sneaky', { refs: ['owner'], line: 3 }],
    ['bad-aggregate', { refs: ['owner', 'dep:example'], line: 4 }],
  ]);

  assert.deepEqual(
    unexpectedDependencyOwnerFeatures(
      features,
      { depName: 'example', ownerFeatures: ['owner'] },
      new Set(['reviewed-aggregate', 'bad-aggregate']),
    ).map(([featureName]) => featureName),
    ['sneaky', 'bad-aggregate'],
  );
});

test('services-core capability profiles keep heavy owners out of the empty profile', async () => {
  const { coreClosedFeatureProfileRules } = await import(
    './core-boundaries/rules/feature-rules.mjs'
  );
  const { dependencyProfileRules } = await import(
    './core-boundaries/rules/crate-rules.mjs'
  );
  const { requiredContentRules } = await import(
    './core-boundaries/rules/source/required-rules.mjs'
  );
  const serviceManifest = 'src/crates/services/services-core/Cargo.toml';
  const profiles = new Map(
    coreClosedFeatureProfileRules
      .filter((rule) => rule.manifestPath === serviceManifest)
      .map((rule) => [rule.featureName, rule.requiredFeatureRefs]),
  );

  assert.deepEqual(profiles.get('filesystem'), [
    'dep:base64',
    'dep:chrono',
    'dep:ignore',
    'dep:openbitfun-core-types',
    'dep:regex',
    'dep:sha2',
    'dep:tokio',
    'tokio/fs',
    'tokio/rt',
    'tokio/sync',
  ]);
  assert.deepEqual(profiles.get('product-identity'), ['dep:openbitfun-core-types']);
  assert.deepEqual(profiles.get('json-io'), [
    'dep:fs2',
    'dep:tokio',
    'dep:windows',
    'tokio/fs',
    'tokio/rt',
    'tokio/sync',
    'tokio/time',
    'windows/Win32_Foundation',
    'windows/Win32_Storage_FileSystem',
  ]);
  assert.deepEqual(profiles.get('local-storage'), [
    'dep:openbitfun-core-types',
    'dep:openbitfun-events',
    'dep:chrono',
    'dep:fs2',
    'dep:libc',
    'dep:regex',
    'dep:sha2',
    'dep:similar',
    'dep:tokio',
    'dep:windows',
    'tokio/fs',
    'tokio/rt',
    'tokio/sync',
    'tokio/time',
    'windows/Win32_Foundation',
    'windows/Win32_Storage_FileSystem',
  ]);
  assert.deepEqual(profiles.get('process-runtime'), [
    'dep:libc',
    'dep:tokio',
    'dep:which',
    'dep:win32job',
    'dep:windows',
    'tokio/io-util',
    'tokio/process',
    'tokio/rt',
    'tokio/time',
    'windows/Win32_Foundation',
    'windows/Win32_System_Diagnostics_ToolHelp',
    'windows/Win32_System_JobObjects',
    'windows/Win32_System_Threading',
  ]);
  assert.deepEqual(profiles.get('workspace-instructions'), [
    'dep:globset',
    'dep:regex',
    'dep:serde_yaml',
    'dep:tokio',
    'tokio/fs',
    'tokio/io-util',
    'tokio/rt',
  ]);
  assert.deepEqual(profiles.get('workspace-runtime'), [
    'dep:anyhow',
    'dep:async-trait',
    'dep:openbitfun-runtime-ports',
    'openbitfun-runtime-ports/runtime-event-port',
    'openbitfun-runtime-ports/workspace-ports',
    'dep:dunce',
    // The concrete local provider restores modification times through WorkspaceFS.
    'dep:filetime',
    'process-runtime',
    'tokio/fs',
    'tokio/io-util',
    'tokio/sync',
  ]);

  const defaultProfile = dependencyProfileRules.find(
    (rule) => rule.crateName === 'services-core',
  );
  for (const dependency of [
    'base64',
    'openbitfun-core-types',
    'openbitfun-events',
    'chrono',
    'fs2',
    'globset',
    'ignore',
    'libc',
    'regex',
    'sha2',
    'similar',
    'which',
    'win32job',
    'windows',
  ]) {
    assert.ok(
      defaultProfile?.forbiddenNonOptionalDeps.includes(dependency),
      `services-core empty profile must reject ambient ${dependency}`,
    );
  }

  const sourceRule = requiredContentRules.find(
    (rule) => rule.path === 'src/crates/services/services-core/src/lib.rs',
  );
  const sourceContracts = sourceRule?.patterns.map((pattern) => pattern.regex.source).join('\n') ?? '';
  for (const moduleName of [
    'diagnostics',
    'diff',
    'filesystem',
    'json_store',
    'managed_runtime',
    'persistence',
    'process_manager',
    'process_tree',
    'session',
    'session_usage',
    'storage_cleanup',
    'system',
    'token_usage',
    'workspace_instructions',
    'workspace_intelligence_cognition',
    'workspace_intelligence_store',
  ]) {
    assert.match(
      sourceContracts,
      new RegExp(`pub mod ${moduleName}`),
      `services-core source rule must protect the ${moduleName} capability gate`,
    );
  }
});

test('services-core Tokio capabilities stay owner-scoped', () => {
  const invalidPackage = {
    name: 'openbitfun-services-core',
    manifest_path: 'src/crates/services/services-core/Cargo.toml',
    dependencies: [
      {
        name: 'tokio',
        kind: null,
        optional: false,
        features: ['fs', 'io-util', 'process', 'rt', 'sync', 'time'],
      },
    ],
    features: {
      filesystem: [],
      'json-io': [],
      'local-storage': [],
      'process-runtime': [],
      'workspace-instructions': [],
      'workspace-runtime': [],
    },
  };

  const messages = findTokioDependencyFeatureViolations([invalidPackage]).map(
    (violation) => violation.message,
  );
  assert.ok(
    messages.some((message) => message.includes('unexpected base Tokio capabilities')),
    'services-core must reject ambient fs/io/process/sync Tokio capabilities',
  );
  assert.ok(
    messages.some((message) => message.includes('filesystem missing effective Tokio capabilities: fs')),
    'services-core must require filesystem to own tokio/fs',
  );
});

test('Services Core accepts only the reviewed feature-owned Tokio runtime graph', () => {
  const validPackage = {
    name: 'openbitfun-services-core',
    manifest_path: 'src/crates/services/services-core/Cargo.toml',
    dependencies: [
      {
        name: 'tokio',
        kind: null,
        optional: true,
        features: [],
      },
    ],
    features: {
      'credential-vault': ['dep:tokio', 'tokio/fs', 'tokio/io-util', 'tokio/rt'],
      diff: ['dep:tokio', 'tokio/rt', 'tokio/time'],
      filesystem: ['dep:tokio', 'tokio/fs', 'tokio/rt', 'tokio/sync'],
      'json-io': ['dep:tokio', 'tokio/fs', 'tokio/rt', 'tokio/sync', 'tokio/time'],
      'routing-state': ['json-io'],
      'resource-capacity': ['json-io'],
      'workspace-intelligence-store': ['json-io', 'dep:sha2'],
      'workspace-intelligence-cognition': ['dep:rusqlite', 'dep:sha2'],
      'workspace-intelligence-commit': ['workspace-intelligence-store', 'workspace-intelligence-cognition'],
      'exclusive-file-lease': ['dep:fs2'],
      'workspace-intelligence-claim': ['workspace-intelligence-commit', 'exclusive-file-lease', 'dep:uuid'],
      'workspace-intelligence-host-anchor': ['json-io', 'dep:uuid', 'dep:libc'],
      'local-storage': [
        'dep:tokio',
        'tokio/fs',
        'tokio/rt',
        'tokio/sync',
        'tokio/time',
      ],
      'session-recovery': ['local-storage', 'workspace-persistence', 'dep:anyhow'],
      permission: ['dep:tokio', 'tokio/rt'],
      'session-search': ['dep:tokio', 'tokio/rt'],
      'process-runtime': [
        'dep:tokio',
        'tokio/io-util',
        'tokio/process',
        'tokio/rt',
        'tokio/time',
      ],
      'workspace-instructions': ['dep:tokio', 'tokio/fs', 'tokio/io-util', 'tokio/rt'],
      'workspace-text-runtime': ['dep:tokio', 'tokio/rt'],
      'workspace-runtime': [
        'process-runtime',
        'tokio/fs',
        'tokio/io-util',
        'tokio/sync',
      ],
      'session-git': ['local-storage'],
      'workspace-transfer': ['dep:tokio', 'tokio/fs', 'tokio/io-util', 'tokio/rt', 'tokio/sync'],
    },
  };

  assert.deepEqual(findTokioDependencyFeatureViolations([validPackage]), []);
});

test('Services Core Tokio owners cannot be hidden behind an unreviewed alias', () => {
  const invalidPackage = {
    name: 'openbitfun-services-core',
    manifest_path: 'src/crates/services/services-core/Cargo.toml',
    dependencies: [
      {
        name: 'tokio',
        kind: null,
        optional: true,
        features: [],
      },
    ],
    features: {
      diff: ['dep:tokio', 'tokio/rt', 'tokio/time'],
      filesystem: ['dep:tokio', 'tokio/fs', 'tokio/rt', 'tokio/sync'],
      'json-io': ['dep:tokio', 'tokio/fs', 'tokio/rt', 'tokio/sync', 'tokio/time'],
      'local-storage': [
        'dep:tokio',
        'tokio/fs',
        'tokio/rt',
        'tokio/sync',
        'tokio/time',
      ],
      permission: ['dep:tokio', 'tokio/rt'],
      'process-runtime': [
        'dep:tokio',
        'tokio/io-util',
        'tokio/process',
        'tokio/rt',
        'tokio/time',
      ],
      'workspace-instructions': ['dep:tokio', 'tokio/fs', 'tokio/io-util', 'tokio/rt'],
      'workspace-text-runtime': ['dep:tokio', 'tokio/rt'],
      'workspace-runtime': [
        'process-runtime',
        'tokio/fs',
        'tokio/io-util',
        'tokio/sync',
      ],
      sneaky: ['filesystem', 'local-storage'],
      'sneaky-weak': ['tokio?/full'],
    },
  };

  const messages = findTokioDependencyFeatureViolations([invalidPackage]).map(
    (violation) => violation.message,
  );
  assert.ok(
    messages.includes('openbitfun-services-core:sneaky Tokio capabilities require an explicit owner contract'),
  );
  assert.ok(
    messages.includes('openbitfun-services-core:sneaky-weak Tokio capabilities require an explicit owner contract'),
  );
});

test('workspace intelligence commit pins only two owners and rejects direct Tokio widening', async () => {
  const manifestPath = 'src/crates/services/services-core/Cargo.toml';
  const manifest = await readFile(new URL(`../${manifestPath}`, import.meta.url), 'utf8');
  const features = parseManifestFeatures(manifest);
  const references = ['workspace-intelligence-store', 'workspace-intelligence-cognition'];
  const rule = coreClosedFeatureProfileRules.find((candidate) =>
    candidate.manifestPath === manifestPath && candidate.featureName === 'workspace-intelligence-commit');
  assert.equal(rule?.exact, true);
  assert.deepEqual(rule.requiredFeatureRefs, references);
  assert.deepEqual(rule.allowedTransitiveFeatureRefs, ['json-io']);
  assert.deepEqual(features['workspace-intelligence-commit'], references);
  assert.deepEqual(features.default, []);
  assert.match(rule.reason, /only the two store owners/);
  const { unexpectedDependencyOwnerFeatures } = await import(
    './core-boundaries/manifest-feature-helpers.mjs'
  );
  const tokioOwner = optionalDependencyFeatureOwnerRules
    .find((candidate) => candidate.crateName === 'services-core')
    .dependencies.find((dependency) => dependency.depName === 'tokio');
  // Exercise the actual owner checker too: redundant direct capabilities must
  // be rejected even when they do not change the effective Tokio union.
  for (const forbidden of ['dep:tokio', 'tokio/rt']) {
    const widened = [...references, forbidden];
    const unexpected = widened.filter((reference) => !rule.requiredFeatureRefs.includes(reference));
    assert.deepEqual(unexpected, [forbidden]);
    assert.deepEqual(unexpectedDependencyOwnerFeatures(new Map([
      ['workspace-intelligence-commit', { refs: widened, line: 1 }],
    ]), tokioOwner).map(([featureName]) => featureName), ['workspace-intelligence-commit']);
  }
  const sourceRule = requiredContentRules.find((candidate) =>
    candidate.path === 'src/crates/services/services-core/src/lib.rs');
  assert.ok(sourceRule.patterns.some((pattern) => pattern.regex.test(
    '#[cfg(feature = "workspace-intelligence-commit")]\npub mod workspace_intelligence_commit;',
  )));
});

test('workspace intelligence commit inherits exactly the effective JSON IO Tokio contract', () => {
  const messages = (refs) => findTokioDependencyFeatureViolations([{
    name: 'openbitfun-services-core',
    manifest_path: 'src/crates/services/services-core/Cargo.toml',
    dependencies: [{ name: 'tokio', kind: null, optional: true, features: [] }],
    features: {
      'json-io': ['dep:tokio', 'tokio/fs', 'tokio/rt', 'tokio/sync', 'tokio/time'],
      'workspace-intelligence-store': ['json-io', 'dep:sha2'],
      'workspace-intelligence-cognition': ['dep:rusqlite', 'dep:sha2'],
      'workspace-intelligence-commit': refs,
    },
  }]).map((violation) => violation.message)
    .filter((message) => message.includes(':workspace-intelligence-commit '));
  const refs = ['workspace-intelligence-store', 'workspace-intelligence-cognition'];
  assert.deepEqual(messages(refs), []);
  assert.match(messages([...refs, 'tokio/process']).join('\n'), /unexpected effective Tokio capabilities: process/);
  assert.match(messages(['workspace-intelligence-cognition']).join('\n'), /missing effective Tokio capabilities: fs, rt, sync, time/);
});

test('workspace intelligence store admits only the reviewed JSON IO Tokio closure', () => {
  const servicesCorePackage = (storeReferences) => ({
    name: 'openbitfun-services-core',
    manifest_path: 'src/crates/services/services-core/Cargo.toml',
    dependencies: [{ name: 'tokio', kind: null, optional: true, features: [] }],
    features: {
      'json-io': ['dep:tokio', 'tokio/fs', 'tokio/rt', 'tokio/sync', 'tokio/time'],
      'workspace-transfer': ['dep:tokio', 'tokio/fs', 'tokio/io-util', 'tokio/rt', 'tokio/sync'],
      'workspace-intelligence-store': storeReferences,
    },
  });
  const storeMessages = (storeReferences) => findTokioDependencyFeatureViolations(
    [servicesCorePackage(storeReferences)],
  ).map((violation) => violation.message)
    .filter((message) => message.includes(':workspace-intelligence-store '));

  assert.deepEqual(storeMessages(['json-io', 'dep:sha2']), []);
  for (const [reference, capability] of [
    ['tokio/process', 'process'],
    ['tokio/net', 'net'],
    ['workspace-transfer', 'io-util'],
  ]) {
    assert.ok(
      storeMessages(['json-io', 'dep:sha2', reference]).includes(
        'openbitfun-services-core:workspace-intelligence-store has unexpected effective '
        + `Tokio capabilities: ${capability}`,
      ),
      `workspace-intelligence-store must reject ${reference} widening`,
    );
  }
});

test('workspace intelligence store stays out of the empty default and product-full assembly', async () => {
  const manifestPath = 'src/crates/services/services-core/Cargo.toml';
  const manifest = await readFile(new URL(`../${manifestPath}`, import.meta.url), 'utf8');
  const features = parseManifestFeatures(manifest);
  const expectedReferences = ['json-io', 'dep:sha2'];

  // The owner definition is exact: generic atomic JSON IO plus content hashing,
  // with no product policy, runtime, process, or network capability.
  assert.deepEqual(features['workspace-intelligence-store'], expectedReferences);
  assert.ok(!features.default.includes('workspace-intelligence-store'));

  const rule = coreClosedFeatureProfileRules.find(
    (candidate) => candidate.manifestPath === manifestPath
      && candidate.featureName === 'workspace-intelligence-store',
  );
  assert.equal(rule?.exact, true);
  assert.deepEqual(rule.requiredFeatureRefs, expectedReferences);
  assert.match(rule.reason, /product policy/);

  const sha2Owner = optionalDependencyFeatureOwnerRules
    .find((candidate) => candidate.crateName === 'services-core')
    .dependencies.find((dependency) => dependency.depName === 'sha2');
  assert.ok(sha2Owner.ownerFeatures.includes('workspace-intelligence-store'));

  // P1 design boundary on the real manifests: the internal store is not part of
  // the empty profile or of the shipped product assembly. A future narrow host
  // consumer may select it in its own manifest without changing this contract.
  const coreManifest = await readFile(
    new URL('../src/crates/assembly/core/Cargo.toml', import.meta.url),
    'utf8',
  );
  assert.deepEqual(
    parseManifestFeatures(coreManifest)['product-full'].filter((reference) =>
      reference.includes('workspace-intelligence-store')),
    [],
  );
});

// P1 core control slice: WP1.1 core assembly + WP1.2a control-vs-control.
// The control slice stays internal to the crate: it selects only the store
// owner and enters no empty default, product-full, or agent-runtime assembly.
test('workspace intelligence control slice stays internal and selects only the store owner', async () => {
  const coreManifestPath = 'src/crates/assembly/core/Cargo.toml';
  const coreManifest = await readFile(new URL(`../${coreManifestPath}`, import.meta.url), 'utf8');
  const features = parseManifestFeatures(coreManifest);
  const expectedReferences = ['openbitfun-services-core/workspace-intelligence-store'];
  assert.deepEqual(features['workspace-intelligence-control'], expectedReferences);
  assert.ok(!features.default.includes('workspace-intelligence-control'));
  assert.deepEqual(
    features['product-full'].filter((reference) => reference.includes('workspace-intelligence-control')),
    [],
  );
  assert.deepEqual(
    features['agent-runtime'].filter((reference) => reference.includes('workspace-intelligence-control')),
    [],
  );
  const rule = coreClosedFeatureProfileRules.find(
    (candidate) => candidate.manifestPath === coreManifestPath
      && candidate.featureName === 'workspace-intelligence-control',
  );
  assert.equal(rule?.exact, true);
  assert.deepEqual(rule.requiredFeatureRefs, expectedReferences);
});

// P1 cognition partition root: WP1.3 cognition partition store + core selection.
// The cognition slice stays internal: its services owner is the bundled SQLite
// store plus content hashing, its core slice selects only that owner, and neither
// enters the empty default, product-full, or agent-runtime assembly.
test('workspace intelligence cognition selects only the partition store owner', async () => {
  const servicesManifestPath = 'src/crates/services/services-core/Cargo.toml';
  const servicesManifest = await readFile(
    new URL(`../${servicesManifestPath}`, import.meta.url),
    'utf8',
  );
  const servicesFeatures = parseManifestFeatures(servicesManifest);
  const servicesReferences = ['dep:rusqlite', 'dep:sha2'];

  // No second control generation: the partition state shares the existing
  // bundled SQLite owner and content hashing and adds no other capability.
  assert.deepEqual(servicesFeatures['workspace-intelligence-cognition'], servicesReferences);
  assert.ok(!servicesFeatures.default.includes('workspace-intelligence-cognition'));

  const servicesRule = coreClosedFeatureProfileRules.find(
    (candidate) => candidate.manifestPath === servicesManifestPath
      && candidate.featureName === 'workspace-intelligence-cognition',
  );
  assert.equal(servicesRule?.exact, true);
  assert.deepEqual(servicesRule.requiredFeatureRefs, servicesReferences);
  assert.match(servicesRule.reason, /without a second control generation/);

  const coreManifestPath = 'src/crates/assembly/core/Cargo.toml';
  const coreManifest = await readFile(new URL(`../${coreManifestPath}`, import.meta.url), 'utf8');
  const coreFeatures = parseManifestFeatures(coreManifest);
  const coreReferences = ['openbitfun-services-core/workspace-intelligence-cognition'];

  assert.deepEqual(coreFeatures['workspace-intelligence-cognition'], coreReferences);
  assert.ok(!coreFeatures.default.includes('workspace-intelligence-cognition'));
  for (const assembly of ['product-full', 'agent-runtime']) {
    assert.deepEqual(
      coreFeatures[assembly].filter((reference) =>
        reference.includes('workspace-intelligence-cognition')),
      [],
      `openbitfun-core ${assembly} must not assemble the internal cognition slice`,
    );
  }

  const coreRule = coreClosedFeatureProfileRules.find(
    (candidate) => candidate.manifestPath === coreManifestPath
      && candidate.featureName === 'workspace-intelligence-cognition',
  );
  assert.equal(coreRule?.exact, true);
  assert.deepEqual(coreRule.requiredFeatureRefs, coreReferences);

  const servicesOwners = optionalDependencyFeatureOwnerRules.find(
    (candidate) => candidate.crateName === 'services-core',
  );
  for (const depName of ['rusqlite', 'sha2']) {
    const depOwner = servicesOwners.dependencies.find(
      (dependency) => dependency.depName === depName,
    );
    assert.ok(
      depOwner.ownerFeatures.includes('workspace-intelligence-cognition'),
      `services-core ${depName} must stay owned by workspace-intelligence-cognition`,
    );
  }

  // The core partition module must stay behind the cognition feature gate.
  // A feature-free `scope` module is shared by both slices and is not gated.
  const corePartitionRule = requiredContentRules.find(
    (rule) => rule.path === 'src/crates/assembly/core/src/service/workspace_intelligence/mod.rs',
  );
  assert.ok(
    corePartitionRule?.patterns.some((pattern) => pattern.regex.test(
      '#[cfg(feature = "workspace-intelligence-cognition")]\npub(crate) mod partition;',
    )),
    'core workspace intelligence source rule must require the cognition partition gate',
  );
});

test('workspace intelligence core commit selects only the governed fence owner', async () => {
  const manifestPath = 'src/crates/assembly/core/Cargo.toml';
  const manifest = await readFile(new URL(`../${manifestPath}`, import.meta.url), 'utf8');
  const features = parseManifestFeatures(manifest);
  const expectedReferences = ['openbitfun-services-core/workspace-intelligence-commit'];
  assert.deepEqual(features['workspace-intelligence-commit'], expectedReferences);
  for (const assembly of ['default', 'product-full', 'agent-runtime']) {
    assert.deepEqual(
      features[assembly].filter((reference) => reference.includes('workspace-intelligence-commit')),
      [],
      `${assembly} must not assemble the internal commit wrapper`,
    );
  }
  for (const oldFeature of ['workspace-intelligence-control', 'workspace-intelligence-cognition']) {
    assert.ok(!features['workspace-intelligence-commit'].includes(oldFeature));
  }
  const rule = coreClosedFeatureProfileRules.find(
    (candidate) => candidate.manifestPath === manifestPath
      && candidate.featureName === 'workspace-intelligence-commit',
  );
  assert.equal(rule?.exact, true);
  assert.deepEqual(rule.requiredFeatureRefs, expectedReferences);

  const modulePath = 'src/crates/assembly/core/src/service/workspace_intelligence/mod.rs';
  const source = await readFile(new URL(`../${modulePath}`, import.meta.url), 'utf8');
  const gate = /#\[cfg\(feature = "workspace-intelligence-commit"\)\]\s*pub\(crate\) mod commit;/;
  assert.match(source, gate);
  const sourceRule = requiredContentRules.find((candidate) => candidate.path === modulePath);
  assert.ok(sourceRule?.patterns.some((pattern) => pattern.regex.test(
    '#[cfg(feature = "workspace-intelligence-commit")]\npub(crate) mod commit;',
  )));
});

test('workspace intelligence core claim selects only the services claim owner', async () => {
  const manifestPath = 'src/crates/assembly/core/Cargo.toml';
  const manifest = await readFile(new URL(`../${manifestPath}`, import.meta.url), 'utf8');
  const features = parseManifestFeatures(manifest);
  const expectedReferences = ['openbitfun-services-core/workspace-intelligence-claim'];
  assert.deepEqual(features['workspace-intelligence-claim'], expectedReferences);
  for (const assembly of ['default', 'product-full', 'agent-runtime']) {
    assert.ok(!features[assembly].includes('workspace-intelligence-claim'));
  }
  for (const slice of ['control', 'cognition', 'commit']) {
    assert.ok(!features['workspace-intelligence-claim'].includes(`workspace-intelligence-${slice}`));
  }
  const rule = coreClosedFeatureProfileRules.find(
    (candidate) => candidate.manifestPath === manifestPath
      && candidate.featureName === 'workspace-intelligence-claim',
  );
  assert.equal(rule?.exact, true);
  assert.deepEqual(rule.requiredFeatureRefs, expectedReferences);
  const modulePath = 'src/crates/assembly/core/src/service/workspace_intelligence/mod.rs';
  const source = await readFile(new URL(`../${modulePath}`, import.meta.url), 'utf8');
  assert.match(source, /#\[cfg\(feature = "workspace-intelligence-claim"\)\]\s*pub\(crate\) mod claim;/);
  const sourceRule = requiredContentRules.find((candidate) => candidate.path === modulePath);
  assert.ok(sourceRule?.patterns.some((pattern) => pattern.regex.test(
    '#[cfg(feature = "workspace-intelligence-claim")]\npub(crate) mod claim;',
  )));
});

test('workspace intelligence host selects only the narrow host owner set', async () => {
  const manifestPath = 'src/crates/assembly/core/Cargo.toml';
  const manifest = await readFile(new URL(`../${manifestPath}`, import.meta.url), 'utf8');
  const features = parseManifestFeatures(manifest);
  const expectedReferences = [
    'workspace-intelligence-control',
    'workspace-intelligence-cognition',
    'workspace-intelligence-commit',
    'workspace-intelligence-claim',
    'openbitfun-services-core/workspace-intelligence-host-anchor',
    'openbitfun-services-core/workspace-persistence',
    'openbitfun-services-core/local-storage',
    'openbitfun-services-core/runtime-ownership',
    'tokio/macros',
    'tokio/rt',
    'tokio/sync',
    'tokio/time',
  ];
  assert.deepEqual(features['workspace-intelligence-host'], expectedReferences);
  for (const assembly of ['default', 'product-full', 'agent-runtime']) {
    assert.ok(
      !features[assembly].includes('workspace-intelligence-host'),
      `${assembly} must not assemble the internal host slice`,
    );
  }
  // The host compiles the persisted registry and the owners it fences claims
  // with; it must never compile a workspace runtime, an agent tool contract, a
  // process runtime or a second control write path.
  for (const forbidden of [
    'workspace-runtime',
    'local-storage',
    'process-runtime',
    'dep:openbitfun-agent-tools',
    'dep:serde_yaml',
  ]) {
    assert.ok(
      !features['workspace-intelligence-host'].includes(forbidden),
      `workspace-intelligence-host must not select ${forbidden}`,
    );
  }
  const rule = coreClosedFeatureProfileRules.find(
    (candidate) => candidate.manifestPath === manifestPath
      && candidate.featureName === 'workspace-intelligence-host',
  );
  assert.equal(rule?.exact, true);
  assert.deepEqual(rule.requiredFeatureRefs, expectedReferences);

  // The reviewed Tokio contract is exactly `macros`, `rt`, `sync` and `time`: the
  // host drives owner futures with a bounded drain and fallback backoff, names
  // `watch` and `Mutex` directly, and performs no IO, network or process work
  // itself.
  const hostMessages = (references) => findTokioDependencyFeatureViolations([{
    name: 'openbitfun-core',
    manifest_path: manifestPath,
    dependencies: [],
    features: { 'workspace-intelligence-host': references },
  }]).map((violation) => violation.message)
    .filter((message) => message.includes(':workspace-intelligence-host '));
  const hostTokio = ['tokio/macros', 'tokio/rt', 'tokio/sync', 'tokio/time'];
  assert.deepEqual(hostMessages(hostTokio), []);
  for (const widened of ['tokio/process', 'tokio/net', 'tokio/fs', 'tokio/io-util', 'tokio/rt-multi-thread']) {
    const messages = hostMessages([...hostTokio, widened]);
    assert.ok(
      messages.length > 0 && messages.every((message) => message.includes('Tokio')),
      `workspace-intelligence-host must reject widening with ${widened}`,
    );
  }

  const modulePath = 'src/crates/assembly/core/src/service/workspace_intelligence/mod.rs';
  const source = await readFile(new URL(`../${modulePath}`, import.meta.url), 'utf8');
  for (const name of ['catalog_readonly', 'host_binding', 'host_standby']) {
    assert.match(
      source,
      new RegExp(`#\\[cfg\\(feature = "workspace-intelligence-host"\\)\\]\\s*pub\\(crate\\) mod ${name};`),
    );
  }
  // The host module itself stays unconditional so a feature-off build answers
  // `NotCompiled` rather than failing to build or silently reporting success.
  assert.match(source, /^pub\(crate\) mod host;$/m);
  const sourceRule = requiredContentRules.find((candidate) => candidate.path === modulePath);
  for (const name of ['catalog_readonly', 'host_binding', 'host_standby']) {
    assert.ok(sourceRule?.patterns.some((pattern) => pattern.regex.test(
      `#[cfg(feature = "workspace-intelligence-host")]\npub(crate) mod ${name};`,
    )), `core workspace intelligence source rule must require the ${name} host gate`);
  }
  assert.ok(sourceRule?.patterns.some((pattern) => pattern.regex.test('pub(crate) mod host;\n')));

  // The gate itself is pinned: a cfg in front of `mod host;` is a violation.
  const gatedHostRule = forbiddenContentRules.find(
    (candidate) => candidate.path === modulePath,
  );
  const gatedPattern = gatedHostRule?.patterns.find((pattern) => pattern.wholeFile);
  assert.ok(gatedPattern, 'the workspace intelligence module must forbid gating `mod host`');
  assert.equal(
    findForbiddenContentMatches(
      '#[cfg(feature = "workspace-intelligence-host")]\npub(crate) mod host;\n',
      [gatedPattern],
      modulePath,
    ).length,
    1,
  );
  assert.equal(findForbiddenContentMatches(source, [gatedPattern], modulePath).length, 0);

  // The host slice must never reach the core workspace runtime owner: that
  // import is what turned the host into a workspace-runtime consumer.
  for (const file of ['host.rs', 'catalog_readonly.rs', 'host_binding.rs', 'host_standby.rs']) {
    const filePath = `src/crates/assembly/core/src/service/workspace_intelligence/${file}`;
    const runtimeRule = forbiddenContentRules.find((candidate) => candidate.path === filePath);
    assert.ok(runtimeRule, `${file} must forbid reaching the workspace runtime owner`);
    assert.equal(
      findForbiddenContentMatches('use crate::service::workspace::WorkspaceService;\n', runtimeRule.patterns, filePath).length,
      1,
    );
    const fileSource = await readFile(new URL(`../${filePath}`, import.meta.url), 'utf8');
    assert.equal(
      findForbiddenContentMatches(fileSource, runtimeRule.patterns, filePath).length,
      0,
      `${file} must not name the workspace runtime owner`,
    );
  }
});

const WORKSPACE_INTELLIGENCE_HOST_APP_FORWARD = 'openbitfun-core/workspace-intelligence-host';

// Both apps are read from Cargo's own metadata for the two manifests that declare
// the host forward. `--no-deps` still reports every workspace member, so this is
// the real feature graph without paying for a full dependency resolution.
function workspaceIntelligenceHostAppPackages() {
  const root = fileURLToPath(new URL('..', import.meta.url));
  return {
    root,
    packages: collectCargoMetadataPackages({
      root,
      manifestPaths: [
        join(root, 'src', 'apps', 'desktop', 'Cargo.toml'),
        join(root, 'src', 'apps', 'server', 'Cargo.toml'),
      ],
    }),
  };
}

test('Desktop and Server forward only the reviewed workspace intelligence host owner', () => {
  const { root, packages } = workspaceIntelligenceHostAppPackages();

  // The reviewed declaration is asserted as data first: a metadata set that lost
  // an app, its forward or its default must fail here instead of passing on an
  // empty package list.
  for (const [name, manifestPath, expectedFeatures] of [
    [
      'openbitfun-desktop',
      'src/apps/desktop/Cargo.toml',
      ['default', 'devtools', 'workspace-intelligence-host'],
    ],
    [
      'openbitfun-server',
      'src/apps/server/Cargo.toml',
      ['default', 'workspace-intelligence-host'],
    ],
  ]) {
    const appPackage = packages.find((pkg) => pkg.name === name);
    assert.ok(appPackage, `${name} must be a Cargo metadata package`);
    assert.equal(appPackage.manifest_path, join(root, ...manifestPath.split('/')));
    assert.deepEqual(
      Object.keys(appPackage.features).sort(),
      expectedFeatures,
      `${name} feature surface`,
    );
    assert.deepEqual(
      appPackage.features['workspace-intelligence-host'],
      [WORKSPACE_INTELLIGENCE_HOST_APP_FORWARD],
    );
    assert.deepEqual(appPackage.features.default, ['workspace-intelligence-host']);
    // The host forward is one extra owner on top of the full product closure; the
    // normal Core edge itself keeps exactly `product-full`.
    const coreEdges = appPackage.dependencies.filter(
      (dependency) => dependency.name === 'openbitfun-core' && (dependency.kind ?? null) === null,
    );
    assert.equal(coreEdges.length, 1, `${name} must keep one normal openbitfun-core edge`);
    assert.deepEqual(coreEdges[0].features, ['product-full']);
  }

  assert.deepEqual(
    findAppWorkspaceIntelligenceHostFeatureViolations(packages, { root }),
    [],
  );

  // The guarded apps are not narrow product entrypoints: the full transitive Core
  // closure must keep treating their `product-full` edge as correct instead of
  // re-reviewing the whole product closure as if it were a CLI-like entrypoint.
  assert.deepEqual(
    findProductEntrypointCoreFeatureViolations(packages, { root, crateLayoutRules })
      .filter((violation) => violation.message.includes('openbitfun-desktop')
        || violation.message.includes('openbitfun-server')),
    [],
  );

  // A metadata set without the apps cannot pass: the guard reports the missing
  // review surface rather than skipping it.
  assert.deepEqual(
    findAppWorkspaceIntelligenceHostFeatureViolations([], { root })
      .map((violation) => violation.message),
    [
      'Desktop app must stay in Cargo metadata so its workspace-intelligence-host forward stays reviewable',
      'Server app must stay in Cargo metadata so its workspace-intelligence-host forward stays reviewable',
    ],
  );
});

test('workspace intelligence host app forwards reject drift the entrypoint closure cannot see', () => {
  const { root, packages } = workspaceIntelligenceHostAppPackages();
  const desktop = packages.find((pkg) => pkg.name === 'openbitfun-desktop');
  const server = packages.find((pkg) => pkg.name === 'openbitfun-server');
  assert.ok(desktop && server, 'both guarded apps must come from Cargo metadata');

  const withoutFeature = (pkg, featureName) => {
    const features = { ...pkg.features };
    delete features[featureName];
    return features;
  };
  const replaceAppFeatures = (pkg, features) => packages.map((candidate) =>
    (candidate === pkg ? { ...candidate, features } : candidate));

  const cases = [
    [
      'Desktop',
      desktop,
      withoutFeature(desktop, 'workspace-intelligence-host'),
      /^Desktop app must declare the workspace-intelligence-host feature that forwards openbitfun-core\/workspace-intelligence-host$/,
    ],
    [
      'Desktop',
      desktop,
      withoutFeature(desktop, 'default'),
      /^Desktop app default feature must keep workspace-intelligence-host$/,
    ],
    [
      'Server',
      server,
      { ...server.features, default: [] },
      /^Server app default feature must stay exactly \[workspace-intelligence-host\], not \[\]$/,
    ],
    [
      'Desktop',
      desktop,
      { ...desktop.features, default: ['workspace-intelligence-host', 'devtools'] },
      /^Desktop app default feature must stay exactly \[workspace-intelligence-host\], not \[workspace-intelligence-host, devtools\]$/,
    ],
    [
      'Desktop',
      desktop,
      { ...desktop.features, 'workspace-intelligence-host': ['openbitfun-services-core/workspace-intelligence-host'] },
      /^Desktop app workspace-intelligence-host feature must forward exactly openbitfun-core\/workspace-intelligence-host, not \[openbitfun-services-core\/workspace-intelligence-host\]$/,
    ],
    [
      'Server',
      server,
      { ...server.features, 'workspace-intelligence-host': ['openbitfun-core/workspace-intelligence-claim'] },
      /^Server app workspace-intelligence-host feature must forward exactly openbitfun-core\/workspace-intelligence-host, not \[openbitfun-core\/workspace-intelligence-claim\]$/,
    ],
    [
      'Desktop',
      desktop,
      {
        ...desktop.features,
        'workspace-intelligence-host': [
          WORKSPACE_INTELLIGENCE_HOST_APP_FORWARD,
          'openbitfun-core/test-support',
        ],
      },
      /feature must forward exactly openbitfun-core\/workspace-intelligence-host, not \[openbitfun-core\/workspace-intelligence-host, openbitfun-core\/test-support\]$/,
    ],
    [
      'Server',
      server,
      {
        ...server.features,
        'workspace-intelligence-host': [
          WORKSPACE_INTELLIGENCE_HOST_APP_FORWARD,
          'openbitfun-core/workspace-intelligence-control',
        ],
      },
      /feature must forward exactly openbitfun-core\/workspace-intelligence-host, not \[openbitfun-core\/workspace-intelligence-host, openbitfun-core\/workspace-intelligence-control\]$/,
    ],
  ];

  for (const [label, appPackage, features, expected] of cases) {
    const mutated = replaceAppFeatures(appPackage, features);
    const messages = findAppWorkspaceIntelligenceHostFeatureViolations(mutated, { root })
      .map((violation) => violation.message);
    assert.equal(messages.length, 1, `${label} case ${expected} must report once: ${messages.join(' | ')}`);
    assert.match(messages[0], expected);

    // The reviewed entrypoint contract only pins the direct Core capability edge,
    // so it reports nothing about an app-level forward: this is the gap the app
    // guard closes, proven on the same metadata the positive case accepts.
    assert.deepEqual(
      findProductEntrypointCoreFeatureViolations(mutated, { root, crateLayoutRules })
        .map((violation) => violation.message)
        .filter((message) => message.includes('workspace-intelligence-host')),
      [],
    );
  }

  // The same metadata without a mutation stays clean, so every report above comes
  // from the injected drift rather than from the real declaration.
  assert.deepEqual(
    findAppWorkspaceIntelligenceHostFeatureViolations(packages, { root }),
    [],
  );
});

test('workspace intelligence cognition cannot acquire Tokio capabilities', () => {
  const cognitionMessages = (references) => findTokioDependencyFeatureViolations([{
    name: 'openbitfun-services-core',
    manifest_path: 'src/crates/services/services-core/Cargo.toml',
    dependencies: [],
    features: { 'workspace-intelligence-cognition': references },
  }]).map((violation) => violation.message)
    .filter((message) => message.includes(':workspace-intelligence-cognition '));

  // The reviewed owner contract is SQLite plus content hashing only, so it
  // holds no Tokio capability a future consumer could inherit.
  assert.deepEqual(cognitionMessages(['dep:rusqlite', 'dep:sha2']), []);
  const widened = cognitionMessages(['dep:rusqlite', 'dep:sha2', 'tokio/process']);
  assert.ok(
    widened.length > 0 && widened.every((message) => message.includes('Tokio')),
    'workspace-intelligence-cognition must reject tokio/process widening',
  );
});

test('Core feature-free Tokio capabilities stay limited to baseline path and state IO', () => {
  const invalidPackage = {
    name: 'openbitfun-core',
    manifest_path: 'src/crates/assembly/core/Cargo.toml',
    dependencies: [
      {
        name: 'tokio',
        kind: null,
        optional: false,
        features: ['fs', 'io-util', 'macros', 'net', 'rt', 'sync', 'time'],
      },
    ],
    features: {},
  };

  const messages = findTokioDependencyFeatureViolations([invalidPackage]).map(
    (violation) => violation.message,
  );
  assert.ok(
    messages.some((message) => message.includes('unexpected base Tokio capabilities')),
    'Core must reject async runtime, networking, and timing capabilities in its feature-free profile',
  );
});

test('Core Tokio capabilities cannot hide behind an unreviewed owner feature', () => {
  const invalidPackage = {
    name: 'openbitfun-core',
    manifest_path: 'src/crates/assembly/core/Cargo.toml',
    dependencies: [
      {
        name: 'tokio',
        kind: null,
        optional: false,
        features: ['fs', 'sync'],
      },
    ],
    features: {
      'agent-runtime': ['tokio/io-util', 'tokio/macros', 'tokio/rt', 'tokio/time'],
      'legacy-migration': [],
      'mcp-runtime': ['agent-runtime', 'tokio/rt-multi-thread'],
      'browser-control': ['tokio/net', 'tokio/rt', 'tokio/time'],
      'workspace-intelligence-host': ['tokio/macros', 'tokio/rt', 'tokio/sync', 'tokio/time'],
      sneaky: ['agent-runtime', 'browser-control'],
    },
  };

  const messages = findTokioDependencyFeatureViolations([invalidPackage]).map(
    (violation) => violation.message,
  );
  assert.deepEqual(messages, [
    'openbitfun-core:sneaky Tokio capabilities require an explicit owner contract',
  ]);
});

test('reviewed Tokio aggregates cannot declare runtime capabilities directly', () => {
  const invalidPackage = {
    name: 'openbitfun-core',
    manifest_path: 'src/crates/assembly/core/Cargo.toml',
    dependencies: [{ name: 'tokio', kind: null, optional: false, features: ['fs', 'sync'] }],
    features: {
      'agent-runtime': ['tokio/io-util', 'tokio/macros', 'tokio/rt', 'tokio/time'],
      'legacy-migration': [],
      'mcp-runtime': ['agent-runtime', 'tokio/rt-multi-thread'],
      'browser-control': ['tokio/net', 'tokio/rt', 'tokio/time'],
      'workspace-intelligence-host': ['tokio/macros', 'tokio/rt', 'tokio/sync', 'tokio/time'],
      'product-full': ['agent-runtime', 'tokio/net'],
    },
  };

  const messages = findTokioDependencyFeatureViolations([invalidPackage]).map(
    (violation) => violation.message,
  );
  assert.deepEqual(messages, [
    'openbitfun-core:product-full Tokio aggregate must compose reviewed owners instead of declaring Tokio capabilities directly',
  ]);
});

test('services-core Windows API capabilities stay feature-owned', async () => {
  const { findServicesCorePlatformDependencyFeatureViolations } = await import(
    './core-boundaries/cargo-dependency-boundaries.mjs'
  );
  assert.equal(
    typeof findServicesCorePlatformDependencyFeatureViolations,
    'function',
    'Cargo boundary checker must expose the services-core platform dependency policy',
  );
  const packageWithAmbientWindowsApis = {
    name: 'openbitfun-services-core',
    manifest_path: 'src/crates/services/services-core/Cargo.toml',
    dependencies: [
      {
        name: 'windows',
        kind: null,
        optional: true,
        target: 'cfg(windows)',
        features: ['Win32_Storage_FileSystem', 'Win32_System_Threading'],
      },
    ],
  };

  const violations = findServicesCorePlatformDependencyFeatureViolations([
    packageWithAmbientWindowsApis,
  ]);
  assert.equal(violations.length, 1);
  assert.match(
    violations[0].message,
    /windows API capabilities must be selected by services-core owner features/,
  );

  assert.deepEqual(
    findServicesCorePlatformDependencyFeatureViolations([
      {
        ...packageWithAmbientWindowsApis,
        dependencies: [{ ...packageWithAmbientWindowsApis.dependencies[0], features: [] }],
      },
    ]),
    [],
  );
});

test('services-integrations Windows dependency keeps only APIs used by its owners', () => {
  const pkg = packageAt(
    'openbitfun-services-integrations',
    'src/crates/services/services-integrations/Cargo.toml',
    [{
      name: 'windows',
      kind: null,
      optional: true,
      target: 'cfg(windows)',
      features: [
        'Win32_Foundation',
        'Win32_Storage_FileSystem',
        'Win32_System_Diagnostics_ToolHelp',
      ],
    }],
  );

  const violations = findServicesIntegrationsPlatformDependencyFeatureViolations([pkg]);
  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /unexpected Windows API capabilities: Win32_System_Diagnostics_ToolHelp/);

  pkg.dependencies[0].features = ['Win32_Foundation', 'Win32_Storage_FileSystem'];
  assert.deepEqual(findServicesIntegrationsPlatformDependencyFeatureViolations([pkg]), []);

  pkg.dependencies[0].target = 'cfg(all(windows, target_arch = "x86_64"))';
  const targetViolations = findServicesIntegrationsPlatformDependencyFeatureViolations([pkg]);
  assert.equal(targetViolations.length, 1);
  assert.match(targetViolations[0].message, /must declare exactly one reviewed Windows dependency/);

  pkg.dependencies[0].target = 'cfg(windows)';
  pkg.dependencies.push({
    name: 'windows',
    kind: null,
    optional: false,
    target: null,
    features: ['Win32_System_Threading'],
  });
  const duplicateViolations = findServicesIntegrationsPlatformDependencyFeatureViolations([pkg]);
  assert.equal(duplicateViolations.length, 1);
  assert.match(duplicateViolations[0].message, /must declare exactly one reviewed Windows dependency/);

  pkg.dependencies = [];
  const missingViolations = findServicesIntegrationsPlatformDependencyFeatureViolations([pkg]);
  assert.equal(missingViolations.length, 1);
  assert.match(missingViolations[0].message, /must declare exactly one reviewed Windows dependency/);
});

test('closed feature profiles reject product-full hidden behind a child feature', async () => {
  const { unexpectedReachableLocalFeatures } = await import(
    './core-boundaries/manifest-feature-helpers.mjs'
  );
  const features = new Map([
    ['service-integrations', { refs: ['file-watch'], line: 1 }],
    [
      'file-watch',
      {
        refs: ['openbitfun-services-integrations/file-watch', 'product-full'],
        line: 2,
      },
    ],
    ['product-full', { refs: ['dep:rmcp'], line: 3 }],
  ]);

  assert.deepEqual(
    unexpectedReachableLocalFeatures(
      features,
      'service-integrations',
      new Set(['file-watch']),
    ),
    [
      {
        featureName: 'product-full',
        path: ['service-integrations', 'file-watch', 'product-full'],
      },
    ],
  );
});

test('capability contract consumers may inherit empty defaults but must select reviewed features', async () => {
  const cargoBoundaries = await import(
    './core-boundaries/cargo-dependency-boundaries.mjs'
  );
  assert.equal(
    typeof cargoBoundaries.findCapabilityContractConsumerViolations,
    'function',
    'Cargo boundary checker must expose the capability contract consumer policy',
  );

  const runtimePorts = capabilityPackage(
    'openbitfun-runtime-ports',
    'src/crates/contracts/runtime-ports/Cargo.toml',
    RUNTIME_PORT_FEATURE_PROFILES,
  );
  const agentTools = agentToolsCapabilityPackage();
  const pluginRuntimeClient = packageAt(
    'openbitfun-plugin-runtime-client',
    'src/crates/execution/plugin-runtime-client/Cargo.toml',
    [
      pathDependency('src/crates/contracts/runtime-ports', {
        name: 'openbitfun-runtime-ports',
      }),
    ],
  );

  const messages = findTestCapabilityViolations(
    cargoBoundaries.findCapabilityContractConsumerViolations,
    [
    runtimePorts,
    agentTools,
    pluginRuntimeClient,
    ],
  ).map((violation) => violation.message);

  assert.doesNotMatch(messages.join('\n'), /default-features = false/);
  assert.ok(messages.some((message) => /plugin-runtime/.test(message)));

  // Shared file/search algorithms consume workspace IO, not the entire runtime API.
  const toolRuntime = packageAt(
    'tool-runtime',
    'src/crates/execution/tool-execution/Cargo.toml',
    [
      pathDependency('src/crates/contracts/runtime-ports', {
        name: 'openbitfun-runtime-ports',
        features: ['workspace-ports'],
      }),
      pathDependency('src/crates/execution/tool-contracts', {
        name: 'openbitfun-agent-tools',
        features: ['computer-use-contract'],
      }),
    ],
  );
  const ioContractRules = capabilityContractDependencyRules.filter(
    ({ packageName }) => ['openbitfun-runtime-ports', 'openbitfun-agent-tools'].includes(packageName),
  );
  assert.deepEqual(findTestCapabilityViolations(
    cargoBoundaries.findCapabilityContractConsumerViolations,
    [runtimePorts, agentTools, toolRuntime],
    ioContractRules,
  ), []);
  for (const features of [[], ['workspace-ports', 'agent-api']]) {
    const mutatedConsumer = {
      ...toolRuntime,
      dependencies: [
        { ...toolRuntime.dependencies[0], features },
        toolRuntime.dependencies[1],
      ],
    };
    const violations = findTestCapabilityViolations(
      cargoBoundaries.findCapabilityContractConsumerViolations,
      [runtimePorts, agentTools, mutatedConsumer],
      ioContractRules,
    );
    assert.ok(violations.some(({ message }) => /tool-runtime.*openbitfun-runtime-ports/.test(message)),
      `tool-runtime must retain exactly workspace-ports, not ${features.join(', ') || 'an empty edge'}`);
  }
  for (const features of [[], ['computer-use-contract', 'mcp-bridge']]) {
    const mutatedConsumer = {
      ...toolRuntime,
      dependencies: [
        toolRuntime.dependencies[0],
        { ...toolRuntime.dependencies[1], features },
      ],
    };
    const violations = findTestCapabilityViolations(
      cargoBoundaries.findCapabilityContractConsumerViolations,
      [runtimePorts, agentTools, mutatedConsumer],
      ioContractRules,
    );
    assert.ok(violations.some(({ message }) => /tool-runtime.*openbitfun-agent-tools/.test(message)),
      `tool-runtime must retain exactly computer-use-contract, not ${features.join(', ') || 'an empty edge'}`);
  }
});

test('unreviewed consumers cannot add capability contract dependency edges', async () => {
  const { findCapabilityContractConsumerViolations } = await import(
    './core-boundaries/cargo-dependency-boundaries.mjs'
  );
  const runtimePorts = capabilityPackage(
    'openbitfun-runtime-ports',
    'src/crates/contracts/runtime-ports/Cargo.toml',
    RUNTIME_PORT_FEATURE_PROFILES,
  );
  const agentTools = agentToolsCapabilityPackage();
  const unreviewed = packageAt(
    'unreviewed-host',
    'src/apps/unreviewed-host/Cargo.toml',
    [
      pathDependency('src/crates/contracts/runtime-ports', {
        name: 'openbitfun-runtime-ports',
        target: 'cfg(windows)',
        usesDefaultFeatures: false,
        features: ['agent-api'],
      }),
    ],
  );

  const messages = findTestCapabilityViolations(
    findCapabilityContractConsumerViolations,
    [runtimePorts, agentTools, unreviewed],
    capabilityContractDependencyRules.slice(0, 2),
  ).map(
    (violation) => violation.message,
  );
  assert.equal(messages.length, 1, messages.join('\n'));
  assert.match(messages[0], /unreviewed consumer/);
});

test('capability contract edge policy rejects alias, weak, optional, and non-normal widening', async () => {
  const { findCapabilityContractConsumerViolations } = await import(
    './core-boundaries/cargo-dependency-boundaries.mjs'
  );
  const runtimePorts = capabilityPackage(
    'openbitfun-runtime-ports',
    'src/crates/contracts/runtime-ports/Cargo.toml',
    RUNTIME_PORT_FEATURE_PROFILES,
  );
  const validDependency = pathDependency('src/crates/contracts/runtime-ports', {
    name: 'openbitfun-runtime-ports',
    usesDefaultFeatures: false,
    features: ['plugin-runtime'],
  });
  const mutations = [
    { label: 'renamed alias forwarding', dependency: { ...validDependency, rename: 'ports' }, features: { sneaky: ['ports/agent-api'] }, expected: /sneaky.*unreviewed.*forwarding/ },
    { label: 'weak alias forwarding', dependency: { ...validDependency, rename: 'ports' }, features: { sneaky: ['ports?/agent-api'] }, expected: /sneaky.*unreviewed.*forwarding/ },
    { label: 'optional edge', dependency: { ...validDependency, optional: true }, features: {}, expected: /unreviewed.*dependency edge/ },
    { label: 'dev edge', dependency: { ...validDependency, kind: 'dev' }, features: {}, expected: /unreviewed.*dependency edge/ },
    { label: 'build edge', dependency: { ...validDependency, kind: 'build' }, features: {}, expected: /unreviewed.*dependency edge/ },
    { label: 'target edge', dependency: { ...validDependency, target: 'cfg(windows)' }, features: {}, expected: /unreviewed.*dependency edge/ },
  ];

  for (const mutation of mutations) {
    const consumer = {
      ...packageAt(
        'openbitfun-plugin-runtime-client',
        'src/crates/execution/plugin-runtime-client/Cargo.toml',
        [mutation.dependency],
      ),
      features: mutation.features,
    };
    const messages = findTestCapabilityViolations(
      findCapabilityContractConsumerViolations,
      [runtimePorts, consumer],
    ).map(
      (violation) => violation.message,
    );
    assert.ok(
      messages.some((message) => mutation.expected.test(message)),
      `${mutation.label} must not widen the reviewed capability contract`,
    );
  }
});

test('capability contract targets require an explicit empty default feature', async () => {
  const { findCapabilityContractConsumerViolations } = await import(
    './core-boundaries/cargo-dependency-boundaries.mjs'
  );
  const runtimePorts = capabilityPackage(
    'openbitfun-runtime-ports',
    'src/crates/contracts/runtime-ports/Cargo.toml',
    RUNTIME_PORT_FEATURE_PROFILES,
  );
  delete runtimePorts.features.default;

  const messages = findTestCapabilityViolations(
    findCapabilityContractConsumerViolations,
    [runtimePorts],
  ).map(
    (violation) => violation.message,
  );
  assert.ok(messages.some((message) => /default feature must stay empty/.test(message)));
});

test('capability contract optional activators reject unreviewed dep aliases', async () => {
  const { findCapabilityContractConsumerViolations } = await import(
    './core-boundaries/cargo-dependency-boundaries.mjs'
  );
  const agentTools = agentToolsCapabilityPackage();
  const dependency = pathDependency('src/crates/execution/tool-contracts', {
    name: 'openbitfun-agent-tools',
    rename: 'tools_contract',
    optional: true,
    usesDefaultFeatures: false,
  });
  const consumer = {
    ...packageAt(
      'openbitfun-acp',
      'src/crates/interfaces/acp/Cargo.toml',
      [dependency],
    ),
    features: {
      client: ['tools_contract/acp-bridge'],
      server: ['dep:tools_contract'],
      sneaky: ['tools_contract'],
    },
  };

  const messages = findTestCapabilityViolations(
    findCapabilityContractConsumerViolations,
    [agentTools, consumer],
  ).map(
    (violation) => violation.message,
  );
  assert.ok(messages.some((message) => /sneaky.*unreviewed.*activation/.test(message)));
  assert.doesNotMatch(messages.join('\n'), /server.*unreviewed.*activation/);
});

test('capability contract consumers cannot remove reviewed forwarding or activation', async () => {
  const { findCapabilityContractConsumerViolations } = await import(
    './core-boundaries/cargo-dependency-boundaries.mjs'
  );
  const runtimePorts = capabilityPackage(
    'openbitfun-runtime-ports',
    'src/crates/contracts/runtime-ports/Cargo.toml',
    RUNTIME_PORT_FEATURE_PROFILES,
  );
  const integrations = {
    ...packageAt(
      'openbitfun-services-integrations',
      'src/crates/services/services-integrations/Cargo.toml',
      [pathDependency('src/crates/contracts/runtime-ports', {
        name: 'openbitfun-runtime-ports',
        optional: true,
        usesDefaultFeatures: false,
      })],
    ),
    features: {
      git: [],
      'remote-connect': [
        'openbitfun-runtime-ports/agent-api',
        'openbitfun-runtime-ports/remote-workspace-ports',
      ],
      'remote-ssh': [
        'openbitfun-runtime-ports/remote-exec-port',
        'openbitfun-runtime-ports/remote-workspace-ports',
        'openbitfun-runtime-ports/workspace-ports',
      ],
      'remote-ssh-concrete': ['dep:openbitfun-runtime-ports'],
      'script-tool-runtime': ['openbitfun-runtime-ports/script-tool-runtime'],
    },
  };
  const servicesCore = {
    ...packageAt(
      'openbitfun-services-core',
      'src/crates/services/services-core/Cargo.toml',
      [pathDependency('src/crates/contracts/runtime-ports', {
        name: 'openbitfun-runtime-ports',
        optional: true,
        usesDefaultFeatures: false,
      })],
    ),
    features: {
      permission: [],
      'workspace-runtime': [
        'dep:openbitfun-runtime-ports',
        'openbitfun-runtime-ports/runtime-event-port',
        'openbitfun-runtime-ports/workspace-ports',
      ],
    },
  };

  const messages = findTestCapabilityViolations(findCapabilityContractConsumerViolations, [
    runtimePorts,
    integrations,
    servicesCore,
  ]).map((violation) => violation.message);

  assert.ok(messages.some((message) => /openbitfun-services-integrations:git.*missing reviewed.*git-port forwarding/.test(message)));
  assert.ok(messages.some((message) => /openbitfun-services-core:permission.*missing reviewed.*activation/.test(message)));
});

test('capability contract targets cannot be removed or replaced by a same-name package', async () => {
  const { findCapabilityContractConsumerViolations } = await import(
    './core-boundaries/cargo-dependency-boundaries.mjs'
  );
  const reviewedConsumer = packageAt(
    'openbitfun-plugin-runtime-client',
    'src/crates/execution/plugin-runtime-client/Cargo.toml',
    [pathDependency('src/crates/contracts/runtime-ports', {
      name: 'openbitfun-runtime-ports',
      usesDefaultFeatures: false,
      features: ['plugin-runtime'],
    })],
  );

  const missingTargetMessages = findTestCapabilityViolations(
    findCapabilityContractConsumerViolations,
    [reviewedConsumer],
  ).map((violation) => violation.message);
  assert.ok(missingTargetMessages.some((message) =>
    /openbitfun-runtime-ports managed target.*missing/.test(message)));

  const runtimePorts = capabilityPackage(
    'openbitfun-runtime-ports',
    'src/crates/contracts/runtime-ports/Cargo.toml',
    RUNTIME_PORT_FEATURE_PROFILES,
  );
  reviewedConsumer.dependencies[0] = {
    ...reviewedConsumer.dependencies[0],
    path: null,
    source: 'registry+https://github.com/rust-lang/crates.io-index',
  };
  const spoofedTargetMessages = findTestCapabilityViolations(
    findCapabilityContractConsumerViolations,
    [runtimePorts, reviewedConsumer],
  ).map((violation) => violation.message);
  assert.ok(spoofedTargetMessages.some((message) => /managed internal path/.test(message)));

  const vendorRuntimePorts = {
    ...runtimePorts,
    manifest_path: join(
      TEST_ROOT,
      'vendor',
      'src',
      'crates',
      'contracts',
      'runtime-ports',
      'Cargo.toml',
    ),
  };
  reviewedConsumer.dependencies[0] = {
    ...reviewedConsumer.dependencies[0],
    path: join(TEST_ROOT, 'vendor', 'src', 'crates', 'contracts', 'runtime-ports'),
    source: null,
  };
  const vendorTargetMessages = findCapabilityContractConsumerViolations(
    [vendorRuntimePorts, reviewedConsumer],
    [capabilityContractDependencyRules[0]],
    { root: TEST_ROOT },
  ).map((violation) => violation.message);
  assert.ok(vendorTargetMessages.some((message) => /managed target.*missing/.test(message)));
});

test('capability contract target feature graphs stay exact', async () => {
  const { findCapabilityContractConsumerViolations } = await import(
    './core-boundaries/cargo-dependency-boundaries.mjs'
  );
  const runtimePorts = capabilityPackage(
    'openbitfun-runtime-ports',
    'src/crates/contracts/runtime-ports/Cargo.toml',
    RUNTIME_PORT_FEATURE_PROFILES,
  );
  runtimePorts.features['git-port'] = ['plugin-runtime'];

  const messages = findTestCapabilityViolations(
    findCapabilityContractConsumerViolations,
    [runtimePorts],
  ).map(
    (violation) => violation.message,
  );
  assert.ok(messages.some((message) => /git-port.*feature graph must stay exact/.test(message)));
});

test('unreviewed local feature aliases cannot wrap reviewed capability owners', async () => {
  const { findCapabilityContractConsumerViolations } = await import(
    './core-boundaries/cargo-dependency-boundaries.mjs'
  );
  const agentTools = agentToolsCapabilityPackage();
  const acp = {
    ...packageAt(
      'openbitfun-acp',
      'src/crates/interfaces/acp/Cargo.toml',
      [pathDependency('src/crates/execution/tool-contracts', {
        name: 'openbitfun-agent-tools',
        optional: true,
        usesDefaultFeatures: false,
      })],
    ),
    features: {
      default: ['client', 'server'],
      client: ['openbitfun-agent-tools/acp-bridge'],
      server: ['dep:openbitfun-agent-tools'],
      sneakyClient: ['client'],
      sneakyServer: ['server'],
    },
  };

  const messages = findTestCapabilityViolations(
    findCapabilityContractConsumerViolations,
    [agentTools, acp],
  ).map(
    (violation) => violation.message,
  );
  assert.ok(messages.some((message) => /sneakyClient.*unreviewed.*aggregate/.test(message)));
  assert.ok(messages.some((message) => /sneakyServer.*unreviewed.*aggregate/.test(message)));
  assert.doesNotMatch(messages.join('\n'), /default.*unreviewed.*aggregate/);
});

test('capability contract consumers cannot remove reviewed dependency edges', async () => {
  const { findCapabilityContractConsumerViolations } = await import(
    './core-boundaries/cargo-dependency-boundaries.mjs'
  );
  const runtimePorts = capabilityPackage(
    'openbitfun-runtime-ports',
    'src/crates/contracts/runtime-ports/Cargo.toml',
    RUNTIME_PORT_FEATURE_PROFILES,
  );
  const pluginRuntimeClient = packageAt(
    'openbitfun-plugin-runtime-client',
    'src/crates/execution/plugin-runtime-client/Cargo.toml',
  );
  const opencodeAdapter = packageAt(
    'openbitfun-opencode-adapter',
    'src/crates/adapters/opencode-adapter/Cargo.toml',
    [pathDependency('src/crates/contracts/runtime-ports', {
      name: 'openbitfun-runtime-ports',
      usesDefaultFeatures: false,
      features: ['plugin-runtime'],
    })],
  );

  const messages = findTestCapabilityViolations(findCapabilityContractConsumerViolations, [
    runtimePorts,
    pluginRuntimeClient,
    opencodeAdapter,
  ]).map((violation) => violation.message);
  assert.ok(messages.some((message) => /openbitfun-plugin-runtime-client.*missing reviewed.*normal.*edge/.test(message)));
  assert.ok(messages.some((message) => /openbitfun-opencode-adapter.*missing reviewed.*dev.*edge/.test(message)));
});

test('vendored Engine.IO remains in resolved feature audits without becoming a product owner', () => {
  const owner = packageAt('owner', 'src/apps/example/Cargo.toml');
  const vendor = { ...packageAt('eioc', 'third_party/eioc/Cargo.toml'), version: '0.5.0' };
  const collect = members => collectCargoMetadataGraph({
    root: TEST_ROOT,
    manifestPaths: [join(TEST_ROOT, 'Cargo.toml')],
    loadMetadata: () => ({
      packages: [owner, vendor], workspace_members: members,
      resolve: { nodes: [{ id: vendor.id, features: ['rustls-tls'], deps: [] }] },
    }),
  });
  const graph = collect([owner.id]);
  assert.deepEqual(graph.packages.map(pkg => pkg.name), ['owner']);
  assert.ok(graph.resolvedPackageFeatures.some(record => record.name === 'eioc'));
  assert.ok(collect([owner.id, vendor.id]).packages.some(pkg => pkg.name === 'eioc'),
    'a product workspace member cannot bypass ownership checks through a vendor path');
});

test('vendored screenshots keeps its reviewed external identity and image profile', () => {
  const owner = packageAt('owner', 'src/apps/example/Cargo.toml');
  const vendor = {
    ...packageAt('screenshots', 'third_party/screenshots/Cargo.toml', [{
      name: 'image',
      rename: null,
      kind: null,
      optional: false,
      target: null,
      features: [],
      uses_default_features: true,
    }]),
    version: '0.8.10',
  };
  const graph = collectCargoMetadataGraph({
    root: TEST_ROOT,
    manifestPaths: [join(TEST_ROOT, 'Cargo.toml')],
    loadMetadata: () => ({
      packages: [owner, vendor],
      workspace_members: [owner.id],
      resolve: { nodes: [{ id: vendor.id, features: ['default'], deps: [] }] },
    }),
  });

  assert.deepEqual(graph.packages.map(pkg => pkg.name), ['owner']);
  assert.ok(graph.resolvedPackageFeatures.some(record => record.name === 'screenshots'));
  assert.deepEqual(findThirdPartyCapabilityFeatureViolations([vendor]), []);
  assert.ok(collectCargoMetadataGraph({
    root: TEST_ROOT,
    manifestPaths: [join(TEST_ROOT, 'Cargo.toml')],
    loadMetadata: () => ({
      packages: [owner, vendor],
      workspace_members: [owner.id, vendor.id],
      resolve: { nodes: [] },
    }),
  }).packages.some(pkg => pkg.name === 'screenshots'));
});

test('vendored Tao is external only at its reviewed version and stays in feature audits', () => {
  const owner = packageAt('owner', 'src/apps/example/Cargo.toml');
  const vendor = { ...packageAt('tao', 'third_party/tao/Cargo.toml'), version: '0.36.0' };
  const collect = (pkg = vendor, members = [owner.id]) => collectCargoMetadataGraph({
    root: TEST_ROOT,
    manifestPaths: [join(TEST_ROOT, 'Cargo.toml')],
    loadMetadata: () => ({
      packages: [owner, pkg], workspace_members: members,
      resolve: { nodes: [{ id: pkg.id, features: ['rwh_06'], deps: [] }] },
    }),
  });
  const graph = collect();
  assert.deepEqual(graph.packages.map(pkg => pkg.name), ['owner']);
  assert.ok(graph.resolvedPackageFeatures.some(record => record.name === 'tao'));
  assert.ok(collect(vendor, [owner.id, vendor.id]).packages.some(pkg => pkg.name === 'tao'));
  assert.ok(collect({ ...vendor, version: '0.37.0' }).packages.some(pkg => pkg.name === 'tao'));
  assert.ok(collect({ ...vendor, name: 'product-owner' }).packages.some(pkg => pkg.name === 'product-owner'));
});

test('vendored Wry is external only at its reviewed version and stays in feature audits', () => {
  const owner = packageAt('owner', 'src/apps/example/Cargo.toml');
  const vendor = { ...packageAt('wry', 'third_party/wry/Cargo.toml'), version: '0.56.0' };
  const collect = (pkg = vendor, members = [owner.id]) => collectCargoMetadataGraph({
    root: TEST_ROOT,
    manifestPaths: [join(TEST_ROOT, 'Cargo.toml')],
    loadMetadata: () => ({
      packages: [owner, pkg], workspace_members: members,
      resolve: { nodes: [{ id: pkg.id, features: ['os-webview'], deps: [] }] },
    }),
  });
  const graph = collect();
  assert.deepEqual(graph.packages.map(pkg => pkg.name), ['owner']);
  assert.ok(graph.resolvedPackageFeatures.some(record => record.name === 'wry'));
  assert.ok(collect(vendor, [owner.id, vendor.id]).packages.some(pkg => pkg.name === 'wry'));
  assert.ok(collect({ ...vendor, version: '0.57.0' }).packages.some(pkg => pkg.name === 'wry'));
  assert.ok(collect({ ...vendor, name: 'product-owner' }).packages.some(pkg => pkg.name === 'product-owner'));
});


test('workspace transfer admits IO without process or networking capabilities', () => {
  const pkg = {
    name: 'openbitfun-services-core',
    manifest_path: 'src/crates/services/services-core/Cargo.toml',
    dependencies: [{ name: 'tokio', kind: null, optional: true, features: [] }],
    features: {
      'workspace-transfer': ['dep:tokio', 'tokio/fs', 'tokio/io-util', 'tokio/rt', 'tokio/sync'],
    },
  };
  assert.deepEqual(findTokioDependencyFeatureViolations([pkg]).filter(v => v.message.includes(':workspace-transfer ')), []);
  pkg.features['workspace-transfer'].push('tokio/process', 'tokio/net');
  assert.ok(findTokioDependencyFeatureViolations([pkg]).some(v =>
    v.message.includes('workspace-transfer has unexpected effective Tokio capabilities')));
});


test('core loopback WebSocket fixture cannot broaden the runtime dependency', () => {
  const runtime = { name: 'tokio-tungstenite', kind: null, optional: true, uses_default_features: true, features: [] };
  const development = { ...runtime, kind: 'dev', optional: false };
  const pkg = packageAt('openbitfun-core', 'src/crates/assembly/core/Cargo.toml', [runtime, development]);
  assert.deepEqual(findThirdPartyCapabilityFeatureViolations([pkg]), []);
  for (const dependencies of [
    [{ ...runtime, optional: false }, development],
    [runtime, { ...development, features: ['rustls-tls-native-roots'] }],
    [runtime, development, { ...development }],
  ]) {
    assert.ok(findThirdPartyCapabilityFeatureViolations([{ ...pkg, dependencies }]).length > 0);
  }
});

// Icon codecs must never pull animation or unrelated product features into small hosts.
test('workspace icon image codecs remain an exact feature-owned slice', () => {
  const pkg = {
    ...packageAt('openbitfun-services-core', 'src/crates/services/services-core/Cargo.toml', [{
      name: 'image', kind: null, optional: true, uses_default_features: false, features: [],
    }]),
    features: {
      'pet-packages': ['dep:image', 'image/gif', 'image/jpeg', 'image/png', 'image/webp'],
      'workspace-icons': ['dep:image', 'image/jpeg', 'image/png', 'image/webp'],
    },
  };
  assert.deepEqual(findThirdPartyCapabilityFeatureViolations([pkg]), []);
  pkg.features['workspace-icons'].push('image/gif');
  assert.match(findThirdPartyCapabilityFeatureViolations([pkg]).map(v => v.message).join('\n'), /workspace-icons.*unexpected.*gif/);
});


test('Responses WebSocket adapter uses framing over the existing Reqwest upgrade', () => {
  const pkg = packageAt('openbitfun-ai-adapters', 'src/crates/adapters/ai-adapters/Cargo.toml', [{
    name: 'tokio-tungstenite', kind: null, optional: false, uses_default_features: false,
    features: ['handshake'],
  }]);
  assert.deepEqual(findThirdPartyCapabilityFeatureViolations([pkg]), []);
  for (const change of [
    { features: ['handshake', 'connect'] },
    { features: ['handshake', 'rustls-tls-native-roots'] },
    { uses_default_features: true },
  ]) {
    const mutated = structuredClone(pkg);
    Object.assign(mutated.dependencies[0], change);
    assert.ok(findThirdPartyCapabilityFeatureViolations([mutated]).length > 0);
  }
});

 test('workspace intelligence claim and synchronous lease have exact closed owners and source gates', async () => {
  const manifestPath = 'src/crates/services/services-core/Cargo.toml';
  const features = parseManifestFeatures(await readFile(new URL('../' + manifestPath, import.meta.url), 'utf8'));
  for (const [featureName, refs] of [
    ['exclusive-file-lease', ['dep:fs2']],
    ['workspace-intelligence-claim', ['workspace-intelligence-commit', 'exclusive-file-lease', 'dep:uuid']],
  ]) {
    assert.deepEqual(features[featureName], refs);
    const rule = coreClosedFeatureProfileRules.find(r => r.manifestPath === manifestPath && r.featureName === featureName);
    assert.equal(rule.exact, true);
    assert.deepEqual(rule.requiredFeatureRefs, refs);
    if (featureName === 'workspace-intelligence-claim') assert.deepEqual(rule.allowedTransitiveFeatureRefs,
      ['workspace-intelligence-store', 'workspace-intelligence-cognition', 'json-io']);
  }
  const owners = optionalDependencyFeatureOwnerRules.find(r => r.crateName === 'services-core').dependencies;
  assert.ok(owners.find(d => d.depName === 'uuid').ownerFeatures.includes('workspace-intelligence-claim'));
  assert.ok(owners.find(d => d.depName === 'fs2').ownerFeatures.includes('exclusive-file-lease'));
  const rule = requiredContentRules.find(r => r.path === 'src/crates/services/services-core/src/lib.rs');
  const source = await readFile(new URL('../' + rule.path, import.meta.url), 'utf8');
  const lock = rule.patterns.find(p => p.message === 'missing shared file lock owner source gate');
  assert.ok(lock.regex.test(source));
  assert.ok(!lock.regex.test('#[cfg(any(feature = "local-storage", feature = "runtime-ownership", feature = "resource-capacity"))] mod file_lock;'));
  assert.ok(rule.patterns.some(p => p.regex.test('#[cfg(feature = "workspace-intelligence-claim")] pub mod workspace_intelligence_claim;')));
  assert.deepEqual(features.default, []);
 });

 test('workspace intelligence claim inherits only JSON IO Tokio and standalone lease needs none', () => {
  const messages = (claimRefs, leaseRefs = ['dep:fs2']) => findTokioDependencyFeatureViolations([{
    name: 'openbitfun-services-core', manifest_path: 'src/crates/services/services-core/Cargo.toml',
    dependencies: [{ name: 'tokio', kind: null, optional: true, features: [] }],
    features: {
      'json-io': ['dep:tokio', 'tokio/fs', 'tokio/rt', 'tokio/sync', 'tokio/time'],
      'workspace-intelligence-store': ['json-io', 'dep:sha2'],
      'workspace-intelligence-cognition': ['dep:rusqlite', 'dep:sha2'],
      'workspace-intelligence-commit': ['workspace-intelligence-store', 'workspace-intelligence-cognition'],
      'workspace-intelligence-claim': claimRefs, 'exclusive-file-lease': leaseRefs,
    },
  }]).map(v => v.message).filter(m => /:workspace-intelligence-claim |:exclusive-file-lease /.test(m));
  const refs = ['workspace-intelligence-commit', 'exclusive-file-lease', 'dep:uuid'];
  assert.deepEqual(messages(refs), []);
  assert.match(messages([...refs, 'tokio/process']).join('\n'), /unexpected effective Tokio capabilities: process/);
  assert.match(messages(['exclusive-file-lease', 'dep:uuid']).join('\n'), /missing effective Tokio capabilities: fs, rt, sync, time/);
  assert.match(messages(refs, ['dep:fs2', 'tokio/rt']).join('\n'), /exclusive-file-lease Tokio capabilities require an explicit owner contract/);
 });

test('workspace intelligence host anchor is an exact write-once feature over uuid and json-io', async () => {
  const manifestPath = 'src/crates/services/services-core/Cargo.toml';
  const manifest = await readFile(new URL('../' + manifestPath, import.meta.url), 'utf8');
  const features = parseManifestFeatures(manifest);
  const refs = ['json-io', 'dep:uuid', 'dep:libc'];

  // The owner definition is exact: generic atomic JSON IO plus opaque v4 uuid
  // generation and the atomic no-follow, non-blocking Unix open, with no hashing
  // dependency, policy, runtime, process, network, or UI capability.
  assert.deepEqual(features['workspace-intelligence-host-anchor'], refs);
  assert.deepEqual(features.default, []);
  assert.ok(!features.default.includes('workspace-intelligence-host-anchor'));

  const rule = coreClosedFeatureProfileRules.find((candidate) =>
    candidate.manifestPath === manifestPath
      && candidate.featureName === 'workspace-intelligence-host-anchor');
  assert.equal(rule?.exact, true);
  assert.deepEqual(rule.requiredFeatureRefs, refs);
  // json-io composes no further local feature, so no transitive local feature
  // needs a separate allowance.
  assert.equal(rule.allowedTransitiveFeatureRefs, undefined);
  assert.ok(!rule.requiredFeatureRefs.includes('dep:sha2'));
  assert.match(rule.reason, /write-once opaque storage-namespace anchor/);

  const owners = optionalDependencyFeatureOwnerRules
    .find((candidate) => candidate.crateName === 'services-core').dependencies;
  assert.ok(owners.find((dependency) => dependency.depName === 'uuid').ownerFeatures
    .includes('workspace-intelligence-host-anchor'));
  // The Unix no-follow, non-blocking open is the only reason this feature owns
  // `libc`; the owner rule must stay exact for it too.
  assert.ok(owners.find((dependency) => dependency.depName === 'libc').ownerFeatures
    .includes('workspace-intelligence-host-anchor'));
  assert.ok(!owners.find((dependency) => dependency.depName === 'sha2').ownerFeatures
    .includes('workspace-intelligence-host-anchor'));

  const sourceRule = requiredContentRules.find((candidate) =>
    candidate.path === 'src/crates/services/services-core/src/lib.rs');
  const gate = sourceRule.patterns.find((pattern) =>
    pattern.message === 'missing workspace-intelligence-host-anchor storage namespace source gate');
  assert.ok(gate, 'the lib.rs source contract must require the host anchor gate');
  assert.match(
    '#[cfg(feature = "workspace-intelligence-host-anchor")]\npub mod workspace_intelligence_host_anchor;',
    gate.regex,
  );
  const source = await readFile(
    new URL('../src/crates/services/services-core/src/lib.rs', import.meta.url),
    'utf8',
  );
  assert.match(source, gate.regex);
  assert.ok(!gate.regex.test(
    '#[cfg(feature = "workspace-intelligence-claim")]\npub mod workspace_intelligence_claim;',
  ));
});

test('workspace intelligence host anchor inherits only JSON IO Tokio and no process or network', () => {
  const messages = (refs) => findTokioDependencyFeatureViolations([{
    name: 'openbitfun-services-core',
    manifest_path: 'src/crates/services/services-core/Cargo.toml',
    dependencies: [{ name: 'tokio', kind: null, optional: true, features: [] }],
    features: {
      'json-io': ['dep:tokio', 'tokio/fs', 'tokio/rt', 'tokio/sync', 'tokio/time'],
      'workspace-intelligence-host-anchor': refs,
    },
  }]).map((violation) => violation.message)
    .filter((message) => message.includes(':workspace-intelligence-host-anchor '));

  const refs = ['json-io', 'dep:uuid', 'dep:libc'];
  // The reviewed Tokio capability row must exist with exactly the json-io
  // closure, so the reviewed refs stay clean and widening names the capability.
  assert.deepEqual(messages(refs), []);
  assert.match(
    messages([...refs, 'tokio/process']).join('\n'),
    /unexpected effective Tokio capabilities: process/,
  );
  assert.match(
    messages([...refs, 'tokio/net']).join('\n'),
    /unexpected effective Tokio capabilities: net/,
  );
  assert.match(
    messages(['dep:uuid']).join('\n'),
    /missing effective Tokio capabilities: fs, rt, sync, time/,
  );
});

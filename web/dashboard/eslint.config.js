import js from '@eslint/js'
import tseslint from 'typescript-eslint'
import reactHooks from 'eslint-plugin-react-hooks'
import i18next from 'eslint-plugin-i18next'

// I18N-01: pseudo-localization gate.
//
// The ten screens (plus the app shell and shared Astra components) must not
// hardcode user-visible strings: every literal in these files is a regression
// the pseudo-locale gate would miss at runtime. `mode: 'all'` makes the rule
// fail `npm run lint` on any string literal in a gated file — JSX text
// (<span>Load</span>), JSX attribute values (placeholder=, aria-label=,
// title=) and plain string literals in the component code (window.confirm,
// setError, labels in objects). The extraction therefore stays complete as
// the screens evolve.
//
// The plugin's `words.exclude` patterns are the whitelist for non-translatable
// literals the screens legitimately need (URL params, storage keys, CSS/class
// names, aria vocabulary, format symbols, icons, short data tokens). The
// plugin's default patterns already skip empty strings and ALL-CAPS tokens.
//
// Negative test: add any new user-facing string literal to a gated file and
// `npm --prefix web/dashboard run lint` must fail before it is moved to
// src/i18n/en.json and referenced through t().

const GATED_I18N_FILES = [
  'src/App.tsx',
  'src/pages/OverviewPage.tsx',
  'src/pages/CostDashboard.tsx',
  'src/pages/ComparePage.tsx',
  'src/pages/CreditsPage.tsx',
  'src/pages/ClassifierPage.tsx',
  'src/pages/CachePage.tsx',
  'src/pages/OrgsPage.tsx',
  'src/pages/ModelsPage.tsx',
  'src/pages/RulesPage.tsx',
  'src/pages/LineagePage.tsx',
  'src/pages/RequestExplorerPage.tsx',
  'src/pages/AnalyticsExplorerPage.tsx',
  'src/pages/DashboardsPage.tsx',
  'src/pages/KeysPage.tsx',
  'src/pages/BudgetsPage.tsx',
  'src/pages/OrgSettingsPage.tsx',
  'src/pages/ModelAccessPage.tsx',
  'src/pages/MembersPage.tsx',
  'src/pages/AdminUsersPage.tsx',
  // IMP-53: the remaining screens and the W3 page modules join the gate —
  // every page must keep its copy in src/i18n/en.json as the screens evolve.
  'src/pages/TasksPage.tsx',
  'src/pages/ToolCallsPage.tsx',
  'src/pages/ToolPolicyPage.tsx',
  'src/pages/LabelPolicyPage.tsx',
  'src/pages/AuditLogPage.tsx',
  'src/pages/PolicyDecisionsPage.tsx',
  // R101-02: the guardrails summary screen (its copy lives in en.json too).
  'src/pages/GuardrailsPage.tsx',
  // OP-12: the prompt studio screens.
  'src/pages/prompts/PromptsPage.tsx',
  'src/pages/prompts/PromptDetail.tsx',
  'src/pages/prompts/PartialsPanel.tsx',
  'src/pages/prompts/PlaygroundPanel.tsx',
  'src/pages/prompts/LabelChips.tsx',
  // MC-4: the MCP credentials screen (its copy lives in src/i18n/en.json too).
  'src/pages/McpCredentialsPage.tsx',
  'src/pages/keys/AgentKeysPanel.tsx',
  'src/pages/keys/ApiKeysPanel.tsx',
  'src/pages/keys/KeyDrawer.tsx',
  'src/pages/keys/OneTimeSecretBanner.tsx',
  'src/pages/keys/ProfilesPanel.tsx',
  'src/pages/orgsettings/ProviderKeysSection.tsx',
  'src/pages/models/AliasesTab.tsx',
  'src/pages/models/ChainChips.tsx',
  'src/pages/models/ModelFormDrawer.tsx',
  'src/pages/models/ModelsPage.tsx',
  'src/pages/models/TagField.tsx',
  'src/pages/budgets/BudgetSettingsSection.tsx',
  'src/components/Pagination.tsx',
  'src/components/ScopeBar.tsx',
  'src/components/GlobalScopeBar.tsx',
  'src/components/OrgSelect.tsx',
  'src/components/OnboardingCard.tsx',
  'src/components/ChunkErrorBoundary.tsx',
  'src/components/astra/StateNotice.tsx',
  'src/components/astra/ActionDialog.tsx',
  'src/components/astra/BulkActions.tsx',
  'src/components/astra/EntityDrawer.tsx',
  'src/components/astra/CommandPalette.tsx',
  'src/components/astra/SignalInbox.tsx',
  'src/components/astra/TableSettingsMenu.tsx',
  'src/components/astra/SavedViewsMenu.tsx',
  'src/components/astra/PageHeader.tsx',
  'src/components/astra/MetricStrip.tsx',
  'src/components/astra/DataTable.tsx',
  'src/components/astra/ChartCard.tsx',
  'src/components/astra/RequestInspector.tsx',
  'src/components/astra/CopyIdButton.tsx',
  'src/components/astra/EvidenceLabel.tsx',
  'src/components/astra/FreshnessControl.tsx',
  'src/components/astra/BoardPanelCard.tsx',
  'src/components/astra/PinnedPanels.tsx',
  'src/components/astra/AstraFixtures.tsx',
  'src/components/astra/FilterBar.tsx',
  'src/components/astra/MetricHint.tsx',
  'src/components/astra/FormDrawer.tsx',
  'src/components/astra/RowActions.tsx',
  'src/components/astra/IdChip.tsx',
  'src/components/astra/OrgName.tsx',
  'src/components/astra/ProvenanceNote.tsx',
  'src/components/astra/SessionGate.tsx',
  'src/components/astra/VersionBanner.tsx',
  // UI-DEV (2026-11-02): the routing map screen and its route-map graph join
  // the gate — the graph's copy stays in src/i18n/en.json like every screen.
  'src/components/astra/RoutingGraph.tsx',
  'src/pages/RoutingMapPage.tsx',
  'src/components/shell/Breadcrumbs.tsx',
  'src/components/shell/OrgSwitcher.tsx',
  'src/components/shell/Sidebar.tsx',
  'src/components/shell/Topbar.tsx',
  'src/components/shell/UserMenu.tsx',
]

// Regex whitelist (plugin shouldSkip: with an empty include a literal is
// skipped ONLY when it matches one of these exclude patterns). A literal may
// live in a gated file only if it matches a non-translatable class below;
// every other string is UI copy and must go to src/i18n/en.json.
// String.raw keeps backslashes literal.
const I18N_WORDS_EXCLUDE = [
  // numbers (digits + separators), money/percent display values
  String.raw`^[0-9][0-9,.;:%/ -]*$`,
  String.raw`^[$€£¥][0-9][0-9,.]*%?$`,
  // single format/currency/punctuation/glyph symbols (arrows, dots, ellipsis)
  String.raw`^[\u00A0-\uFFFF\u0021-\u007E]{1,4}$`,
  // storage keys, url params, aria vocabulary, short lowercase data tokens
  String.raw`^[a-z][a-z0-9]*(?:[-_./][a-z0-9]+)*(?:\[[^\]]+\])?(?:\.[a-z0-9]+)?$`,
  // CSS type/tag selectors for focus management ('input, select, button')
  String.raw`^(?:[a-z][a-z0-9-]*(?:\[.{0,40}\])?(?:\.[a-z][a-z0-9-]+)*(?:::[a-z]+)?)(?:,\s*[a-z][a-z0-9-]*[^\s,]*){0,4}$`,
  // tailwind utility classes (incl. arbitrary values, variants like
  // disabled:opacity-40 and placeholder:text-*, single- or multi-line) —
  // never user-visible
  String.raw`^[a-z][a-z0-9-]*(?:[-:][a-z0-9-]+)*(?:-\[[^\]\s]*\])?(?:\s+[a-z][a-z0-9-]*(?:[-:][a-z0-9-]+)*(?:-\[[^\]\s]*\])?){0,60}$`,
  // astra css tokens: var(--astra-*) / var(--token, fallback)
  String.raw`^var\(--[a-z0-9-]+(,\s*[^)]*)?\)$`,
  // i18next key lookups (t('...') / titleKey: '...') — lowercase dotted
  String.raw`^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)+$`,
  // api/fixture fragments (no spaces, no UI words): 'POST /api/models',
  // 'gpt-4o-mini', 'nightly-etl', 'prod-backend'
  String.raw`^[A-Za-z0-9_/.:\-]{3,64}$`,
  // fixture data timestamps with timezone: '2026-09-05 14:30 UTC'
  String.raw`^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}( [A-Z]{2,4})?$`,
  // ellipsis-bearing data tokens: 'req_…', 'org:9f2c…:v3'
  String.raw`^[A-Za-z0-9_/.:;,\- ]{1,16}…[A-Za-z0-9_/.:;,\- ]{0,16}$`,
  // short parenthesized data annotations (units, filters): '(30d, this org)',
  // 'At (UTC)', 'Confidence (%)'
  String.raw`^\([A-Za-z0-9_,.%()/ -]{1,40}\)$`,
  // 'Word (annotation)' / 'Word (a) or Word (b)' data headers: 'Cost (USD)',
  // 'Slug (optional)', 'From (UTC)', 'Daily budget (cents)'
  String.raw`^[A-Za-z][A-Za-z0-9 ]{0,20} \([A-Za-z0-9_,.%()/ -]{1,40}\)( or [A-Za-z][A-Za-z0-9 ]{0,20} \([A-Za-z0-9_,.%()/ -]{1,40}\))?$`,
]

export default tseslint.config(
  { ignores: ['dist', 'node_modules'] },
  {
    files: ['**/*.{ts,tsx}'],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    plugins: {
      'react-hooks': reactHooks,
      i18next,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // The codebase predates the linter; these are enabled so NEW code is
      // held to the standard while the legacy patterns are tracked, not
      // blindly restyled in this change.
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    },
  },
  {
    files: GATED_I18N_FILES,
    rules: {
      'i18next/no-literal-string': [
        'error',
        {
          mode: 'all',
          words: { exclude: I18N_WORDS_EXCLUDE },
        },
      ],
    },
  },
)

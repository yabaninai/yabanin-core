import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

/**
 * Curated sidebar. Doc ids are derived from each file's path relative to the
 * docs root (../../docs), e.g. docs/lineage.md -> 'lineage',
 * docs/onprem/install-guide.md -> 'onprem/install-guide'.
 */
const sidebars: SidebarsConfig = {
  docs: [
    'intro',
    'quickstart',
    'index',
    'sso-oidc',
    'architecture',
    'audit',
    'demo',
    'evidence/agent-routing-case',
    'deployment-options',
    'compatibility',
    {
      type: 'category',
      label: 'Clients',
      collapsed: true,
      items: ['clients/sdk-versions', 'clients/codex', 'clients/claude-code', 'clients/opencode', 'clients/continue', 'clients/cline'],
    },
    'agent-readiness',
    'cli',
    'ci',
    'harness',
    'labels',
    'analytics',
    'shadow-mode',
    'evaluation',

    {
      type: 'category',
      label: 'Concepts',
      collapsed: false,
      items: ['cache', 'cache-architecture', 'cache-precision', 'gateway-performance', 'caching-compared', 'classifier', 'classifier-ml', 'lineage', 'pipeline', 'agent-governance', 'mcp-gateway', 'a2a-gateway', 'tool-policies', 'agentic-development'],
    },

    {
      type: 'category',
      label: 'Security',
      collapsed: false,
      items: ['security', 'security-owasp-llm', 'security-audit'],
    },

    {
      type: 'category',
      label: 'Sovereignty',
      collapsed: false,
      items: [
        'residency-packs',
        'sovereign-models',
        'multi-region',
        'onprem/install-guide',
        'onprem/offline-bundle',
        'onprem/airgap-checklist',
      ],
    },

    {
      type: 'category',
      label: 'Integrations',
      collapsed: true,
      items: ['byok', 'providers', 'opencode-integration'],
    },

    {
      type: 'category',
      label: 'Self-Host & Ops',
      collapsed: true,
      items: [
        'DEVELOPMENT',
        'ops',
        'ops/dns-setup',
        'ops/secrets-rotation',
        'ops/public-stand',
        'runbooks/production',
        'runbooks/incident-response',
        'runbooks/cache-incident',
        'runbooks/dr-drill',
        'runbooks/region-down',
        'runbooks/sev-classification',
        'runbooks/alerts',
        'runbooks/backup-restore-rehearsal',
        'runbooks/budget-reservations-alerts',
        'runbooks/onprem-upgrade',
        'runbooks/public-stand-deploy',
        'runbooks/post-mortem-template',
      ],
    },

    {
      type: 'category',
      label: 'Licensing',
      collapsed: true,
      items: ['license/pki-architecture', 'license/customer-setup'],
    },

    {
      type: 'category',
      label: 'Reference',
      collapsed: true,
      items: ['api/cache-admin-api'],
    },
  ],
};

export default sidebars;

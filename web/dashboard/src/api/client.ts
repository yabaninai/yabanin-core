//
// The implementation is split by domain (behavior-preserving extraction from
// the former monolithic client.ts):
//   ./http.ts      — fetchJSON/postJSON/listQuery, DEFAULT_PAGE_SIZE and the
//                    shared list types (the only hot file after the merge);
//   ./orgs.ts      — organizations;
//   ./keys.ts      — admin API keys;
//   ./agentKeys.ts — agent keys, profiles, agent budgets;
//   ./models.ts    — model catalog;
//   ./aliases.ts   — model aliases;
//   ./rules.ts     — routing rules + server-side preview;
//   ./analytics.ts — cost/shadow/latency/quality/task analytics, saved views;
//   ./requests.ts  — request list/detail/stats + tool-call report;
//   ./budgets.ts   — team budgets and org spend alerts;
//   ./credits.ts   — credits & billing;
//   ./audit.ts     — audit journal + preconditioned rollback (AF-09);
//   ./members.ts   — whitelists, teams, members, developers;
//   ./admins.ts    — administrator (root) users;
//   ./orgSettings.ts — org budget settings (NEXT-18f) + AUX-24 org settings;
//   ./mcp.ts ./a2a.ts — MCP/A2A registries;
//   ./toolPolicy.ts  — tool-call policies;
//   ./labels.ts      — label policy;
//   ./lineage.ts     — lineage + verify;
//   ./pricing.ts     — pricing CRUD.
// Every export keeps its historical name, so existing `from './client'`
// imports (pages, components, tests) stay valid; new code imports the domain
// module it needs. The HTTP lifecycle (CSRF, cancellation, 401 gate) lives in
// ./transport.

export { ApiError } from './transport.ts'
export type { RequestOptions } from './transport.ts'

export { fetchJSON, postJSON, listQuery, DEFAULT_PAGE_SIZE } from './http.ts'
export type { Paginated, ListSortParams } from './http.ts'

export * from './orgs.ts'
export * from './keys.ts'
export * from './agentKeys.ts'
export * from './models.ts'
export * from './aliases.ts'
export * from './rules.ts'
export * from './analytics.ts'
export * from './requests.ts'
export * from './budgets.ts'
export * from './credits.ts'
export * from './audit.ts'
export * from './members.ts'
export * from './admins.ts'
export * from './orgSettings.ts'
export * from './orgCaps.ts'
export * from './mcp.ts'
export * from './a2a.ts'
export * from './toolPolicy.ts'
export * from './policyDecisions.ts'
export * from './policyPipelines.ts'
export * from './clientConfig.ts'
export * from './labels.ts'
export * from './lineage.ts'
export * from './pricing.ts'

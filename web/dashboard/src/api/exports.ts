//
// Verified receiver inventory (this tree, 2026-10-03):
//   - Spend-alert webhook: GET/PATCH /api/organizations/{id}/spend-alert
//     (services/admin/handlers/router_billing.go, MustBeRoot group; the PATCH
//     overwrites BOTH fields, so callers always send the full pair). GET
//     reports threshold_usd, webhook_url, last_alert_at and the computed
//     spend_today. last_alert_at is the ONLY delivery signal: the API does
//     not track delivery success/failure, and there is no connection-test
//     endpoint, privacy-mode flag or sampling field.
//   - WORM lineage export: NO admin API — export/verify run via the trcli
//     binary (pkg/trcli/lineage_export.go). The page renders an honest
//     "not configured via API" state; nothing is invented.
//   - OTLP GenAI spans (RM-93) and SIEM (RM-92): not merged — planned rows
//     only, without data.
// A connection-test/receiver-config API is a needs-lease (see work record

export {
  getOrgSpendAlert,
  updateOrgSpendAlert,
  type OrgSpendAlertSettings,
  type OrgSpendAlertPatch,
} from './budgets.ts'

/** Same shape the dialog copy promises: an http(s) URL, non-empty. */
export function isValidWebhookUrl(value: string): boolean {
  return /^https?:\/\//.test(value)
}

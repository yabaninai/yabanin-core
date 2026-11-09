package adminstore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"time"

	"github.com/reireirei/yabanin/pkg/i18n"
	"github.com/reireirei/yabanin/pkg/webhooks"
)

// ---------------------------------------------------------------------------
// W-CAPS: org-level beta caps — the storage + delivery surface behind the
// admin caps endpoint (GET/PUT /api/orgs/{id}/caps) and the gateway's
// org-caps enforcement (pkg/gateway/ratelimit.go).
//
// A beta org gets DEFAULT ORG CAPS unless it overrides them: 60 RPM,
// 200k TPM and a hard $50/month budget (virtual credits, USD cents). NULL
// means "beta default" — never "unlimited" — so clearing an override always
// lands the org back on the safe beta limits. Overrides live in the
// org_caps table (migration 0004); a missing row is all-defaults.
//
// The budget-exceeded webhook reuses the spend-alert delivery infra
// (SpendAlertChecker's SSRF-guarded dialer lives in this package; the
// notifier below calls it — it does not modify the checker's loop).
// ---------------------------------------------------------------------------

// Beta defaults applied when the org has no override for a dimension.
const (
	// DefaultOrgCapsRPM is the beta per-org requests-per-minute default.
	DefaultOrgCapsRPM int64 = 60
	// DefaultOrgCapsTPM is the beta per-org tokens-per-minute default.
	DefaultOrgCapsTPM int64 = 200_000
	// DefaultOrgCapsMonthlyBudgetCents is the beta hard monthly budget:
	// $50.00 of virtual credits, in USD cents.
	DefaultOrgCapsMonthlyBudgetCents int64 = 5_000_000
)

// cap have NO beta default — an org gets them only by setting an override
// (effective 0 = the window is off, and the aggregate TPM default above keeps
// applying). A null override therefore means "off" for exactly these three
// dimensions; every other null still means "beta default".

// value orders the rejection policy only — on a 429 the Retry-After hint
// scales with it. It is not a preemptive scheduler.
const (
	DefaultAPIKeyPriority = 5
	MinAPIKeyPriority     = 0
	MaxAPIKeyPriority     = 9
)

// ValidAPIKeyPriority reports whether v is a settable key priority.
func ValidAPIKeyPriority(v int) bool {
	return v >= MinAPIKeyPriority && v <= MaxAPIKeyPriority
}

// OrgCaps settable bounds (mirrors the key_rate_limits sanity caps for
// rpm/tpm; the budget cap is a cent range that fits a sane beta budget).
const (
	MinOrgCapsValue           = MinRateLimitValue
	MaxOrgCapsValue           = MaxRateLimitValue
	MinOrgCapsBudgetCents     = int64(1)
	MaxOrgCapsBudgetCents     = int64(1_000_000_000) // $10M — a fat-finger guard
	OrgCapsMonthSpendMaxCents = int64(math.MaxInt64 / 2)
)

// OrgCaps is one stored org_caps row (migration 0004; split-token + per-key
// columns added in 0014). Every field nil = beta default for that dimension
type OrgCaps struct {
	OrgID string `json:"org_id"`
	// RPM overrides the beta requests-per-minute default (nil = default).
	RPM *int64 `json:"rpm"`
	// TPM overrides the beta tokens-per-minute default (nil = default).
	TPM *int64 `json:"tpm"`
	// MonthlyBudgetCents overrides the beta hard monthly budget (nil = default).
	MonthlyBudgetCents *int64 `json:"monthly_budget_cents"`
	// TPM (nil = off — no window for this dimension).
	InputTokensPerMin  *int64 `json:"input_tokens_per_min"`
	OutputTokensPerMin *int64 `json:"output_tokens_per_min"`
	// (nil = off).
	KeyTokensPerMin *int64 `json:"key_tokens_per_min"`

	UpdatedAt time.Time `json:"updated_at"`
}

// EffectiveOrgCaps is what the gateway enforces: the beta defaults merged
// with the org's overrides, plus the overrides themselves (the admin UI shows
// "override" vs "beta default" as distinct states). InputTPM/OutputTPM/
// KeyTPM have no beta default: 0 = the dimension is off.
type EffectiveOrgCaps struct {
	OrgID string `json:"org_id"`
	RPM   int64  `json:"rpm"`
	TPM   int64  `json:"tpm"`
	// MonthlyBudgetCents is the hard monthly budget in USD cents.
	MonthlyBudgetCents int64 `json:"monthly_budget_cents"`
	// Split token caps (0 = off — no window is enforced).
	InputTPM  int64 `json:"input_tokens_per_min"`
	OutputTPM int64 `json:"output_tokens_per_min"`
	// KeyTPM is the per-API-key TPM cap for every key of the org (0 = off).
	KeyTPM int64 `json:"key_tokens_per_min"`

	// MonthSpendCents is the measured month-to-date spend in USD cents
	// (0 when the caller did not ask for spend — the gateway path never
	// fabricates it).
	MonthSpendCents int64 `json:"month_spend_cents"`

	RPMOverride         *int64 `json:"rpm_override"`
	TPMOverride         *int64 `json:"tpm_override"`
	BudgetOverrideCents *int64 `json:"monthly_budget_override_cents"`
	InputTPMOverride    *int64 `json:"input_tokens_per_min_override"`
	OutputTPMOverride   *int64 `json:"output_tokens_per_min_override"`
	KeyTPMOverride      *int64 `json:"key_tokens_per_min_override"`
}

// OrgCapsUpdate is a PUT payload: every pointer nil = clear the override
// (back to the beta default, or off for the split dimensions); a value must
// pass ValidateOrgCapsUpdate.
type OrgCapsUpdate struct {
	RPM                *int64
	TPM                *int64
	MonthlyBudgetCents *int64
	InputTPM           *int64
	OutputTPM          *int64
	KeyTPM             *int64
}

// ValidateOrgCapsUpdate checks one update in memory (the DB CHECKs re-check).
func ValidateOrgCapsUpdate(u OrgCapsUpdate) error {
	for name, v := range map[string]*int64{
		"rpm":                   u.RPM,
		"tpm":                   u.TPM,
		"input_tokens_per_min":  u.InputTPM,
		"output_tokens_per_min": u.OutputTPM,
		"key_tokens_per_min":    u.KeyTPM,
	} {
		if v != nil && (*v < MinOrgCapsValue || *v > MaxOrgCapsValue) {
			return fmt.Errorf("%s must be between %d and %d, or null for the beta default",
				name, MinOrgCapsValue, MaxOrgCapsValue)
		}
	}
	if u.MonthlyBudgetCents != nil &&
		(*u.MonthlyBudgetCents < MinOrgCapsBudgetCents || *u.MonthlyBudgetCents > MaxOrgCapsBudgetCents) {
		return fmt.Errorf("monthly_budget_cents must be between %d and %d, or null for the beta default",
			MinOrgCapsBudgetCents, MaxOrgCapsBudgetCents)
	}
	return nil
}

// GetOrgCaps returns the raw org_caps row; no row is ErrNotFound (distinct
// from an all-defaults org, whose EffectiveOrgCaps still resolves).
func (s *Store) GetOrgCaps(ctx context.Context, orgID string) (*OrgCaps, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	var c OrgCaps
	err := s.db.QueryRow(ctx, `
		SELECT org_id, rpm, tpm, monthly_budget_cents,
		       input_tokens_per_min, output_tokens_per_min, key_tokens_per_min,
		       updated_at
		FROM org_caps WHERE org_id = $1`, orgID,
	).Scan(&c.OrgID, &c.RPM, &c.TPM, &c.MonthlyBudgetCents,
		&c.InputTokensPerMin, &c.OutputTokensPerMin, &c.KeyTokensPerMin, &c.UpdatedAt)
	if IsNotFound(err) {
		return nil, fmt.Errorf("org caps not found: %s: %w", orgID, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get org caps: %w", err)
	}
	return &c, nil
}

// EffectiveOrgCaps merges the beta defaults with the org's overrides. An
// unknown org is ErrNotFound — caps exist only for orgs that exist.
func (s *Store) EffectiveOrgCaps(ctx context.Context, orgID string) (*EffectiveOrgCaps, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	var (
		rpm, tpm, budget            *int64
		inputTPM, outputTPM, keyTPM *int64
		exists                      bool
	)
	err := s.db.QueryRow(ctx, `
		SELECT o.id IS NOT NULL, c.rpm, c.tpm, c.monthly_budget_cents,
		       c.input_tokens_per_min, c.output_tokens_per_min, c.key_tokens_per_min
		FROM organizations o
		LEFT JOIN org_caps c ON c.org_id = o.id
		WHERE o.id = $1`, orgID,
	).Scan(&exists, &rpm, &tpm, &budget, &inputTPM, &outputTPM, &keyTPM)
	if IsNotFound(err) {
		return nil, fmt.Errorf("org not found: %s: %w", orgID, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("resolve org caps: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("org not found: %s: %w", orgID, ErrNotFound)
	}
	eff := &EffectiveOrgCaps{
		OrgID:               orgID,
		RPM:                 DefaultOrgCapsRPM,
		TPM:                 DefaultOrgCapsTPM,
		MonthlyBudgetCents:  DefaultOrgCapsMonthlyBudgetCents,
		RPMOverride:         rpm,
		TPMOverride:         tpm,
		BudgetOverrideCents: budget,
		InputTPMOverride:    inputTPM,
		OutputTPMOverride:   outputTPM,
		KeyTPMOverride:      keyTPM,
	}
	if rpm != nil {
		eff.RPM = *rpm
	}
	if tpm != nil {
		eff.TPM = *tpm
	}
	if budget != nil {
		eff.MonthlyBudgetCents = *budget
	}
	if inputTPM != nil {
		eff.InputTPM = *inputTPM
	}
	if outputTPM != nil {
		eff.OutputTPM = *outputTPM
	}
	if keyTPM != nil {
		eff.KeyTPM = *keyTPM
	}
	return eff, nil
}

// UpdateOrgCaps upserts the org's overrides; nil fields CLEAR the override
// for that dimension (back to the beta default). An unknown org is
// ErrNotFound — the INSERT only fires when the organization row exists, so
// no orphan caps row can be stored.
func (s *Store) UpdateOrgCaps(ctx context.Context, orgID string, u OrgCapsUpdate) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	if err := ValidateOrgCapsUpdate(u); err != nil {
		return fmt.Errorf("update org caps: %w", err)
	}
	tag, err := s.db.Exec(ctx, `
		INSERT INTO org_caps (org_id, rpm, tpm, monthly_budget_cents,
		                      input_tokens_per_min, output_tokens_per_min, key_tokens_per_min,
		                      updated_at)
		SELECT $1, $2, $3, $4, $5, $6, $7, now()
		FROM organizations o WHERE o.id = $1
		ON CONFLICT (org_id) DO UPDATE SET
			rpm = EXCLUDED.rpm,
			tpm = EXCLUDED.tpm,
			monthly_budget_cents = EXCLUDED.monthly_budget_cents,
			input_tokens_per_min = EXCLUDED.input_tokens_per_min,
			output_tokens_per_min = EXCLUDED.output_tokens_per_min,
			key_tokens_per_min = EXCLUDED.key_tokens_per_min,
			updated_at = now()`,
		orgID, u.RPM, u.TPM, u.MonthlyBudgetCents, u.InputTPM, u.OutputTPM, u.KeyTPM,
	)
	if err != nil {
		return fmt.Errorf("update org caps: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("org not found: %s: %w", orgID, ErrNotFound)
	}
	return nil
}

// OrgMonthSpendCents returns the org's month-to-date spend in USD cents
// (UTC month boundary, shadow traffic excluded — the same accounting window
// the spend alerts use). Cents keep the enforcement comparison integer.
func (s *Store) OrgMonthSpendCents(ctx context.Context, orgID string) (int64, error) {
	if s.db == nil {
		return 0, fmt.Errorf("database not available")
	}
	now := time.Now().UTC()
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	var usd float64
	if err := s.db.QueryRow(ctx, `
		SELECT COALESCE(SUM(cost_in_usd), 0) FROM request_logs
		WHERE org_id::text = $1 AND created_at >= $2
		  AND COALESCE(ab_group, '') <> 'shadow'`,
		orgID, monthStart,
	).Scan(&usd); err != nil {
		return 0, fmt.Errorf("org month spend: %w", err)
	}
	cents := int64(math.Round(usd * 100))
	if cents < 0 {
		cents = 0
	}
	if cents > OrgCapsMonthSpendMaxCents {
		cents = OrgCapsMonthSpendMaxCents
	}
	return cents, nil
}

// OrgAlertTarget names the webhook destination a budget-exceeded event goes
// to: the org's existing spend-alert webhook (reused, not duplicated), with
// the org's presentation currency for the payload label.
type OrgAlertTarget struct {
	Name       string
	WebhookURL string
	Currency   string
}

// OrgAlertTarget resolves the org's spend-alert webhook destination. An org
// without a configured webhook returns an empty URL (the caller skips
// delivery) — that is not an error.
func (s *Store) OrgAlertTarget(ctx context.Context, orgID string) (OrgAlertTarget, error) {
	if s.db == nil {
		return OrgAlertTarget{}, fmt.Errorf("database not available")
	}
	var t OrgAlertTarget
	err := s.db.QueryRow(ctx, `
		SELECT name, COALESCE(spend_alert_webhook_url, ''), COALESCE(currency, 'USD')
		FROM organizations WHERE id = $1`, orgID,
	).Scan(&t.Name, &t.WebhookURL, &t.Currency)
	if IsNotFound(err) {
		return OrgAlertTarget{}, fmt.Errorf("org not found: %s: %w", orgID, ErrNotFound)
	}
	if err != nil {
		return OrgAlertTarget{}, fmt.Errorf("org alert target: %w", err)
	}
	return t, nil
}

// BudgetWebhookNotifier delivers budget_exceeded webhooks to an org's
// configured spend-alert webhook. It REUSES the spend-alert delivery infra
// in this package (the SSRF-guarded dialer) by calling it — the checker's
// background loop is untouched.
type BudgetWebhookNotifier struct {
	httpClient *http.Client
	log        *slog.Logger
}

// NewBudgetWebhookNotifier wires the notifier over the same guarded dialer
// the SpendAlertChecker posts through (private/loopback/link-local targets
// and DNS rebinding are rejected at connect time).
func NewBudgetWebhookNotifier(log *slog.Logger) *BudgetWebhookNotifier {
	if log == nil {
		log = slog.Default()
	}
	return &BudgetWebhookNotifier{
		httpClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{DialContext: spendAlertDialer()},
		},
		log: log.With("component", "budget-webhook-notifier"),
	}
}

// BudgetExceeded posts one budget_exceeded event. webhookURL empty = nothing
// configured = a no-op success. A rejected (SSRF-guard) or failing delivery
// is an error for the caller to log — the 402 denial itself is unaffected.
func (n *BudgetWebhookNotifier) BudgetExceeded(ctx context.Context, orgID string, t OrgAlertTarget, budgetCents, spendCents int64) error {
	if t.WebhookURL == "" {
		return nil
	}
	// Same SSRF guard the spend-alert webhook path runs (defense in depth —
	// the dialer re-checks the resolved IP at connect time).
	if err := webhooks.ValidateURLWithContext(ctx, t.WebhookURL, false); err != nil {
		return fmt.Errorf("budget webhook url rejected: %w", err)
	}
	cur := i18n.Currency(t.Currency)
	payload := map[string]interface{}{
		"event":                "budget_exceeded",
		"org_id":               orgID,
		"org_name":             t.Name,
		"monthly_budget_cents": budgetCents,
		"spend_cents":          spendCents,
		"currency":             cur,
		"timestamp":            time.Now().UTC().Format(time.RFC3339),
		"message": fmt.Sprintf("Monthly budget for %s reached %s %.2f (budget: %s %.2f)",
			t.Name, cur, float64(spendCents)/100, cur, float64(budgetCents)/100),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal budget webhook: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build budget webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("budget webhook request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("budget webhook returned status %d", resp.StatusCode)
	}
	n.log.Info("budget_exceeded webhook delivered", "org_id", orgID, "status", resp.StatusCode)
	return nil
}

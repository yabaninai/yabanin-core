package adminstore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/reireirei/yabanin/pkg/i18n"
	"github.com/reireirei/yabanin/pkg/ssrf"
	"github.com/reireirei/yabanin/pkg/webhooks"
)

// SpendAlertChecker runs a background loop that checks org spend against
// thresholds and fires webhook alerts when exceeded.
type SpendAlertChecker struct {
	store         *Store
	httpClient    *http.Client
	checkInterval time.Duration
	alertCooldown time.Duration
	log           *slog.Logger
}

// NewSpendAlertChecker creates a background checker for spend alerts.
func NewSpendAlertChecker(store *Store, log *slog.Logger) *SpendAlertChecker {
	return &SpendAlertChecker{
		store: store,
		// The dialer re-validates the resolved IP at connect time (see
		// spendAlertDialer) so a webhook URL cannot reach private,
		// loopback, or link-local (cloud-metadata) targets — even via a
		// domain that re-resolves after validation (DNS rebinding).
		httpClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{DialContext: spendAlertDialer()},
		},
		checkInterval: 5 * time.Minute,
		alertCooldown: 6 * time.Hour,
		log:           log.With("component", "spend-alert-checker"),
	}
}

// Run starts the background check loop. Blocks until ctx is cancelled.
func (c *SpendAlertChecker) Run(ctx context.Context) {
	c.log.Info("spend alert checker started", "interval", c.checkInterval)

	ticker := time.NewTicker(c.checkInterval)
	defer ticker.Stop()

	// Run immediately on start.
	c.checkOnce(ctx)

	for {
		select {
		case <-ticker.C:
			c.checkOnce(ctx)
		case <-ctx.Done():
			c.log.Info("spend alert checker stopped")
			return
		}
	}
}

func (c *SpendAlertChecker) checkOnce(ctx context.Context) {
	orgs, err := c.store.ListOrgsWithSpendAlerts(ctx)
	if err != nil {
		c.log.Error("failed to list orgs with spend alerts", "error", err)
		return
	}

	if len(orgs) == 0 {
		return
	}

	now := time.Now().UTC()

	for _, org := range orgs {
		// Check cooldown — skip if alerted within the cooldown window.
		if org.LastAlertAt != nil && now.Sub(*org.LastAlertAt) < c.alertCooldown {
			continue
		}

		spend, err := c.store.SpendToday(ctx, org.ID)
		if err != nil {
			c.log.Error("failed to get spend", "org_id", org.ID, "error", err)
			continue
		}

		if spend < org.ThresholdUSD {
			continue
		}

		c.log.Info("spend threshold exceeded",
			"org_id", org.ID,
			"org_name", org.Name,
			"spend", spend,
			"threshold", org.ThresholdUSD,
		)

		// Fire webhook if configured.
		if org.WebhookURL != "" {
			if err := c.fireWebhook(ctx, org, spend); err != nil {
				c.log.Error("webhook delivery failed", "org_id", org.ID, "error", err)
			}
		}

		// Update last alert time for cooldown.
		if err := c.store.UpdateLastAlertAt(ctx, org.ID, now); err != nil {
			c.log.Error("failed to update last alert time", "org_id", org.ID, "error", err)
		}
	}
}

func (c *SpendAlertChecker) fireWebhook(ctx context.Context, org SpendAlertOrg, spend float64) error {
	// SSRF guard: reject webhook URLs that target private/loopback/link-local
	// (cloud-metadata) space or non-HTTPS. Defense in depth — the dialer below
	// re-checks the IP at connect time to close the DNS-rebinding gap.
	if err := webhooks.ValidateURLWithContext(ctx, org.WebhookURL, false); err != nil {
		return fmt.Errorf("spend alert webhook url rejected: %w", err)
	}

	// currency is the org's presentation code (I18N-11). The amount itself is
	// still USD-denominated (stored money is USD); the code tells the receiver
	// how to label it. i18n.Currency normalizes + defaults to USD.
	cur := i18n.Currency(org.Currency)
	payload := map[string]interface{}{
		"event":       "spend_alert",
		"org_id":      org.ID,
		"org_name":    org.Name,
		"spend_today": spend,
		"threshold":   org.ThresholdUSD,
		"currency":    cur,
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"message":     fmt.Sprintf("Daily spend for %s reached %s %.2f (threshold: %s %.2f)", org.Name, cur, spend, cur, org.ThresholdUSD),
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", org.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("webhook request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	c.log.Info("spend alert webhook delivered", "org_id", org.ID, "status", resp.StatusCode)
	return nil
}

// spendAlertDialer returns the webhook delivery DialContext: the shared
// ssrf.NewGuardedDialer, which resolves the hostname itself, rejects every
// reserved answer at connect time (loopback, link-local/metadata, private,
// CGNAT, multicast), and dials the pinned verified IP — closing the
// DNS-rebinding gap a validate-then-dial design leaves open.
func spendAlertDialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	return ssrf.NewGuardedDialer(ssrf.DialerOptions{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	})
}

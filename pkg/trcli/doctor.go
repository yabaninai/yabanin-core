package trcli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/spf13/cobra"
)

// doctorCheckTimeout bounds each individual health probe. A var (not a
// const) so tests can shorten it instead of waiting out real seconds.
var doctorCheckTimeout = 5 * time.Second

// resolveGatewayURL returns only an explicitly configured target. Doctor must
// not infer consent to contact a hosted or loopback service from its defaults.
func resolveGatewayURL(flagValue string) string {
	if strings.TrimSpace(flagValue) != "" {
		return strings.TrimRight(strings.TrimSpace(flagValue), "/")
	}
	if v := strings.TrimSpace(os.Getenv("YABANIN_GATEWAY_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return ""
}

// resolveAdminURL returns only an explicitly configured target.
func resolveAdminURL(flagValue string) string {
	if strings.TrimSpace(flagValue) != "" {
		return strings.TrimRight(strings.TrimSpace(flagValue), "/")
	}
	if v := strings.TrimSpace(os.Getenv("YABANIN_ADMIN_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return ""
}

func doctorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose connectivity to explicitly configured gateway and admin targets",
		RunE: func(cmd *cobra.Command, _ []string) error {
			w := cmd.OutOrStdout()
			_, _ = fmt.Fprintln(w, "Yabanin Doctor")
			_, _ = fmt.Fprintln(w, "==============")

			offline, _ := cmd.Flags().GetBool("offline")
			if offline {
				writeSkipped(w, "Gateway", "offline")
				writeSkipped(w, "Admin panel", "offline")
				return errors.New("health checks skipped: offline")
			}

			baseURL, _ := cmd.Flags().GetString("base-url")
			adminURL, _ := cmd.Flags().GetString("admin-url")
			targets := []struct {
				name string
				base string
				path string
			}{
				{"Gateway", resolveGatewayURL(baseURL), "/healthz"},
				{"Admin panel", resolveAdminURL(adminURL), "/health"},
			}

			client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			}}
			selected := 0
			canceled := false
			healthy := true
			for index, target := range targets {
				if canceled {
					for _, remaining := range targets[index:] {
						reason := "no target configured"
						if remaining.base != "" {
							reason = "canceled before request"
						}
						writeSkipped(w, remaining.name, reason)
					}
					break
				}
				if target.base == "" {
					writeSkipped(w, target.name, "no target configured")
					continue
				}
				selected++
				url, err := scopedHealthURL(target.base, target.path)
				result := healthOutcome{}
				if err != nil {
					result.diagnosis = "invalid health URL"
				} else {
					result = probeHealth(cmd.Context(), client, url)
				}
				if result.canceled {
					canceled = true
				}
				if !result.ok {
					healthy = false
				}
				mark := "✗"
				if result.ok {
					mark = "✓"
				}
				_, _ = fmt.Fprintf(w, "%s %s: %s\n", mark, target.name, result.diagnosis)
			}

			if selected == 0 {
				return errors.New("no health targets configured")
			}
			if canceled {
				return fmt.Errorf("doctor canceled before completing: %w", cmd.Context().Err())
			}
			if healthy {
				_, _ = fmt.Fprintln(w, "\n✓ All configured checks healthy")
				return nil
			}
			return errors.New("configured health checks failed")
		},
	}
	cmd.Flags().Bool("offline", false, "Skip all health requests")
	return cmd
}

func writeSkipped(w io.Writer, name, reason string) {
	_, _ = fmt.Fprintf(w, "– %s: skipped (health unknown; %s)\n", name, reason)
}

// scopedHealthURL validates the operator-provided base URL and adds the
// service-specific health path without discarding an existing base path.
func scopedHealthURL(base, healthPath string) (string, error) {
	if strings.ContainsFunc(base, unicode.IsControl) {
		return "", errors.New("invalid URL")
	}
	u, err := url.Parse(base)
	if err != nil || u == nil || u.Opaque != "" || u.Host == "" || u.Hostname() == "" {
		return "", errors.New("invalid URL")
	}
	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return "", errors.New("invalid URL")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(base, "#") || u.Fragment != "" || u.RawFragment != "" || strings.ContainsFunc(u.Path, unicode.IsControl) {
		return "", errors.New("invalid URL")
	}
	if strings.HasSuffix(u.Host, ":") {
		return "", errors.New("invalid URL")
	}
	if port := u.Port(); port != "" {
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return "", errors.New("invalid URL")
		}
	}
	// Preserve escaped path separators in a configured proxy/tenant prefix.
	// Re-encoding only Path would turn %2F into / and change the selected route.
	escapedPath := strings.TrimRight(u.EscapedPath(), "/") + healthPath
	u.Path, err = url.PathUnescape(escapedPath)
	if err != nil {
		return "", errors.New("invalid URL")
	}
	u.RawPath = escapedPath
	return u.String(), nil
}

// healthOutcome is one probe's verdict. A canceled probe is distinct from a
// timeout: cancellation means the operator interrupted the command, not that
// the service is down.
type healthOutcome struct {
	ok        bool
	canceled  bool
	diagnosis string
}

// probeHealth GETs the health endpoint once and maps the outcome to a
// distinct, sanitized diagnosis. The URL and transport error are never shown.
func probeHealth(ctx context.Context, client *http.Client, url string) healthOutcome {
	ctx, cancel := context.WithTimeout(ctx, doctorCheckTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return healthOutcome{diagnosis: "invalid health URL"}
	}
	resp, err := client.Do(req)
	if err != nil {
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			return healthOutcome{diagnosis: fmt.Sprintf("unreachable: timeout after %s", doctorCheckTimeout)}
		case errors.Is(err, context.Canceled):
			return healthOutcome{canceled: true, diagnosis: "check canceled before the service answered"}
		default:
			return healthOutcome{diagnosis: "unreachable: connection failed"}
		}
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
		return healthOutcome{ok: true, diagnosis: "healthy"}
	case http.StatusUnauthorized:
		return healthOutcome{diagnosis: "reachable but requires auth (HTTP 401); health not confirmed"}
	case http.StatusServiceUnavailable:
		return healthOutcome{diagnosis: "reports unhealthy (HTTP 503)"}
	default:
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return healthOutcome{diagnosis: fmt.Sprintf("redirect refused (HTTP %d)", resp.StatusCode)}
		}
		return healthOutcome{diagnosis: fmt.Sprintf("unexpected HTTP %d", resp.StatusCode)}
	}
}

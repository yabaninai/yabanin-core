package trcli

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runDoctor executes `yb doctor` with a capture buffer for BOTH writers so
// full-output capture is testable (TP-08). It rides the command's default
// context; the cancellation test below sets its own.
func runDoctor(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := RootCommand()
	root.SilenceErrors = true
	root.SilenceUsage = true
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(append([]string{"doctor"}, args...))
	err := root.Execute()
	return buf.String(), err
}

func okHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
}

type doctorRoundTripper func(*http.Request) (*http.Response, error)

func (f doctorRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDoctor_NoImplicitTargetsMakesNoRequests(t *testing.T) {
	t.Setenv("YABANIN_GATEWAY_URL", "")
	t.Setenv("YABANIN_ADMIN_URL", "")
	t.Setenv("YABANIN_DEPLOY_MODE", "")
	t.Setenv("YABANIN_REGION", "")

	previousTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previousTransport })
	var requests []string
	http.DefaultTransport = doctorRoundTripper(func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r.URL.Scheme+"://"+r.URL.Host+r.URL.Path)
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody, Request: r}, nil
	})

	out, err := runDoctor(t)
	require.Empty(t, requests, "doctor without explicit targets must not make requests")
	require.Error(t, err)
	assert.Contains(t, out, "health unknown")
	assert.NotContains(t, out, "All services healthy")
}

func TestDoctor_NoImplicitOnPremTargetMakesNoRequests(t *testing.T) {
	clearDoctorTargetEnv(t)
	t.Setenv("YABANIN_DEPLOY_MODE", "onprem")
	previousTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previousTransport })
	var requests int
	http.DefaultTransport = doctorRoundTripper(func(r *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody, Request: r}, nil
	})

	out, err := runDoctor(t)
	require.Error(t, err)
	assert.Zero(t, requests)
	assert.Contains(t, out, "health unknown")
}

func TestDoctor_OfflineSkipsMalformedFlagAndEnvTargets(t *testing.T) {
	t.Setenv("YABANIN_GATEWAY_URL", "https://env-user:env-secret@invalid.test/?secret=env")
	t.Setenv("YABANIN_ADMIN_URL", "also not a URL")
	previousTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previousTransport })
	var requests int
	http.DefaultTransport = doctorRoundTripper(func(r *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody, Request: r}, nil
	})

	out, err := runDoctor(t, "--offline", "--base-url", "https://flag-user:flag-secret@invalid.test/?secret=flag", "--admin-url", "not a URL")
	require.Error(t, err)
	assert.Zero(t, requests)
	assert.Contains(t, out, "health unknown; offline")
	assert.NotContains(t, out, "All configured checks healthy")
	for _, secret := range []string{"flag-secret", "env-secret", "secret=flag", "secret=env", "invalid.test"} {
		assert.NotContains(t, out, secret)
	}
}

func TestDoctor_GatewayOnlyChecksSelectedTargetOnce(t *testing.T) {
	clearDoctorTargetEnv(t)
	var gatewayHits int
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gatewayHits++
		assert.Equal(t, "/healthz", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer gateway.Close()

	out, err := runDoctor(t, "--base-url", gateway.URL)
	require.NoError(t, err)
	assert.Equal(t, 1, gatewayHits)
	assert.Contains(t, out, "Gateway: healthy")
	assert.Contains(t, out, "Admin panel: skipped (health unknown; no target configured)")
	assert.Contains(t, out, "All configured checks healthy")
}

func TestDoctor_AdminOnlyChecksSelectedTargetOnce(t *testing.T) {
	clearDoctorTargetEnv(t)
	var adminHits int
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adminHits++
		assert.Equal(t, "/health", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer admin.Close()
	out, err := runDoctor(t, "--admin-url", admin.URL)
	require.NoError(t, err)
	assert.Equal(t, 1, adminHits)
	assert.Contains(t, out, "Gateway: skipped (health unknown; no target configured)")
	assert.Contains(t, out, "Admin panel: healthy")
}

func TestDoctor_FlagOverridesEnvironmentAndPreservesBasePath(t *testing.T) {
	clearDoctorTargetEnv(t)
	var flagHits, envHits int
	flagServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flagHits++
		assert.Equal(t, "/prefix/healthz", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer flagServer.Close()
	envServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		envHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer envServer.Close()
	t.Setenv("YABANIN_GATEWAY_URL", envServer.URL)

	_, err := runDoctor(t, "--base-url", flagServer.URL+"/prefix/")
	require.NoError(t, err)
	assert.Equal(t, 1, flagHits)
	assert.Zero(t, envHits)
}

func TestDoctor_InvalidURLDoesNotLeakInput(t *testing.T) {
	clearDoctorTargetEnv(t)
	unsafe := (&url.URL{
		Scheme:   "https",
		User:     url.UserPassword("example-user", "fixture-value"),
		Host:     "redaction.invalid",
		RawQuery: url.Values{"query": {"private-value"}}.Encode(),
	}).String()
	out, err := runDoctor(t, "--base-url", unsafe)
	require.Error(t, err)
	assert.Contains(t, out, "invalid health URL")
	for _, marker := range []string{"example-user", "fixture-value", "redaction.invalid", "query=private-value"} {
		assert.NotContains(t, out, marker)
	}
}

func TestDoctor_InvalidURLFormsAreRejectedWithoutDialing(t *testing.T) {
	clearDoctorTargetEnv(t)
	for _, target := range []string{
		"ftp://example.test",
		"http:///missing-host",
		"http://example.test:99999",
		"http://example.test/path?query=secret",
		"http://example.test/path#fragment",
		"http://example.test/#",
		"http://example.test/with\ncontrol",
	} {
		t.Run(target, func(t *testing.T) {
			previousTransport := http.DefaultTransport
			t.Cleanup(func() { http.DefaultTransport = previousTransport })
			var requests int
			http.DefaultTransport = doctorRoundTripper(func(r *http.Request) (*http.Response, error) {
				requests++
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody, Request: r}, nil
			})
			out, err := runDoctor(t, "--base-url", target)
			require.Error(t, err)
			assert.Zero(t, requests)
			assert.Contains(t, out, "invalid health URL")
			assert.NotContains(t, out, target)
		})
	}
}

func TestDoctor_TransportErrorDoesNotLeakDetails(t *testing.T) {
	clearDoctorTargetEnv(t)
	previousTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previousTransport })
	http.DefaultTransport = doctorRoundTripper(func(r *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("dial failure for %s with credential marker", r.URL.String())
	})

	out, err := runDoctor(t, "--base-url", "http://sensitive.example:1234")
	require.Error(t, err)
	assert.Contains(t, out, "unreachable: connection failed")
	assert.NotContains(t, out, "sensitive.example")
	assert.NotContains(t, out, "1234")
	assert.NotContains(t, out, "credential marker")
}

func TestDoctor_RedirectIsNotFollowed(t *testing.T) {
	clearDoctorTargetEnv(t)
	var destinationHits int
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		destinationHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer destination.Close()
	var redirectHits int
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectHits++
		w.Header().Set("Location", destination.URL+"/healthz")
		w.WriteHeader(http.StatusFound)
	}))
	defer redirect.Close()

	out, err := runDoctor(t, "--base-url", redirect.URL)
	require.Error(t, err)
	assert.Equal(t, 1, redirectHits)
	assert.Zero(t, destinationHits)
	assert.Contains(t, out, "redirect refused (HTTP 302)")
	assert.NotContains(t, out, destination.URL)
}

func TestDoctor_NoTargetsIsUnknownAndNotHealthy(t *testing.T) {
	clearDoctorTargetEnv(t)
	out, err := runDoctor(t)
	require.Error(t, err)
	assert.Contains(t, out, "Gateway: skipped (health unknown; no target configured)")
	assert.Contains(t, out, "Admin panel: skipped (health unknown; no target configured)")
	assert.NotContains(t, out, "All configured checks healthy")
}

func clearDoctorTargetEnv(t *testing.T) {
	t.Helper()
	t.Setenv("YABANIN_GATEWAY_URL", "")
	t.Setenv("YABANIN_ADMIN_URL", "")
	t.Setenv("YABANIN_DEPLOY_MODE", "")
	t.Setenv("YABANIN_REGION", "")
}

func TestDoctor_AllHealthy_CapturedOutputAndDistinctPaths(t *testing.T) {
	var gwPath, adPath string
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gwPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer gw.Close()
	ad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer ad.Close()

	out, err := runDoctor(t, "--base-url", gw.URL, "--admin-url", ad.URL)
	require.NoError(t, err)
	// The real endpoints: gateway /healthz, admin /health (TP-08).
	assert.Equal(t, "/healthz", gwPath)
	assert.Equal(t, "/health", adPath)
	// Everything lands in the capture writer — no stray fmt.Println.
	assert.Contains(t, out, "Yabanin Doctor")
	assert.Contains(t, out, "✓ Gateway: healthy")
	assert.Contains(t, out, "✓ Admin panel: healthy")
	assert.Contains(t, out, "✓ All configured checks healthy")
}

func TestDoctor_AdminReportsUnhealthy503(t *testing.T) {
	gw := httptest.NewServer(okHandler())
	defer gw.Close()
	ad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ad.Close()

	out, err := runDoctor(t, "--base-url", gw.URL, "--admin-url", ad.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "configured health checks failed")
	assert.Contains(t, out, "✗ Admin panel: reports unhealthy (HTTP 503)")
	assert.NotContains(t, out, "All configured checks healthy")
}

func TestDoctor_AuthRequired401_DistinctFromOutage(t *testing.T) {
	gw := httptest.NewServer(okHandler())
	defer gw.Close()
	ad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ad.Close()

	out, err := runDoctor(t, "--base-url", gw.URL, "--admin-url", ad.URL)
	require.Error(t, err)
	assert.Contains(t, out, "reachable but requires auth (HTTP 401); health not confirmed")
	assert.NotContains(t, out, "unreachable")
}

func TestDoctor_Timeout_DiagnosedAsTimeout(t *testing.T) {
	old := doctorCheckTimeout
	doctorCheckTimeout = 60 * time.Millisecond
	t.Cleanup(func() { doctorCheckTimeout = old })

	var gatewayHits, adminHits atomic.Int32
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		gatewayHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer gw.Close()
	// Hold each request until its client goes away (probe timeout) — the
	// request context release also lets ad.Close() finish cleanly.
	ad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adminHits.Add(1)
		<-r.Context().Done()
	}))
	defer ad.Close()

	out, err := runDoctor(t, "--base-url", gw.URL, "--admin-url", ad.URL)
	require.Error(t, err)
	assert.Contains(t, out, "✗ Admin panel: unreachable: timeout after 60ms")
	assert.Contains(t, out, "✓ Gateway: healthy")
	assert.EqualValues(t, 1, gatewayHits.Load())
	assert.EqualValues(t, 1, adminHits.Load(), "a timed-out health request must not be retried")
}

func TestDoctor_CancellationIsDistinctFromTimeout(t *testing.T) {
	clearDoctorTargetEnv(t)
	var gatewayHits, adminHits atomic.Int32
	started := make(chan struct{})
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gatewayHits.Add(1)
		close(started)
		<-r.Context().Done()
	}))
	defer gw.Close()
	ad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adminHits.Add(1)
		<-r.Context().Done()
	}))
	defer ad.Close()

	ctx, cancel := context.WithCancel(t.Context())
	root := RootCommand()
	root.SilenceErrors = true
	root.SilenceUsage = true
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetContext(ctx)
	root.SetArgs([]string{"doctor", "--base-url", gw.URL, "--admin-url", ad.URL})
	done := make(chan error, 1)
	go func() { done <- root.ExecuteContext(ctx) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("gateway probe did not start")
	}
	cancel()
	err := <-done
	require.Error(t, err)
	assert.Contains(t, err.Error(), "doctor canceled")
	assert.Contains(t, buf.String(), "check canceled before the service answered")
	assert.NotContains(t, buf.String(), "timeout")
	assert.EqualValues(t, 1, gatewayHits.Load())
	assert.Zero(t, adminHits.Load(), "cancellation must not continue to another target")
}

func TestDoctor_EnvURLsAreActuallyChecked(t *testing.T) {
	var gwHit, adHit bool
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gwHit = r.URL.Path == "/healthz"
		w.WriteHeader(http.StatusOK)
	}))
	defer gw.Close()
	ad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adHit = r.URL.Path == "/health"
		w.WriteHeader(http.StatusOK)
	}))
	defer ad.Close()

	t.Setenv("YABANIN_GATEWAY_URL", gw.URL)
	t.Setenv("YABANIN_ADMIN_URL", ad.URL)

	out, err := runDoctor(t)
	require.NoError(t, err)
	assert.True(t, gwHit, "custom env gateway URL must actually be probed")
	assert.True(t, adHit, "custom env admin URL must actually be probed")
	assert.Contains(t, out, "✓ All configured checks healthy")
}

func TestDoctor_URLResolutionOrder(t *testing.T) {
	clearDoctorTargetEnv(t)
	t.Run("flag wins over env", func(t *testing.T) {
		t.Setenv("YABANIN_ADMIN_URL", "http://from-env:1")
		assert.Equal(t, "http://from-flag:2", resolveAdminURL("http://from-flag:2"))
	})
	t.Run("env wins over default", func(t *testing.T) {
		t.Setenv("YABANIN_ADMIN_URL", "http://from-env:1/")
		assert.Equal(t, "http://from-env:1", resolveAdminURL(""))
	})
	t.Run("admin default matches the admin client", func(t *testing.T) {
		assert.Empty(t, resolveAdminURL(""))
	})
	t.Run("gateway onprem default", func(t *testing.T) {
		t.Setenv("YABANIN_DEPLOY_MODE", "onprem")
		assert.Empty(t, resolveGatewayURL(""))
	})
	t.Run("gateway cloud default", func(t *testing.T) {
		assert.Empty(t, resolveGatewayURL(""))
	})
	t.Run("gateway env wins over deploy default", func(t *testing.T) {
		t.Setenv("YABANIN_GATEWAY_URL", "http://gw-env:3")
		assert.Equal(t, "http://gw-env:3", resolveGatewayURL(""))
	})
}

func TestResolveAdminFlags_HonorsAdminURLEnv(t *testing.T) {
	getString := func(name string) (string, error) {
		if name == "admin-url" {
			return "", nil
		}
		if name == "api-key" {
			return "svc-key", nil
		}
		return "org-1", nil // org flag
	}
	t.Setenv("YABANIN_ADMIN_URL", "http://env-admin:9")
	base, apiKey, org, err := resolveAdminFlags(getString, "org")
	require.NoError(t, err)
	assert.Equal(t, "http://env-admin:9", base)
	assert.Equal(t, "svc-key", apiKey)
	assert.Equal(t, "org-1", org)
}

// negative control for the CLI network observer. Targets injected via env
// (standing in for CDN/font/analytics endpoints) are dialed EXACTLY once and
// each is REPORTED by name and outcome: configured live targets read healthy;
// a configured dead beacon surfaces its failure and fails the run; a live but
// UNCONFIGURED listener is never dialed (no implicit targets, nothing else on
// the machine is contacted).
func TestDoctor_InjectedEgressTargetsAreObservedAndReported(t *testing.T) {
	cdn := httptest.NewServer(okHandler())
	t.Cleanup(cdn.Close)
	font := httptest.NewServer(okHandler())
	t.Cleanup(font.Close)
	unconfigured := httptest.NewServer(okHandler())
	unconfiguredURL := unconfigured.URL
	t.Cleanup(unconfigured.Close)
	beacon := httptest.NewServer(okHandler())
	beaconURL := beacon.URL
	beacon.Close() // a dead injected endpoint: the observer must report the failure

	previousTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previousTransport })
	var mu sync.Mutex
	var requests []string
	observe := func() {
		real := previousTransport
		http.DefaultTransport = doctorRoundTripper(func(r *http.Request) (*http.Response, error) {
			mu.Lock()
			requests = append(requests, r.URL.Scheme+"://"+r.URL.Host+r.URL.Path)
			mu.Unlock()
			return real.RoundTrip(r)
		})
	}

	// Phase 1: the two configured live targets are probed exactly once each
	// and reported; the live unconfigured listener is never dialed.
	t.Setenv("YABANIN_GATEWAY_URL", cdn.URL)
	t.Setenv("YABANIN_ADMIN_URL", font.URL)
	observe()
	out, err := runDoctor(t)
	require.NoError(t, err)
	mu.Lock()
	assert.ElementsMatch(t, []string{cdn.URL + "/healthz", font.URL + "/health"}, requests,
		"each configured target must be probed exactly once, nothing else dialed")
	requests = nil
	mu.Unlock()
	assert.Contains(t, out, "✓ Gateway: healthy")
	assert.Contains(t, out, "✓ Admin panel: healthy")
	assert.NotContains(t, out, unconfiguredURL, "an unconfigured local listener must not be contacted or named")

	// Phase 2: injecting a dead beacon as the admin target must surface its
	// failure in the report and fail the run — never a silent swallow.
	t.Setenv("YABANIN_ADMIN_URL", beaconURL)
	out, err = runDoctor(t)
	require.Error(t, err, "a dead configured target must fail the run")
	mu.Lock()
	assert.ElementsMatch(t, []string{cdn.URL + "/healthz", beaconURL + "/health"}, requests,
		"the dead beacon must be probed exactly once via the observer")
	mu.Unlock()
	assert.Contains(t, out, "✗ Admin panel", "the failed injected target must be named in the report")
	assert.NotContains(t, out, "All configured checks healthy")
}

// a configured proxy/tenant prefix must survive scopedHealthURL — re-encoding
// only Path would turn %2F into / and change the selected route.
func TestDoctor_PreservesEscapedTenantPrefix(t *testing.T) {
	clearDoctorTargetEnv(t)
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.RequestURI)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	_, err := runDoctor(t, "--base-url", server.URL+"/tenant%2Fblue%2F/", "--admin-url", server.URL+"/admin%2Fblue/")
	require.NoError(t, err)
	assert.Equal(t, []string{"/tenant%2Fblue%2F/healthz", "/admin%2Fblue/health"}, requests)
}

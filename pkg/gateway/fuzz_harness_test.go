package cli

// Shared hermetic harness for the gateway fuzz-seed targets (task
// gateway-fuzz-seeds). Everything here is deterministic: static policy
// sets, resolver-backed SSRF allow-lists, loopback upstreams, injectable
// clocks. No external network beyond 127.0.0.1 dial-outs.

import (
	"context"
	"log/slog"
	"net"
	"os/exec"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/a2aagg"
	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/ssrf"
)

// fuzzDiscardLogger is a non-nil sink for the gateway log fields.
func fuzzDiscardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// fuzzDockerUp reports whether a Docker daemon is reachable. Real-storage
// seeds (MC-25) run on the disposable testdb stands in the tests gate (no
// -short; Docker is required there) and step aside everywhere else, so plain
// `go test ./pkg/gateway/` stays green on Dockerless machines.
func fuzzDockerUp() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	return exec.CommandContext(context.Background(), "docker", "info", "--format", "{{.ServerVersion}}").Run() == nil
}

// fuzzDeadRedis returns a publisher whose client dials a closed loopback
// port: every publish fails fast with ECONNREFUSED and never panics (the
// retry goroutine is bounded and asynchronous).
func fuzzDeadRedis(t *testing.T) *eventpublisher.RedisPublisher {
	t.Helper()
	rc := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { _ = rc.Close() })
	return eventpublisher.NewRedisPublisher(rc, "fuzz-events")
}

// Static hermetic SSRF allow-lists.

func fuzzLoopbackPinnedList(t *testing.T) ssrf.AllowList {
	t.Helper()
	al, err := ssrf.NewAllowListTrustingExactPins([]string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("loopback pin list: %v", err)
	}
	return al
}

func fuzzPublicAllowList(t *testing.T) ssrf.AllowList {
	t.Helper()
	al, err := ssrf.NewAllowListWithResolver([]string{"api.example.com"},
		func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		})
	if err != nil {
		t.Fatalf("public allow list: %v", err)
	}
	return al
}

func fuzzResolverErrList(t *testing.T) ssrf.AllowList {
	t.Helper()
	al, err := ssrf.NewAllowListWithResolver([]string{"api.example.com"},
		func(context.Context, string) ([]net.IP, error) {
			return nil, context.DeadlineExceeded
		})
	if err != nil {
		t.Fatalf("resolver-err list: %v", err)
	}
	return al
}

func fuzzReservedList(t *testing.T) ssrf.AllowList {
	t.Helper()
	al, err := ssrf.NewAllowListWithResolver([]string{"api.example.com"},
		func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("127.0.0.9")}, nil
		})
	if err != nil {
		t.Fatalf("reserved list: %v", err)
	}
	return al
}

func fuzzEmptyAnswerList(t *testing.T) ssrf.AllowList {
	t.Helper()
	al, err := ssrf.NewAllowListWithResolver([]string{"api.example.com"},
		func(context.Context, string) ([]net.IP, error) {
			return nil, nil
		})
	if err != nil {
		t.Fatalf("empty-answer list: %v", err)
	}
	return al
}

// fuzzA2ADB implements a2aagg.DB with one canned row outcome.
type fuzzA2ADB struct {
	agent *a2aagg.Agent
	err   error // returned from Scan (pgx.ErrNoRows maps to ErrNotFound in the store)
}

func (d fuzzA2ADB) QueryRow(context.Context, string, ...any) pgx.Row {
	return fuzzA2ARow(d)
}

func (d fuzzA2ADB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, pgx.ErrNoRows
}

func (d fuzzA2ADB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag(""), nil
}

type fuzzA2ARow struct {
	agent *a2aagg.Agent
	err   error
}

func (r fuzzA2ARow) Scan(dest ...any) error {
	if a := r.agent; a != nil {
		name := ""
		if a.DisplayName != nil {
			name = *a.DisplayName
		}
		// The canned row is scanned even when an error is canned:
		// production scanAgent discards the agent on any scan error, so
		// current behavior is unchanged, but an error-suppressing store
		// variant receives a valid row/URL through the same stack instead
		// of failing on missing-agent setup (N1-A2A-EFFECTS).
		fuzzScanAgent(dest, a, name)
	}
	return r.err
}

// fuzzScanAgent copies the canned agent fields into the pgx scan dests.
func fuzzScanAgent(dest []any, a *a2aagg.Agent, name string) {
	if p, ok := dest[0].(*string); ok {
		*p = a.ID
	}
	if p, ok := dest[1].(*string); ok {
		*p = a.OrgID
	}
	if p, ok := dest[2].(*string); ok {
		*p = a.Name
	}
	if p, ok := dest[3].(**string); ok {
		*p = &name
	}
	if p, ok := dest[4].(*string); ok {
		*p = a.URL
	}
	if p, ok := dest[5].(*bool); ok {
		*p = a.Enabled
	}
	if p, ok := dest[6].(*time.Time); ok {
		*p = a.CreatedAt
	}
	if p, ok := dest[7].(*time.Time); ok {
		*p = a.UpdatedAt
	}
}

// fuzzA2AHook is an a2aagg.Hook with a canned deny reason.
type fuzzA2AHook struct {
	deny string
}

func (h fuzzA2AHook) Scan(_ context.Context, params []byte) ([]byte, string, string) {
	return params, h.deny, "enforce"
}

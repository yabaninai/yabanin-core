package migrate

import (
	"context"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The structural corpus verifies decoded credentials and TCP identities are
// retained by the configured pool. Live tests additionally prove that actual
// migration SQL uses this same transport, including TLS and session settings.
// dsnBoundaryCase is one boundary input of the connection seam.
type dsnBoundaryCase struct {
	name    string
	uri     string // operator-supplied pgx-style URI
	wantErr string // non-empty: the migration configuration must fail with an error containing this
	wantURL string // wantErr empty: reference URL for decoded connection identity
	wantReq struct {
		user string // required decoded username in the pool configuration
		pass string // required decoded password ("" when the URI carries none)
	}
}

// dsnBoundaryCorpus enumerates the seam's boundary inputs. There are no
// empty-URI rows: an empty URI makes pgx fall back to environment defaults,
// so its outcome is environment-dependent by definition and cannot be pinned
// deterministically; the explicit keyword-DSN and unix-socket rows cover the
// same seam surfaces deterministically. Note on ports: pgx fills the default
// port 5432 when the URI omits it, so "no port" rows still pin :5432 in the
// reference identity.
var dsnBoundaryCorpus = []dsnBoundaryCase{
	{
		name:    "not a uri",
		uri:     "not-a-uri",
		wantErr: "parse pg_uri",
	},
	{
		name:    "scheme only",
		uri:     "://missing-scheme",
		wantErr: "parse pg_uri",
	},
	{
		name:    "canonical uri with port",
		uri:     "postgres://postgres:postgres@stand:5432/yabanin?sslmode=disable",
		wantURL: "postgres://postgres:postgres@stand:5432/yabanin",
		wantReq: struct{ user, pass string }{"postgres", "postgres"},
	},
	{
		name:    "no port in uri",
		uri:     "postgres://postgres:postgres@stand/yabanin",
		wantURL: "postgres://postgres:postgres@stand:5432/yabanin",
		wantReq: struct{ user, pass string }{"postgres", "postgres"},
	},
	{
		name:    "postgresql scheme canonicalized",
		uri:     "postgresql://svc:pw@stand:5433/yabanin",
		wantURL: "postgres://svc:pw@stand:5433/yabanin",
		wantReq: struct{ user, pass string }{"svc", "pw"},
	},
	{
		name:    "pool parameters retained",
		uri:     "postgres://svc:pw@stand/yabanin?pool_max_conns=2&sslmode=allow",
		wantURL: "postgres://svc:pw@stand:5432/yabanin",
		wantReq: struct{ user, pass string }{"svc", "pw"},
	},
	{
		name:    "percent-encoded at in password",
		uri:     "postgres://svc:p%40ss@stand/yabanin",
		wantURL: "postgres://svc:p%40ss@stand:5432/yabanin",
		wantReq: struct{ user, pass string }{"svc", "p@ss"},
	},
	{
		name:    "percent-encoded slash in password",
		uri:     "postgres://svc:p%2Fss@stand/yabanin",
		wantURL: "postgres://svc:p%2Fss@stand:5432/yabanin",
		wantReq: struct{ user, pass string }{"svc", "p/ss"},
	},
	{
		name:    "percent-encoded hash in password",
		uri:     "postgres://svc:p%23x@stand/yabanin",
		wantURL: "postgres://svc:p%23x@stand:5432/yabanin",
		wantReq: struct{ user, pass string }{"svc", "p#x"},
	},
	{
		name:    "encoded username and password colon",
		uri:     "postgres://svc%40team:p%3Ass@stand/yabanin",
		wantURL: "postgres://svc%40team:p%3Ass@stand:5432/yabanin",
		wantReq: struct{ user, pass string }{"svc@team", "p:ss"},
	},
	{
		name:    "ipv6 host with port",
		uri:     "postgres://svc:pw@[::1]:5432/yabanin",
		wantURL: "postgres://svc:pw@[::1]:5432/yabanin",
		wantReq: struct{ user, pass string }{"svc", "pw"},
	},
	{
		name:    "empty password",
		uri:     "postgres://svc@stand/yabanin",
		wantURL: "postgres://svc:@stand:5432/yabanin",
		wantReq: struct{ user, pass string }{"svc", ""},
	},
	{
		name:    "keyword dsn with explicit port",
		uri:     "host=stand port=5433 user=svc password=pw dbname=yabanin",
		wantURL: "postgres://svc:pw@stand:5433/yabanin",
		wantReq: struct{ user, pass string }{"svc", "pw"},
	},
	{
		name:    "keyword dsn without port",
		uri:     "host=stand user=svc password=pw dbname=yabanin",
		wantURL: "postgres://svc:pw@stand:5432/yabanin",
		wantReq: struct{ user, pass string }{"svc", "pw"},
	},
	{
		// Empty authority: net/url gives Host="" and pgx fills the host from
		// a filesystem-probed machine default while the URI's socket-ish tail
		// silently becomes the database name — the effective target would
		// differ per machine, so the seam refuses the input class itself,
		// deterministically on every filesystem. (The libpq percent-encoded
		// host form cannot even be expressed here: net/url rejects %2F in a
		// host as an invalid escape.)
		name:    "unix socket directory host via uri",
		uri:     "postgres://svc@/tmp/yabanin",
		wantErr: "no host authority",
	},
	{
		name:    "unix socket directory host via keyword dsn",
		uri:     "host=/tmp user=svc dbname=yabanin",
		wantErr: "unix-socket",
	},
}

func TestMigrationConnectionBoundaryCorpus(t *testing.T) {
	for _, tc := range dsnBoundaryCorpus {
		t.Run(tc.name, func(t *testing.T) {
			pool, err := Connect(context.Background(), tc.uri, "test")
			if pool != nil {
				defer pool.Close()
				if err == nil {
					err = requireTCP(pool.Config())
				}
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected %q error, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			cfg := pool.Config().ConnConfig
			expected, err := url.Parse(tc.wantURL)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.User != tc.wantReq.user || cfg.Password != tc.wantReq.pass {
				t.Fatal("decoded credentials changed")
			}
			if cfg.Host != expected.Hostname() || strconv.Itoa(int(cfg.Port)) != expected.Port() || cfg.Database != strings.TrimPrefix(expected.Path, "/") {
				t.Fatal("effective TCP/database identity changed")
			}
			if tc.name == "pool parameters retained" && pool.Config().MaxConns != 2 {
				t.Fatal("pool limit changed")
			}
		})
	}
	seen := map[string]bool{}
	for _, tc := range dsnBoundaryCorpus {
		if seen[tc.name] {
			t.Fatalf("duplicate corpus row %q", tc.name)
		}
		seen[tc.name] = true
	}
}

func TestMigrationConnectionTLSAndFallbacks(t *testing.T) {
	t.Setenv("PGSSLMODE", "require")
	pool, err := Connect(context.Background(), "host=localhost user=svc dbname=test application_name=migration-proof connect_timeout=3 options='-c statement_timeout=1200'", "eu")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	cfg := pool.Config().ConnConfig
	if cfg.TLSConfig == nil || len(cfg.Fallbacks) != 0 {
		t.Fatal("required TLS gained a plaintext fallback")
	}
	if cfg.RuntimeParams["application_name"] != "migration-proof" || cfg.ConnectTimeout.Seconds() != 3 || cfg.RuntimeParams["options"] != "-c statement_timeout=1200" {
		t.Fatal("connection settings changed")
	}
	fallback, err := Connect(context.Background(), "host=localhost,/tmp user=svc dbname=test sslmode=disable", "eu")
	if err != nil {
		t.Fatal(err)
	}
	defer fallback.Close()
	if err := requireTCP(fallback.Config()); err == nil {
		t.Fatal("socket fallback accepted")
	}
}

// A min-connections pool may dial as soon as NewWithConfig returns. Refusal
// must happen before constructing that pool, not merely before migrations.
func TestMigrationSocketRefusalPrecedesPoolDial(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "migration-socket-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	address := filepath.Join(dir, ".s.PGSQL.5432")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: address, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, run := range []func(context.Context, string, string) (Result, error){Run, func(ctx context.Context, dsn, region string) (Result, error) { return Down(ctx, dsn, region, 0) }} {
		_, err := run(ctx, "host="+dir+" port=5432 user=svc dbname=test pool_min_conns=1 pool_min_idle_conns=1 sslmode=disable", "eu")
		if err == nil || !strings.Contains(err.Error(), "unix-socket") {
			t.Fatalf("expected pre-dial refusal, got %v", err)
		}
	}
	if err := listener.SetDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.AcceptUnix()
	if conn != nil {
		_ = conn.Close()
		t.Fatal("refused migration contacted the socket")
	}
	if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("expected untouched listener timeout, got %v", err)
	}
}

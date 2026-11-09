package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"runtime/debug"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/adminauth"
)

// inside the protected group, like /api/me) tells an authenticated console
// session which server it is talking to: build version/commit, the admin API
// contract level (api_level — the dashboard compares it against its own
// only: no secrets, no filesystem paths, no topology details.

// AdminAPILevel is the admin API contract level served by this build. It
// starts at 1 and is bumped only when the API surface changes in a way the
// expectation). A const, not a var: the level is part of the code contract,
// never a deploy-time knob.
const AdminAPILevel = 1

// buildVersion and buildCommit are overridable at build time via
// -ldflags "-X github.com/reireirei/yabanin/services/admin/handlers.buildVersion=... -X ...buildCommit=..."
// (vars, not consts, so the linker can replace them — the same pattern
// pkg/trcli uses for the release build). Left empty they fall back to the
// VCS information embedded by the Go toolchain (debug.ReadBuildInfo).
var (
	buildVersion = ""
	buildCommit  = ""
)

// versionResponse is the GET /api/version payload. Every field is always
// present and typed so the dashboard handshake can rely on the shape; an
// undeterminable migration version is reported as 0 ("nothing applied" —
// the same semantics pkg/migrate uses for a missing schema state).
type versionResponse struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	APILevel  int    `json:"api_level"`
	Migration int64  `json:"migration"`
}

// SchemaVersionSource is the narrow capability the version handler needs:
// raw access to the admin store's connection pool. *adminstore.Store
// satisfies it via DB(); stores without the capability (unit-test stubs)
// simply report migration 0. The pool is read-only use: one SELECT against
// the same schema_migrations state pkg/migrate maintains — no second source
// of truth and no new store surface.
type SchemaVersionSource interface {
	DB() *pgxpool.Pool
}

// schemaVersionQuerier is the minimal query surface readSchemaVersion needs
// (*pgxpool.Pool satisfies it; tests substitute a fake, mirroring the
// adminstore pgxdb seam).
type schemaVersionQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
}

// schemaVersionQuery reads the latest applied migration from the
// schema_migrations table — the authoritative migrate state, exactly the
// query pkg/migrate.Run/Down use for their Result.Version.
const schemaVersionQuery = `SELECT MAX(version) FROM schema_migrations`

// readSchemaVersion returns the latest applied migration version. Any read
// failure (table absent before the first migration, NULL row, pool error) is
// surfaced to the caller; the handler logs it and degrades to 0 instead of
// failing the handshake — the endpoint must stay answerable so the dashboard
// can at least learn the API level.
func readSchemaVersion(ctx context.Context, q schemaVersionQuerier) (int64, error) {
	var version int64
	if err := q.QueryRow(ctx, schemaVersionQuery).Scan(&version); err != nil {
		return 0, err
	}
	return version, nil
}

// buildIdentity resolves the reported version/commit: ldflags overrides win
// (release builds), then the VCS metadata the toolchain embeds (vcs.revision,
// suffixed -dirty for modified trees), then honest "dev"/"unknown" fallbacks.
// Pure so tests can pin every branch with a synthetic BuildInfo.
func buildIdentity(ldVersion, ldCommit string, bi *debug.BuildInfo) (version, commit string) {
	version, commit = ldVersion, ldCommit
	if bi != nil {
		if version == "" {
			version = bi.Main.Version
		}
		if commit == "" {
			dirty := false
			for _, s := range bi.Settings {
				switch s.Key {
				case "vcs.revision":
					commit = s.Value
				case "vcs.modified":
					dirty = s.Value == "true"
				}
			}
			if commit != "" && dirty {
				commit += "-dirty"
			}
		}
	}
	if version == "" {
		version = "dev"
	}
	if commit == "" {
		commit = "unknown"
	}
	return version, commit
}

// Build information is immutable for the life of the process: read once
// (Do's happens-before makes the result visible to every request goroutine).
var (
	buildInfoOnce    sync.Once
	buildInfoVersion string
	buildInfoCommit  string
)

// resolveBuildInfo returns the version/commit pair this build reports.
func resolveBuildInfo() (version, commit string) {
	buildInfoOnce.Do(func() {
		var bi *debug.BuildInfo
		if info, ok := debug.ReadBuildInfo(); ok {
			bi = info
		}
		buildInfoVersion, buildInfoCommit = buildIdentity(buildVersion, buildCommit, bi)
	})
	return buildInfoVersion, buildInfoCommit
}

// Version answers GET /api/version for an authenticated console session.
// Mounted inside the protected group (HOT-PATCH: router.go, right after
// /api/me) the session middleware is the gate; the in-context user check
// below only fails closed if the route ever leaves that group.
func (h *AdminHandlers) Version() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := adminauth.AdminUserFromContext(r)
		if !ok || user.ID == "" {
			writeJSON(w, http.StatusUnauthorized, apiError{Error: "unauthorized"})
			return
		}

		version, commit := resolveBuildInfo()
		resp := versionResponse{
			Version:   version,
			Commit:    commit,
			APILevel:  AdminAPILevel,
			Migration: 0,
		}
		if src, isSource := h.store.(SchemaVersionSource); isSource {
			if pool := src.DB(); pool != nil {
				migration, err := readSchemaVersion(r.Context(), pool)
				if err != nil {
					// Degraded, not failed: report 0 and log for the
					// operator. The error never reaches the client (it can
					// name driver/host details).
					if h.logger != nil {
						h.logger.WarnContext(r.Context(), "schema version unavailable; reporting 0",
							slog.String("error", err.Error()))
					}
				}
				resp.Migration = migration
			}
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

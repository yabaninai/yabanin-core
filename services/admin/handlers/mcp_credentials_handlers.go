package handlers

// MC-1 (MCP-CREDENTIALS-PLAN-2026-10-05): admin CRUD for the server-level
// MCP credential (one per registered server). Root-only and org-scoped, the
// same posture as the mcp_servers CRUD (router_mcp.go).
//
// The store is the narrow MCPCredentialStore capability (*adminstore.Store
// satisfies it — compile pin). Plaintext secret material exists only as a
// call argument into the store; the response rows carry the last-4 mask
// exclusively (the adminstore read types have no secret field at all).
// After every successful mutation the optional version bumper is notified so
// the gateway's resolver cache drops its entries for the org (MC-2 contract,
// OrgCredsVersionBumper parity); a failed bump is a warning, never a failed
// response — the gateway TTL bounds staleness either way.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// MCPCredentialStore is the narrow server-level capability the handlers
// consume (exactly the MC-1 contract; *adminstore.Store satisfies it).
type MCPCredentialStore interface {
	UpsertMCPServerCredential(ctx context.Context, orgID, serverName, kind, plaintextSecret string) (adminstore.MCPServerCredential, error)
	GetMCPServerCredential(ctx context.Context, orgID, serverName string) (adminstore.MCPServerCredential, error)
	DeleteMCPServerCredential(ctx context.Context, orgID, serverName string) error
	SetMCPServerCredentialEnabled(ctx context.Context, orgID, serverName string, enabled bool) (adminstore.MCPServerCredential, error)
}

// compile pin: the production store implements the narrow capability.
var _ MCPCredentialStore = (*adminstore.Store)(nil)

// MCPUserCredLifecycle is the grant-CRUD hook surface (MC-3): a per-user
// credential of a (server, agent) pair is ORPHANED when the grant is
// revoked/disabled and RESTORED when the grant returns. *adminstore.Store
// implements it (compile pin).
type MCPUserCredLifecycle interface {
	OrphanMCPUserCredentials(ctx context.Context, orgID, serverName, agentKeyID string) error
	RestoreMCPUserCredentials(ctx context.Context, orgID, serverName, agentKeyID string) error
}

// compile pin: the production store implements the lifecycle hook.
var _ MCPUserCredLifecycle = (*adminstore.Store)(nil)

// SetMCPUserCredLifecycle attaches the grant-CRUD orphan/restore hook. nil =
// the hook is a no-op (runtime still enforces the grant on every invoke;
// the status is lifecycle bookkeeping).
func (h *AdminHandlers) SetMCPUserCredLifecycle(l MCPUserCredLifecycle) {
	h.mcp.userCredLifecycle = l
}

// MCPCredsVersionBumper is the gateway cache-invalidation hook (MC-2): after
// a successful credential CRUD the handlers bump the org's version so the
// gateway drops its cached resolver decisions immediately.
type MCPCredsVersionBumper interface {
	SetMCPCredsVersion(ctx context.Context, orgID string, version int64) error
}

// mcpCredBodyLimit bounds the credential JSON body (a headers or oauth
// payload; the store additionally caps the plaintext at 8 KiB).
const mcpCredBodyLimit = 16 * 1024

// mcpCredentialPutBody is the PUT payload. Secret accepts either a string
// (a pre-serialized JSON payload) or a raw JSON object (headers); the store
// validates the shape per kind.
type mcpCredentialPutBody struct {
	Kind    string          `json:"kind"`
	Secret  json.RawMessage `json:"secret"`
	Enabled *bool           `json:"enabled,omitempty"`
}

// SetMCPCredentialStore attaches the server-level credential store and the
// optional version bumper. A nil store keeps the routes mounted but
// unwired: they answer 503 (requireMCPCredStore).
func (h *AdminHandlers) SetMCPCredentialStore(store MCPCredentialStore, bumper MCPCredsVersionBumper) {
	h.mcp.credStore = store
	h.mcp.credsVersionBumper = bumper
}

// requireMCPCredStore writes 503 when the credential store is not wired
// (no DB) and returns false; the handler must return immediately.
func (h *AdminHandlers) requireMCPCredStore(w http.ResponseWriter) bool {
	if h.mcp.credStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "mcp credential store not configured (no database)"})
		return false
	}
	return true
}

// PutMCPServerCredential — PUT /api/organizations/{id}/mcp/servers/{name}/credential
// Creates or rotates the server-level credential (kind switch allowed; a
// rotation bumps the store version). Enabled=false in the body disables the
// stored credential after the write.
func (h *AdminHandlers) PutMCPServerCredential() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireMCPCredStore(w) {
			return
		}
		orgID, name := h.mcpCredentialPathIDs(w, r)
		if orgID == "" {
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, mcpCredBodyLimit+1))
		if err != nil || len(raw) > mcpCredBodyLimit {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid request body"})
			return
		}
		var body mcpCredentialPutBody
		if err := json.Unmarshal(raw, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "malformed JSON body"})
			return
		}
		secret, ok := decodeMCPCredSecret(w, body.Secret)
		if !ok {
			return
		}
		cred, err := h.mcp.credStore.UpsertMCPServerCredential(r.Context(), orgID, name, body.Kind, secret)
		if err != nil {
			h.writeMCPCredStoreErr(w, "update", orgID, name, err)
			return
		}
		if body.Enabled != nil && !*body.Enabled {
			if cred, err = h.mcp.credStore.SetMCPServerCredentialEnabled(r.Context(), orgID, name, false); err != nil {
				h.writeMCPCredStoreErr(w, "update", orgID, name, err)
				return
			}
		}
		h.auditLogAction(r, "update", "mcp_server_credential",
			mcpCredAuditDetails("upsert", name, orgID, cred))
		h.bumpMCPCredsVersion(r, orgID)
		writeJSON(w, http.StatusOK, cred)
	}
}

// GetMCPServerCredential — GET /api/organizations/{id}/mcp/servers/{name}/credential
// Masked read (last4/has_secret); 404 when the server has no credential.
func (h *AdminHandlers) GetMCPServerCredential() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireMCPCredStore(w) {
			return
		}
		orgID, name := h.mcpCredentialPathIDs(w, r)
		if orgID == "" {
			return
		}
		cred, err := h.mcp.credStore.GetMCPServerCredential(r.Context(), orgID, name)
		if err != nil {
			h.writeMCPCredStoreErr(w, "get", orgID, name, err)
			return
		}
		writeJSON(w, http.StatusOK, cred)
	}
}

// DeleteMCPServerCredential — DELETE /api/organizations/{id}/mcp/servers/{name}/credential
func (h *AdminHandlers) DeleteMCPServerCredential() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireMCPCredStore(w) {
			return
		}
		orgID, name := h.mcpCredentialPathIDs(w, r)
		if orgID == "" {
			return
		}
		if err := h.mcp.credStore.DeleteMCPServerCredential(r.Context(), orgID, name); err != nil {
			h.writeMCPCredStoreErr(w, "delete", orgID, name, err)
			return
		}
		h.auditLogAction(r, "delete", "mcp_server_credential",
			mcpCredAuditDetails("delete", name, orgID, adminstore.MCPServerCredential{}))
		h.bumpMCPCredsVersion(r, orgID)
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	}
}

// mcpCredentialPathIDs extracts and validates the (org, server) path pair,
// writing 400 itself when either is empty ("", false returned).
func (h *AdminHandlers) mcpCredentialPathIDs(w http.ResponseWriter, r *http.Request) (orgID, name string) {
	orgID = r.PathValue("id")
	name = r.PathValue("name")
	if orgID == "" || name == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "org id and server name are required"})
		return "", ""
	}
	return orgID, name
}

// decodeMCPCredSecret accepts a JSON string payload or a raw JSON object
// (re-serialized verbatim) and rejects anything else / empty.
func decodeMCPCredSecret(w http.ResponseWriter, raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "secret is required"})
		return "", false
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil || s == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "secret must be a non-empty string or a JSON object"})
			return "", false
		}
		return s, true
	}
	if raw[0] != '{' {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "secret must be a JSON string or object"})
		return "", false
	}
	return string(raw), true
}

// mcpCredAuditDetails renders the journal line — masks and facts only, no
// secret material (the store guarantees the row type carries none).
func mcpCredAuditDetails(action, server, orgID string, cred adminstore.MCPServerCredential) string {
	details := "action=" + action + ",server=" + server + ",org=" + orgID
	if cred.Kind != "" {
		details += ",kind=" + cred.Kind + ",last4=" + cred.SecretLast4
	}
	if cred.Enabled {
		details += ",enabled=true"
	}
	return details
}

// writeMCPCredStoreErr maps store failures for the credential surface:
// not-found → 404, a Postgres rejection → generic 500 (driver text goes to
// the log, never to the wire), anything else → 400 (store validation
// messages are client-actionable and carry no secret material — they are
// produced before encryption on the write path, truncated for the body).
func (h *AdminHandlers) writeMCPCredStoreErr(w http.ResponseWriter, action, orgID, name string, err error) {
	switch {
	case errors.Is(err, adminstore.ErrNotFound):
		writeJSON(w, http.StatusNotFound, apiError{Error: "mcp server or credential not found"})
	case isPgError(err):
		if h.store != nil && h.store.Log() != nil {
			h.store.Log().Error("mcp credential store call failed",
				"action", action, "org", orgID, "server", name, "error", err.Error())
		}
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "internal error"})
	default:
		msg := err.Error()
		if len(msg) > 300 {
			msg = msg[:300]
		}
		writeJSON(w, http.StatusBadRequest, apiError{Error: msg})
	}
}

// isPgError reports whether err is a Postgres driver error.
func isPgError(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr)
}

// bumpMCPCredsVersion invalidates the gateway's MCP credential cache after a
// successful CRUD (MC-2 contract: nanos version per org). A failed bump is a
// warning, never a failed response — the gateway TTL bounds staleness.
func (h *AdminHandlers) bumpMCPCredsVersion(r *http.Request, orgID string) {
	if h.mcp.credsVersionBumper == nil {
		return
	}
	if err := h.mcp.credsVersionBumper.SetMCPCredsVersion(r.Context(), orgID, time.Now().UnixNano()); err != nil {
		if h.store != nil && h.store.Log() != nil {
			h.store.Log().Warn("mcp credential version bump failed; gateway cache expires via TTL",
				"org_id", orgID, "error", err.Error())
		}
	}
}

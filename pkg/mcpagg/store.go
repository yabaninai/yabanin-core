// Package mcpagg implements the MCP aggregator core (MCP-02, Phase 5):
// the org-managed registry of external Model Context Protocol servers and
// the gateway-side proxy that invokes their tools over HTTP(S) MCP
// streamable HTTP — with SSRF guarding and bounded timeouts.
//
// Design: docs/mcp-gateway.md (MCP-01 spec spike). The feature is OFF by
// default: the gateway mounts the proxy route group only when
// YABANIN_MCP_GATEWAY=1, and every server row is inert until enabled.
package mcpagg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
)

// Credential modes for the connection configuration (migration 0016, I54):
// which credential layer may authorize an invoke on this server.
const (
	// CredModeAuto is the legacy resolution chain — per-user active →
	// server-level enabled → none — unchanged from pre-0016 behavior. It is
	// the DEFAULT: existing rows and omitted API fields keep it.
	CredModeAuto = "auto"
	// CredModeService restricts resolution to the org/project service
	// credential (server-level); per-user credentials are never consulted.
	CredModeService = "service"
	// CredModeDelegated restricts resolution to the per-user credential
	// after its authorization. An unavailable user credential NEVER falls
	// back to the more privileged service credential (I54 negative): the
	// invoke proceeds unauthenticated and the lazy-authorization flow takes
	// over.
	CredModeDelegated = "delegated"
)

// CredentialModes is the closed vocabulary accepted by Create/Update.
var CredentialModes = []string{CredModeAuto, CredModeService, CredModeDelegated}

// ValidateCredentialMode enforces the migration-0016 CHECK in the API layer
// (a rejected value is a 400, not a 500 from the DB constraint). An empty
// value is the auto default and valid.
func ValidateCredentialMode(mode string) error {
	if mode == "" {
		return nil
	}
	for _, m := range CredentialModes {
		if m == mode {
			return nil
		}
	}
	return fmt.Errorf("mcpagg: credential_mode must be one of %s", strings.Join(CredentialModes, ", "))
}

// Server is a row of the mcp_servers registry (MCP-02, migration 0004).
// AllowedTools is the per-server tool allow-list; an empty slice means all
// tools on the server are callable. CredentialMode selects the credential
// layer (migration 0016, I54); ConfigVersion versions the connection
// configuration — every successful Update bumps it.
type Server struct {
	ID             string    `json:"id"`
	OrgID          string    `json:"org_id"`
	Name           string    `json:"name"`
	DisplayName    *string   `json:"display_name,omitempty"`
	URL            string    `json:"url"`
	Transport      string    `json:"transport"`
	AllowedTools   []string  `json:"allowed_tools"`
	Enabled        bool      `json:"enabled"`
	CredentialMode string    `json:"credential_mode"`
	ConfigVersion  int64     `json:"config_version"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// CreateParams is the input for Store.Create. AllowedTools nil/empty means
// "all tools" (stored as '[]'). An empty CredentialMode stores 'auto'.
type CreateParams struct {
	OrgID          string
	Name           string
	DisplayName    *string
	URL            string
	Transport      string
	AllowedTools   []string
	Enabled        bool
	CredentialMode string
}

// UpdateParams is the input for Store.Update; nil fields are left untouched.
// Every applied update bumps config_version (the connection configuration is
// versioned as a whole, not per-field).
type UpdateParams struct {
	DisplayName    *string
	URL            *string
	Transport      *string
	AllowedTools   *[]string
	Enabled        *bool
	CredentialMode *string
}

// ErrNotFound is returned when a server row does not exist for the org.
var ErrNotFound = errors.New("mcpagg: server not found")

// Store reads and writes the mcp_servers registry. The db handle is the
// pgx-compatible interface (pgxpool.Pool in production); nil db makes every
// method fail — the gateway wires the store only when a DB pool exists.
type Store struct {
	db DB
}

// DB is the database surface Store needs (satisfied by *pgxpool.Pool).
type DB interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// NewStore creates a Store. db may be nil (every method then errors).
func NewStore(db DB) *Store { return &Store{db: db} }

const scanCols = `id::text, org_id::text, name, display_name, url, transport,
	allowed_tools::jsonb, enabled, credential_mode, config_version,
	created_at, updated_at`

// serverScanTarget binds the scan destinations for the scanCols column order.
// A Row/Rows Scan takes the addresses directly, so a fresh target per call.
type serverScanTarget struct {
	id, orgID, name, url, transport, credentialMode string
	displayName                                     *string
	toolsJSON                                       []byte
	enabled                                         bool
	configVersion                                   int64
	createdAt, updatedAt                            time.Time
}

func (t *serverScanTarget) toServer() (*Server, error) {
	s := &Server{
		ID:             t.id,
		OrgID:          t.orgID,
		Name:           t.name,
		DisplayName:    t.displayName,
		URL:            t.url,
		Transport:      t.transport,
		Enabled:        t.enabled,
		CredentialMode: t.credentialMode,
		ConfigVersion:  t.configVersion,
		CreatedAt:      t.createdAt,
		UpdatedAt:      t.updatedAt,
	}
	if s.CredentialMode == "" {
		// Defense in depth for rows read outside a migrated schema (the
		// column is NOT NULL DEFAULT 'auto' since 0016).
		s.CredentialMode = CredModeAuto
	}
	if t.toolsJSON != nil {
		if err := json.Unmarshal(t.toolsJSON, &s.AllowedTools); err != nil {
			return nil, fmt.Errorf("mcpagg: decode allowed_tools: %w", err)
		}
	}
	if s.AllowedTools == nil {
		s.AllowedTools = []string{}
	}
	return s, nil
}

func (t *serverScanTarget) scanArgs() []any {
	return []any{&t.id, &t.orgID, &t.name, &t.displayName, &t.url, &t.transport,
		&t.toolsJSON, &t.enabled, &t.credentialMode, &t.configVersion,
		&t.createdAt, &t.updatedAt}
}

func scanServer(row pgx.Row) (*Server, error) {
	t := &serverScanTarget{}
	if err := row.Scan(t.scanArgs()...); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return t.toServer()
}

// GetEnabled returns the named server when it exists AND is enabled for the
// org. A disabled or missing server both yield ErrNotFound — the proxy must
// not reveal which (an operator can then distinguish enabled-vs-registered by
// name, but a client must not).
func (s *Store) GetEnabled(ctx context.Context, orgID, name string) (*Server, error) {
	if s.db == nil {
		return nil, errors.New("mcpagg: database not available")
	}
	row := s.db.QueryRow(ctx,
		`SELECT `+scanCols+` FROM mcp_servers WHERE org_id = $1 AND name = $2 AND enabled`,
		orgID, name)
	return scanServer(row)
}

// Create inserts a new server row. The URL must already have passed
// ValidateServerURL (callers enforce; the DB CHECK is the second layer).
func (s *Store) Create(ctx context.Context, p CreateParams) (*Server, error) {
	if s.db == nil {
		return nil, errors.New("mcpagg: database not available")
	}
	if p.Transport == "" {
		p.Transport = TransportHTTP
	}
	if p.CredentialMode == "" {
		p.CredentialMode = CredModeAuto
	}
	if err := ValidateCredentialMode(p.CredentialMode); err != nil {
		return nil, err
	}
	toolsJSON, err := encodeTools(p.AllowedTools)
	if err != nil {
		return nil, err
	}
	row := s.db.QueryRow(ctx,
		`INSERT INTO mcp_servers (org_id, name, display_name, url, transport, allowed_tools, enabled, credential_mode)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING `+scanCols,
		p.OrgID, p.Name, p.DisplayName, p.URL, p.Transport, toolsJSON, p.Enabled, p.CredentialMode)
	srv, err := scanServer(row)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("mcpagg: server %q already exists for the org", p.Name)
		}
		return nil, err
	}
	return srv, nil
}

// Update applies a partial update to an org's server and returns the row.
// Every applied update bumps config_version by one (the connection
// configuration is versioned as a whole, N05-P02-T02), so a reader can pin
// the configuration revision a credential decision or audit record belongs
// to. A nil-CredentialMode update leaves the mode untouched.
func (s *Store) Update(ctx context.Context, orgID, name string, p UpdateParams) (*Server, error) {
	if s.db == nil {
		return nil, errors.New("mcpagg: database not available")
	}
	if p.CredentialMode != nil {
		if err := ValidateCredentialMode(*p.CredentialMode); err != nil {
			return nil, err
		}
	}
	sets := []string{}
	args := []any{orgID, name}
	n := 3
	if p.DisplayName != nil {
		sets = append(sets, fmt.Sprintf("display_name = $%d", n))
		args = append(args, *p.DisplayName)
		n++
	}
	if p.URL != nil {
		sets = append(sets, fmt.Sprintf("url = $%d", n))
		args = append(args, *p.URL)
		n++
	}
	if p.Transport != nil {
		sets = append(sets, fmt.Sprintf("transport = $%d", n))
		args = append(args, *p.Transport)
		n++
	}
	if p.AllowedTools != nil {
		toolsJSON, err := encodeTools(*p.AllowedTools)
		if err != nil {
			return nil, err
		}
		sets = append(sets, fmt.Sprintf("allowed_tools = $%d", n))
		args = append(args, toolsJSON)
		n++
	}
	if p.Enabled != nil {
		sets = append(sets, fmt.Sprintf("enabled = $%d", n))
		args = append(args, *p.Enabled)
		n++
	}
	if p.CredentialMode != nil {
		sets = append(sets, fmt.Sprintf("credential_mode = $%d", n))
		args = append(args, *p.CredentialMode)
	}
	if len(sets) == 0 {
		return s.Get(ctx, orgID, name)
	}
	sets = append(sets, "updated_at = now()", "config_version = config_version + 1")
	row := s.db.QueryRow(ctx,
		`UPDATE mcp_servers SET `+strings.Join(sets, ", ")+
			` WHERE org_id = $1 AND name = $2 RETURNING `+scanCols,
		args...)
	srv, err := scanServer(row)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return srv, nil
}

// Get returns the named server regardless of enabled state (admin reads).
func (s *Store) Get(ctx context.Context, orgID, name string) (*Server, error) {
	if s.db == nil {
		return nil, errors.New("mcpagg: database not available")
	}
	row := s.db.QueryRow(ctx,
		`SELECT `+scanCols+` FROM mcp_servers WHERE org_id = $1 AND name = $2`,
		orgID, name)
	return scanServer(row)
}

// List returns all servers for the org (newest first), admin reads.
func (s *Store) List(ctx context.Context, orgID string) ([]*Server, error) {
	if s.db == nil {
		return nil, errors.New("mcpagg: database not available")
	}
	rows, err := s.db.Query(ctx,
		`SELECT `+scanCols+` FROM mcp_servers WHERE org_id = $1 ORDER BY created_at DESC, name`,
		orgID)
	if err != nil {
		return nil, fmt.Errorf("mcpagg: list servers: %w", err)
	}
	defer rows.Close()

	var out []*Server
	for rows.Next() {
		srv, err := scanServerFromRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, srv)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("mcpagg: list servers: %w", err)
	}
	return out, nil
}

// Delete removes the org's named server. ErrNotFound when absent.
func (s *Store) Delete(ctx context.Context, orgID, name string) error {
	if s.db == nil {
		return errors.New("mcpagg: database not available")
	}
	tag, err := s.db.Exec(ctx,
		`DELETE FROM mcp_servers WHERE org_id = $1 AND name = $2`,
		orgID, name)
	if err != nil {
		return fmt.Errorf("mcpagg: delete server: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Grant is a row of the mcp_server_grants table (MCP-03, migration 0006;
// action dimension added by migration 0020). It authorizes one agent (a yag_
// principal, G1) to use one server, with its own tool allow-list and action
// vocabulary. AllowedTools nil/empty means "every tool the SERVER allows" —
// the server allow-list is always the ceiling. AllowedActions empty means
// the OPPOSITE on the action dimension: an explicitly empty list authorizes
// NO action (the grant stays subject-valid for audit but executes nothing) —
// the action dimension is fail-closed, migration 0020's default
// ["invoke","list"] preserves pre-0020 rows.
type Grant struct {
	ID             string    `json:"id"`
	OrgID          string    `json:"org_id"`
	AgentID        string    `json:"agent_id"`
	ServerName     string    `json:"server_name"`
	AllowedTools   []string  `json:"allowed_tools"`
	AllowedActions []string  `json:"allowed_actions"`
	Enabled        bool      `json:"enabled"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// GrantCreateParams is the input for Store.CreateGrant. AllowedActions nil
// lets the column default apply (["invoke","list"] — today's behavior); a
// non-nil slice is validated (known actions only, no duplicates) and stored
// as given — an explicit empty slice stores [] and denies all actions.
type GrantCreateParams struct {
	OrgID          string
	AgentID        string
	ServerName     string
	AllowedTools   []string
	AllowedActions *[]string
	Enabled        bool
}

// ChainAllowance is the effective tool ceiling across an agent's whole
// delegation chain (AUTH-02), keyed by server name. See the Allows method
// for the per-entry semantics.
type ChainAllowance map[string][]string

// GrantUpdateParams is the input for Store.UpdateGrant; nil fields untouched.
// AllowedActions non-nil replaces the action vocabulary (validated; empty
// slice = deny all actions).
type GrantUpdateParams struct {
	AllowedTools   *[]string
	AllowedActions *[]string
	Enabled        *bool
}

const grantScanCols = `id::text, org_id::text, agent_id::text, server_name,
	allowed_tools::jsonb, allowed_actions::jsonb, enabled, created_at, updated_at`

type grantScanTarget struct {
	id, orgID, agentID, serverName string
	toolsJSON, actionsJSON         []byte
	enabled                        bool
	createdAt, updatedAt           time.Time
}

func (t *grantScanTarget) toGrant() (*Grant, error) {
	g := &Grant{
		ID:         t.id,
		OrgID:      t.orgID,
		AgentID:    t.agentID,
		ServerName: t.serverName,
		Enabled:    t.enabled,
		CreatedAt:  t.createdAt,
		UpdatedAt:  t.updatedAt,
	}
	if t.toolsJSON != nil {
		if err := json.Unmarshal(t.toolsJSON, &g.AllowedTools); err != nil {
			return nil, fmt.Errorf("mcpagg: decode grant allowed_tools: %w", err)
		}
	}
	if g.AllowedTools == nil {
		g.AllowedTools = []string{}
	}
	if t.actionsJSON != nil {
		if err := json.Unmarshal(t.actionsJSON, &g.AllowedActions); err != nil {
			return nil, fmt.Errorf("mcpagg: decode grant allowed_actions: %w", err)
		}
	}
	if g.AllowedActions == nil {
		// The column is NOT NULL since 0020; nil here can only be a scan-layer
		// anomaly. Normalize to the explicit empty list — the action check
		// treats empty as deny-all, so an anomaly denies rather than grants.
		g.AllowedActions = []string{}
	}
	return g, nil
}

func (t *grantScanTarget) scanArgs() []any {
	return []any{&t.id, &t.orgID, &t.agentID, &t.serverName,
		&t.toolsJSON, &t.actionsJSON, &t.enabled, &t.createdAt, &t.updatedAt}
}

func scanGrant(row pgx.Row) (*Grant, error) {
	t := &grantScanTarget{}
	if err := row.Scan(t.scanArgs()...); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return t.toGrant()
}

// GetEnabledGrant returns the agent's grant on the named server when it
// exists AND is enabled. A missing or disabled grant both yield ErrNotFound —
// the proxy treats either as "no access" without revealing which (the agent
// cannot enumerate servers by probing grant state).
func (s *Store) GetEnabledGrant(ctx context.Context, orgID, agentID, serverName string) (*Grant, error) {
	if s.db == nil {
		return nil, errors.New("mcpagg: database not available")
	}
	row := s.db.QueryRow(ctx,
		`SELECT `+grantScanCols+` FROM mcp_server_grants
		 WHERE org_id = $1 AND agent_id = $2 AND server_name = $3 AND enabled`,
		orgID, agentID, serverName)
	return scanGrant(row)
}

// GetGrant returns the agent's grant on the named server regardless of
// enabled state (admin reads).
func (s *Store) GetGrant(ctx context.Context, orgID, agentID, serverName string) (*Grant, error) {
	if s.db == nil {
		return nil, errors.New("mcpagg: database not available")
	}
	row := s.db.QueryRow(ctx,
		`SELECT `+grantScanCols+` FROM mcp_server_grants
		 WHERE org_id = $1 AND agent_id = $2 AND server_name = $3`,
		orgID, agentID, serverName)
	return scanGrant(row)
}

// Allows reports whether tool may be invoked on server under this ceiling:
// the server must be present in the map (every chain member holds an enabled
// grant on it) and the tool must pass the chain's tool scope.
func (a ChainAllowance) Allows(server, tool string) bool {
	tools, ok := a[server]
	if !ok {
		return false
	}
	if tools == nil {
		return true
	}
	return slices.Contains(tools, tool)
}

// delegationChainDepth caps the recursive walk. Delegation (ADL-03) only
// allows root→child, so real chains have length ≤ 2; the bound is purely a
// defense-in-depth guard against malformed parent links (a walk that never
// reaches a root is a broken chain and denies everything below).
const delegationChainDepth = 16

// delegationChainSQL walks the agent's delegation chain upward through
// agent_keys.parent_id — org-scoped and ACTIVE keys only — and aggregates
// every chain member's enabled grant in one round trip:
//
//	chain_n — number of chain members (0 = unknown/revoked agent key);
//	rooted  — whether the walk reached a root key (parent_id IS NULL);
//	grants  — [{server, tools}] of all ENABLED grants held by any member.
//
// root→child delegation means the live chain always ends at a root key.
// A walk that terminates elsewhere — missing, foreign-org or revoked
// ancestor, a corrupt parent cycle (bounded by depth), or a revoked
// starting key — reports rooted=false or chain_n=0 so callers fail closed:
// revoking any ancestor retracts everything below it.
var delegationChainSQL = `
WITH RECURSIVE chain(id, parent, depth) AS (
    SELECT id::text, parent_id::text, 0
      FROM agent_keys
     WHERE id = $2::uuid AND org_id = $1::uuid AND active
  UNION ALL
    SELECT k.id::text, k.parent_id::text, c.depth + 1
      FROM agent_keys k
      JOIN chain c ON k.id::text = c.parent
     WHERE c.depth < ` + fmt.Sprint(delegationChainDepth) + `
       AND k.active
       AND k.org_id = $1::uuid
)
SELECT (SELECT count(*) FROM chain)::int AS chain_n,
       EXISTS (SELECT 1 FROM chain WHERE parent IS NULL) AS rooted,
       COALESCE((SELECT jsonb_agg(jsonb_build_object('server', g.server_name,
                                                     'tools', g.allowed_tools))
                   FROM chain c
                   JOIN mcp_server_grants g ON g.agent_id::text = c.id
                  WHERE g.org_id = $1::uuid
                    AND g.enabled),
                '[]'::jsonb) AS grants`

// chainGrantJSON decodes one element of the aggregated grants column.
type chainGrantJSON struct {
	Server string   `json:"server"`
	Tools  []string `json:"tools"`
}

// DelegationChainAllowance computes the tool ceiling of the agent's whole
// delegation chain (AUTH-02). The agent key itself must exist in the org
// and be active (ErrNotFound otherwise). Every chain member must hold an
// enabled grant on a server for the server to appear in the result; its
// tools are the intersection of all members' restricting grants (nil when
// none restricts). A chain whose walk does not reach a root key — missing,
// foreign-org or revoked ancestor, or a corrupt parent cycle — yields an
// empty allowance: revoking any ancestor retracts everything below it.
func (s *Store) DelegationChainAllowance(ctx context.Context, orgID, agentID string) (ChainAllowance, error) {
	if s.db == nil {
		return nil, errors.New("mcpagg: database not available")
	}
	var (
		chainN     int
		rooted     bool
		grantsJSON []byte
	)
	err := s.db.QueryRow(ctx, delegationChainSQL, orgID, agentID).
		Scan(&chainN, &rooted, &grantsJSON)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Defensive: the aggregate always yields one row.
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("mcpagg: delegation chain lookup: %w", err)
	}
	if chainN == 0 {
		return nil, ErrNotFound // agent key does not exist in this org
	}
	if !rooted {
		return ChainAllowance{}, nil
	}
	var raw []chainGrantJSON
	if len(grantsJSON) > 0 {
		if err := json.Unmarshal(grantsJSON, &raw); err != nil {
			return nil, fmt.Errorf("mcpagg: decode delegation chain grants: %w", err)
		}
	}
	grants := make([]*Grant, 0, len(raw))
	for _, r := range raw {
		grants = append(grants, &Grant{ServerName: r.Server, AllowedTools: r.Tools})
	}
	return chainAllowanceFor(grants, chainN), nil
}

// chainAllowanceFor intersects the chain's enabled grants per server. A
// server is present only when every one of the chainN members holds an
// enabled grant on it; the value is nil when no member restricts tools,
// otherwise the exact (possibly empty) intersection.
func chainAllowanceFor(grants []*Grant, chainN int) ChainAllowance {
	byServer := make(map[string][]*Grant)
	for _, g := range grants {
		byServer[g.ServerName] = append(byServer[g.ServerName], g)
	}
	out := make(ChainAllowance, len(byServer))
	for server, member := range byServer {
		if len(member) != chainN {
			continue // a chain member lacks an enabled grant → no access
		}
		var allowed []string
		for _, g := range member {
			if len(g.AllowedTools) == 0 {
				continue // unrestricted member grant
			}
			allowed = intersectTools(allowed, g.AllowedTools)
		}
		out[server] = allowed
	}
	return out
}

// intersectTools intersects allow-list b into accumulator a (nil = empty
// accumulator, meaning "not yet restricted"). When both inputs are non-nil
// the result is non-nil even when empty — an empty intersection is a real
// restriction (nothing allowed), never "unrestricted".
func intersectTools(a, b []string) []string {
	if a == nil {
		return append([]string(nil), b...)
	}
	out := []string{}
	for _, t := range a {
		if slices.Contains(b, t) {
			out = append(out, t)
		}
	}
	return out
}

// CreateGrant inserts a per-agent grant. The (org_id, agent_id, server_name)
// triple is unique. AllowedActions nil leaves the column to its default
// (["invoke","list"]); a non-nil slice is validated and stored as given.
func (s *Store) CreateGrant(ctx context.Context, p GrantCreateParams) (*Grant, error) {
	if s.db == nil {
		return nil, errors.New("mcpagg: database not available")
	}
	toolsJSON, err := encodeTools(p.AllowedTools)
	if err != nil {
		return nil, err
	}
	cols := []string{"org_id", "agent_id", "server_name", "allowed_tools", "enabled"}
	args := []any{p.OrgID, p.AgentID, p.ServerName, toolsJSON, p.Enabled}
	if p.AllowedActions != nil {
		actionsJSON, err := encodeActions(*p.AllowedActions)
		if err != nil {
			return nil, err
		}
		cols = append(cols, "allowed_actions")
		args = append(args, actionsJSON)
	}
	placeholders := make([]string, len(args))
	for i := range args {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
	}
	row := s.db.QueryRow(ctx,
		`INSERT INTO mcp_server_grants (`+strings.Join(cols, ", ")+`)
		 VALUES (`+strings.Join(placeholders, ", ")+`)
		 RETURNING `+grantScanCols,
		args...)
	g, err := scanGrant(row)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("mcpagg: grant for agent %q on %q already exists", p.AgentID, p.ServerName)
		}
		return nil, err
	}
	return g, nil
}

// UpdateGrant applies a partial update to the agent's grant on the server.
func (s *Store) UpdateGrant(ctx context.Context, orgID, agentID, serverName string, p GrantUpdateParams) (*Grant, error) {
	if s.db == nil {
		return nil, errors.New("mcpagg: database not available")
	}
	sets := []string{}
	args := []any{orgID, agentID, serverName}
	n := 4
	if p.AllowedTools != nil {
		toolsJSON, err := encodeTools(*p.AllowedTools)
		if err != nil {
			return nil, err
		}
		sets = append(sets, fmt.Sprintf("allowed_tools = $%d", n))
		args = append(args, toolsJSON)
		n++
	}
	if p.AllowedActions != nil {
		actionsJSON, err := encodeActions(*p.AllowedActions)
		if err != nil {
			return nil, err
		}
		sets = append(sets, fmt.Sprintf("allowed_actions = $%d", n))
		args = append(args, actionsJSON)
		n++
	}
	if p.Enabled != nil {
		sets = append(sets, fmt.Sprintf("enabled = $%d", n))
		args = append(args, *p.Enabled)
	}
	if len(sets) == 0 {
		return s.GetGrant(ctx, orgID, agentID, serverName)
	}
	sets = append(sets, "updated_at = now()")
	row := s.db.QueryRow(ctx,
		`UPDATE mcp_server_grants SET `+strings.Join(sets, ", ")+
			` WHERE org_id = $1 AND agent_id = $2 AND server_name = $3 RETURNING `+grantScanCols,
		args...)
	g, err := scanGrant(row)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return g, nil
}

// DeleteGrant revokes the agent's grant on the server. ErrNotFound when absent.
func (s *Store) DeleteGrant(ctx context.Context, orgID, agentID, serverName string) error {
	if s.db == nil {
		return errors.New("mcpagg: database not available")
	}
	tag, err := s.db.Exec(ctx,
		`DELETE FROM mcp_server_grants WHERE org_id = $1 AND agent_id = $2 AND server_name = $3`,
		orgID, agentID, serverName)
	if err != nil {
		return fmt.Errorf("mcpagg: delete grant: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListGrantsForAgent returns all enabled grants held by the agent (admin reads
// + ADL-03 delegation: the parent's grant set is the ceiling a child may be
// issued). Newest first.
func (s *Store) ListGrantsForAgent(ctx context.Context, orgID, agentID string) ([]*Grant, error) {
	if s.db == nil {
		return nil, errors.New("mcpagg: database not available")
	}
	rows, err := s.db.Query(ctx,
		`SELECT `+grantScanCols+` FROM mcp_server_grants
		 WHERE org_id = $1 AND agent_id = $2 AND enabled ORDER BY created_at DESC`,
		orgID, agentID)
	if err != nil {
		return nil, fmt.Errorf("mcpagg: list agent grants: %w", err)
	}
	defer rows.Close()
	var out []*Grant
	for rows.Next() {
		t := &grantScanTarget{}
		if err := rows.Scan(t.scanArgs()...); err != nil {
			return nil, err
		}
		g, err := t.toGrant()
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("mcpagg: list agent grants: %w", err)
	}
	return out, nil
}

// ListGrantsForServer returns all grants on the named server (admin reads),
// newest first.
func (s *Store) ListGrantsForServer(ctx context.Context, orgID, serverName string) ([]*Grant, error) {
	if s.db == nil {
		return nil, errors.New("mcpagg: database not available")
	}
	rows, err := s.db.Query(ctx,
		`SELECT `+grantScanCols+` FROM mcp_server_grants
		 WHERE org_id = $1 AND server_name = $2 ORDER BY created_at DESC`,
		orgID, serverName)
	if err != nil {
		return nil, fmt.Errorf("mcpagg: list grants: %w", err)
	}
	defer rows.Close()
	var out []*Grant
	for rows.Next() {
		t := &grantScanTarget{}
		if err := rows.Scan(t.scanArgs()...); err != nil {
			return nil, err
		}
		g, err := t.toGrant()
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("mcpagg: list grants: %w", err)
	}
	return out, nil
}

func encodeTools(tools []string) ([]byte, error) {
	if tools == nil {
		tools = []string{}
	}
	return json.Marshal(tools)
}

// validGrantActions is the action vocabulary (grantcheck.go, migration 0020
// CHECK parity): the two things a grant can authorize on a server.
var validGrantActions = map[string]struct{}{
	GrantActionInvoke: {},
	GrantActionList:   {},
}

// encodeActions validates and encodes the grant action vocabulary: known
// actions only, no duplicates, at most the full vocabulary (the CHECK in
// migration 0020 rejects anything else — the Go side gives the same answer
// before the round trip). An empty slice encodes [] (deny all actions) —
// a real restriction, not an omission.
func encodeActions(actions []string) ([]byte, error) {
	if len(actions) > len(validGrantActions) {
		return nil, fmt.Errorf("mcpagg: grant action list has %d entries, vocabulary has %d",
			len(actions), len(validGrantActions))
	}
	seen := make(map[string]struct{}, len(actions))
	for _, a := range actions {
		if _, ok := validGrantActions[a]; !ok {
			return nil, fmt.Errorf("mcpagg: %q is not a known grant action (vocabulary: %s, %s)",
				a, GrantActionInvoke, GrantActionList)
		}
		if _, dup := seen[a]; dup {
			return nil, fmt.Errorf("mcpagg: grant action %q is duplicated", a)
		}
		seen[a] = struct{}{}
	}
	if actions == nil {
		actions = []string{}
	}
	return json.Marshal(actions)
}

// isUniqueViolation reports whether err is a Postgres unique-violation
// (23505) — the (org_id, name) uniqueness constraint.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// scanServerFromRows scans one row of a List query (same column order as
// scanCols).
func scanServerFromRows(rows pgx.Rows) (*Server, error) {
	t := &serverScanTarget{}
	if err := rows.Scan(t.scanArgs()...); err != nil {
		return nil, err
	}
	return t.toServer()
}

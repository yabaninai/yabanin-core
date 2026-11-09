package inventory

// E02-P01 W02-C02: the import runner — incremental MCP registry import.
// Incrementality is registry-state-driven: the last imported server
// payload already carries config_version and allowed_tools, so a pass
// re-lists a server's tools only when that server's configuration moved
// (config_version bump or allowed_tools delta). Unchanged servers still
// refresh their server row (a cheap last_seen touch); their tool surface
// is skipped. State lives in the registry itself — no side table.

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

// ImportRunner drives MCP registry import passes for orgs.
type ImportRunner struct {
	store   *Store
	servers ServerSource
	tools   ToolSource
	now     func() time.Time
}

// NewImportRunner wires the runner. A nil now defaults to UTC wall time
// (tests inject a fixed clock).
func NewImportRunner(store *Store, servers ServerSource, tools ToolSource) (*ImportRunner, error) {
	if store == nil {
		return nil, ErrNilStore
	}
	if servers == nil || tools == nil {
		return nil, ErrNilSource
	}
	return &ImportRunner{store: store, servers: servers, tools: tools,
		now: func() time.Time { return time.Now().UTC() }}, nil
}

// serverConfigMoved reports whether the server's configuration advanced
// past the last imported snapshot. A missing snapshot (first import or
// tombstoned row) always refreshes.
func serverConfigMoved(prev *Row, srv serverSnapshot) bool {
	if prev == nil {
		return true
	}
	var p MCPServerPayload
	if err := json.Unmarshal(prev.Payload, &p); err != nil {
		return true // unreadable prior state — safest is a full refresh
	}
	// ToolsSynced is required: a snapshot left by a missed tool listing
	// carries the same config_version but no fresh tool surface — the
	// next pass must retry the listing, not skip it.
	return !p.ToolsSynced || p.ConfigVersion != srv.ConfigVersion ||
		!slices.Equal(p.AllowedTools, srv.AllowedTools)
}

// serverSnapshot is the minimal config identity the incrementality check
// needs (extracted so the check stays testable without mcpagg types).
type serverSnapshot struct {
	ConfigVersion int64
	AllowedTools  []string
}

// Run executes one incremental import pass for the org.
func (r *ImportRunner) Run(ctx context.Context, orgID string) (*MCPImportReport, error) {
	list, err := r.servers.List(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("inventory: list mcp servers: %w", err)
	}
	now := r.now()
	report := &MCPImportReport{}
	var batch []Asset
	for _, srv := range list {
		res := ServerImportResult{Name: srv.Name, ConfigVersion: srv.ConfigVersion}
		key := MCPServerKey(srv.Name)

		prev, found, err := r.store.GetAsset(ctx, orgID, KindMCPServer, key)
		if err != nil {
			return nil, fmt.Errorf("inventory: read prior server state %s: %w", key, err)
		}
		if found && !serverConfigMoved(&prev, serverSnapshot{ConfigVersion: srv.ConfigVersion, AllowedTools: srv.AllowedTools}) {
			// Configuration unchanged and the tool surface was synced:
			// refresh only the server row (kept marked as synced).
			res.Skipped = true
			// found ⇒ the row previously imported ⇒ its name passed the
			// registry rules then, so the build cannot fail here.
			assets, _, _ := BuildMCPImportAssets(Timestamps{FirstSeen: now, LastSeen: now}, orgID, srv, nil, nil, true)
			batch = append(batch, assets...)
			report.Servers = append(report.Servers, res)
			continue
		}

		descs, err := r.tools.ListTools(ctx, orgID, srv.Name)
		switch {
		case err != nil:
			// Tool surface unknown this pass; server identity still lands
			// (unmarked for sync so the next pass retries) — unless the
			// server entry itself fails the registry rules.
			res.Error = err.Error()
			assets, dropped, berr := BuildMCPImportAssets(Timestamps{FirstSeen: now, LastSeen: now}, orgID, srv, nil, nil, false)
			if berr != nil {
				res.Error = berr.Error()
			} else {
				res.DroppedTools = len(dropped)
				batch = append(batch, assets...)
			}
		default:
			res.ToolsSeen = len(descs)
			assets, dropped, berr := BuildMCPImportAssets(Timestamps{FirstSeen: now, LastSeen: now}, orgID, srv, descs, srv.AllowedTools, true)
			if berr != nil {
				res.Error = berr.Error()
			} else {
				res.ToolsImported = len(assets) - 1
				res.DroppedTools = len(dropped)
				batch = append(batch, assets...)
			}
		}
		report.Servers = append(report.Servers, res)
	}
	if len(batch) > 0 {
		counts, err := r.store.UpsertAssets(ctx, batch)
		if err != nil {
			return nil, fmt.Errorf("inventory: upsert mcp import batch: %w", err)
		}
		report.Counts = counts
	}
	return report, nil
}

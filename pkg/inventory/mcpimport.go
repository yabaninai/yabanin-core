package inventory

// E02-P01 W02-C01: import of the MCP registry into the observable asset
// registry. Servers become mcp_server assets, their advertised (and, when
// configured, allow-listed) tools become mcp_tool assets. Source is
// mcp_registry, confidence high — both are write-model invariants enforced
// by Asset.Validate.
//
// The upstream seams are narrow interfaces: ServerSource is satisfied by
// *mcpagg.Store.List, ToolSource by an adapter over
// *mcpagg.Proxy.ListServerTools (the live-HTTP call needs an Identity and
// grant posture, so its wiring is deferred to the runner card W02-C02;
// tests use fixtures). This keeps the import logic testable without a
// database or an upstream MCP server.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/reireirei/yabanin/pkg/mcpagg"
)

// ServerSource lists an org's MCP servers (satisfied by *mcpagg.Store).
type ServerSource interface {
	List(ctx context.Context, orgID string) ([]*mcpagg.Server, error)
}

// ToolSource lists the tools one server advertises (satisfied by an
// adapter over *mcpagg.Proxy.ListServerTools in the runner card).
type ToolSource interface {
	ListTools(ctx context.Context, orgID, server string) ([]mcpagg.ToolDescriptor, error)
}

// MCPServerPayload is the registry payload of one mcp_server asset: the
// operator-relevant server identity and state at import time.
// ToolsSynced marks whether the tool surface in this snapshot came from a
// successful listing (absent/false = the last pass missed the upstream —
// incrementality must not treat that as fresh).
type MCPServerPayload struct {
	Name           string   `json:"name"`
	DisplayName    string   `json:"display_name,omitempty"`
	URL            string   `json:"url"`
	Transport      string   `json:"transport"`
	AllowedTools   []string `json:"allowed_tools,omitempty"`
	Enabled        bool     `json:"enabled"`
	CredentialMode string   `json:"credential_mode"`
	ConfigVersion  int64    `json:"config_version"`
	ToolsSynced    bool     `json:"tools_synced,omitempty"`
}

// MCPToolPayload is the registry payload of one mcp_tool asset.
type MCPToolPayload struct {
	Server      string          `json:"server"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
}

// ServerImportResult records what one server contributed to an import
// pass. A tool-listing error (disabled server, unreachable upstream,
// missing grant posture) does not fail the import: that server's tools
// are simply not refreshed, and the miss is reported here for the
// operator. DroppedTools counts advertised descriptors rejected by the
// key rules (never silently discarded). Skipped marks a server whose
// configuration did not move since the last pass — its tool surface was
// not re-listed (W02-C02 incrementality).
type ServerImportResult struct {
	Name          string `json:"name"`
	ConfigVersion int64  `json:"config_version"`
	ToolsSeen     int    `json:"tools_seen"`
	ToolsImported int    `json:"tools_imported"`
	DroppedTools  int    `json:"dropped_tools"`
	Skipped       bool   `json:"skipped,omitempty"`
	Error         string `json:"error,omitempty"`
}

// MCPImportReport is the outcome of one ImportMCPRegistry pass.
type MCPImportReport struct {
	Servers []ServerImportResult
	Counts  ImportCounts
}

// ErrNilSource marks a wiring defect (nil seam passed to the importer).
var ErrNilSource = errors.New("inventory: nil MCP source")

// ErrNilStore marks a wiring defect (nil registry store).
var ErrNilStore = errors.New("inventory: nil store")

// MCPServerKey is the deterministic asset key of a registered MCP server.
func MCPServerKey(name string) string { return "mcp_server:" + name }

// MCPToolKey is the deterministic asset key of one server's tool.
func MCPToolKey(server, tool string) string { return "mcp_tool:" + server + "/" + tool }

// BuildMCPImportAssets derives the asset batch for one server and its
// advertised tools. When allowed is non-empty (the server's configured
// allow-list) only those tool names are imported; nil/empty means "all
// advertised tools". toolsSynced records whether tools came from a
// successful listing (false on an upstream miss — see MCPServerPayload).
//
// Adversarial posture (W02-C03): the upstream is untrusted. A server name
// that fails the mcpagg registry rules (which exclude "/" — keeping
// mcp_tool:<server>/<tool> keys unambiguous) makes the whole entry
// unimportable and returns an error; the caller reports it and imports
// the remaining servers. Tool descriptors that would poison the batch
// are dropped and REPORTED, never silently: names failing the key rules,
// duplicate names within one listing (a duplicate would hit the same
// conflict key twice in one statement and fail the whole org import),
// and payloads that do not marshal (a corrupt InputSchema).
func BuildMCPImportAssets(at Timestamps, orgID string, srv *mcpagg.Server, tools []mcpagg.ToolDescriptor, allowed []string, toolsSynced bool) (assets []Asset, dropped []string, err error) {
	if err := mcpagg.ValidateServerName(srv.Name); err != nil {
		return nil, nil, fmt.Errorf("inventory: server name fails registry rules: %w", err)
	}
	serverPayload, err := json.Marshal(MCPServerPayload{
		Name:           srv.Name,
		DisplayName:    deref(srv.DisplayName),
		URL:            srv.URL,
		Transport:      srv.Transport,
		AllowedTools:   srv.AllowedTools,
		Enabled:        srv.Enabled,
		CredentialMode: srv.CredentialMode,
		ConfigVersion:  srv.ConfigVersion,
		ToolsSynced:    toolsSynced,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("inventory: marshal server payload: %w", err)
	}
	assets = append(assets, Asset{
		OrgID: orgID, AssetKey: MCPServerKey(srv.Name), Kind: KindMCPServer,
		Payload: serverPayload, Source: SourceMCPRegistry, Confidence: ConfidenceHigh,
		FirstSeen: at.FirstSeen, LastSeen: at.LastSeen,
	})
	allow := map[string]bool{}
	if len(allowed) > 0 {
		for _, t := range allowed {
			allow[t] = true
		}
	}
	seen := map[string]bool{}
	for _, td := range tools {
		if len(allow) > 0 && !allow[td.Name] {
			continue
		}
		if validKeyPart("tool", td.Name) != nil {
			dropped = append(dropped, td.Name)
			continue
		}
		if seen[td.Name] {
			// A duplicate would address the same conflict key twice in
			// one upsert statement and abort the whole batch.
			dropped = append(dropped, td.Name)
			continue
		}
		seen[td.Name] = true
		payload, err := json.Marshal(MCPToolPayload{
			Server:      srv.Name,
			Description: td.Description,
			InputSchema: td.InputSchema,
		})
		if err != nil {
			// Corrupt InputSchema: marshal fails; drop the descriptor
			// rather than emit an empty (invalid) payload.
			dropped = append(dropped, td.Name)
			continue
		}
		assets = append(assets, Asset{
			OrgID: orgID, AssetKey: MCPToolKey(srv.Name, td.Name), Kind: KindTool,
			Payload: payload, Source: SourceMCPRegistry, Confidence: ConfidenceHigh,
			FirstSeen: at.FirstSeen, LastSeen: at.LastSeen,
		})
	}
	return assets, dropped, nil
}

// Timestamps carries the import pass observation window.
type Timestamps struct {
	FirstSeen, LastSeen time.Time
}

// ImportMCPRegistry runs one import pass: every server of the org becomes
// (or refreshes) an mcp_server asset, and every server whose ToolSource
// answers contributes its allow-listed tool assets. The batch is upserted
// atomically through the registry store; per-server misses are reported,
// not fatal.
func ImportMCPRegistry(ctx context.Context, store *Store, orgID string, servers ServerSource, tools ToolSource, at Timestamps) (*MCPImportReport, error) {
	if store == nil {
		return nil, ErrNilStore
	}
	if servers == nil || tools == nil {
		return nil, ErrNilSource
	}
	list, err := servers.List(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("inventory: list mcp servers: %w", err)
	}
	report := &MCPImportReport{}
	var batch []Asset
	for _, srv := range list {
		res := ServerImportResult{Name: srv.Name, ConfigVersion: srv.ConfigVersion}
		descs, err := tools.ListTools(ctx, orgID, srv.Name)
		switch {
		case err != nil:
			// The tool surface is unknown this pass, but the server's
			// identity is a registry fact — it still imports (nil tools
			// builds the server row only, unmarked for sync), and the
			// miss is reported.
			res.Error = err.Error()
			assets, dropped, berr := BuildMCPImportAssets(at, orgID, srv, nil, nil, false)
			if berr != nil {
				res.Error = berr.Error()
			} else {
				res.DroppedTools = len(dropped)
				batch = append(batch, assets...)
			}
		default:
			res.ToolsSeen = len(descs)
			assets, dropped, berr := BuildMCPImportAssets(at, orgID, srv, descs, srv.AllowedTools, true)
			if berr != nil {
				res.Error = berr.Error()
			} else {
				res.ToolsImported = len(assets) - 1 // minus the server row
				res.DroppedTools = len(dropped)
				batch = append(batch, assets...)
			}
		}
		report.Servers = append(report.Servers, res)
	}
	if len(batch) > 0 {
		counts, err := store.UpsertAssets(ctx, batch)
		if err != nil {
			return nil, fmt.Errorf("inventory: upsert mcp import batch: %w", err)
		}
		report.Counts = counts
	}
	return report, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

package mcp

import (
	"os"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/delegation"
)

// DelegationOptions is the optional MCP wiring for tr_delegate. Zero value /
// nil means the tool is not registered and no executors are started.
type DelegationOptions struct {
	Enabled      bool
	Orchestrator *delegation.Orchestrator
}

// DelegationFromEnv constructs options from process environment (routed
// through pkg/config). When the flag is off, the returned Enabled is false
// and Orchestrator is nil so MCP start does not allocate executors or
// network clients.
func DelegationFromEnv() *DelegationOptions {
	env := config.DelegationFromEnv()
	if !env.Enabled {
		return &DelegationOptions{Enabled: false}
	}
	ws := env.Workspace
	if ws == "" {
		ws, _ = os.Getwd()
	}
	bridge := env.BridgeURL
	var execs []delegation.Executor
	if bridge != "" {
		execs = append(execs,
			delegation.NewBridgeExecutor(string(delegation.ProviderCodex), bridge),
			delegation.NewBridgeExecutor(string(delegation.ProviderCursor), bridge),
		)
	} else {
		execs = append(execs,
			delegation.NewFakeExecutor(string(delegation.ProviderCodex)),
			delegation.NewFakeExecutor(string(delegation.ProviderCursor)),
		)
	}
	return &DelegationOptions{
		Enabled:      true,
		Orchestrator: delegation.NewOrchestrator(ws, execs...),
	}
}

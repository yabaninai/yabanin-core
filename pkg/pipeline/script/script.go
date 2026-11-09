// Package script is the mount point for policy `when` condition engines.
// OP-0a fixes only the seam; OP-7 owns the implementations (Lua candidate
// with Starlark/expr challengers — owner decision 2026-10-06).
//
// The core engine (pkg/pipeline) never interprets condition sources. A
// policy step with `when:` compiles ONLY through an engine that was
// registered on the pipeline Engine before compilation:
//
//	eng := pipeline.NewEngine()
//	var lua script.Engine = mylua.New(...)          // OP-7 implementation
//	eng.Scripts().Register(lua.Name(), lua.Compile) // name matches when_engine
//	compiled, err := eng.LoadPolicy(policyYAML)     // unregistered => load error
//
// Engines are registered by Name(); with exactly one engine registered it is
// the default for steps that omit when_engine, otherwise when_engine is
// required. Compilation happens once per step at policy load; the returned
// Program must be deterministic, side-effect free, safe for concurrent
// Evaluate calls, and internally sandboxed with bounded time and memory —
// the pipeline engine enforces no budget around Evaluate beyond the caller's
// context. Condition evaluation errors follow the step's on_error mode, so a
// broken engine fail-closes by default.
//
// Changing the condition language (OP-7 outcome) must not change the YAML
// policy model: engines differ, this interface does not.
package script

import "github.com/reireirei/yabanin/pkg/pipeline"

// Engine compiles `when` condition sources of policy steps into runnable
// programs. Implementations are registered by Name into the pipeline
// engine's script registry (pipeline.Engine.Scripts).
type Engine interface {
	// Name returns the registry name policies reference via when_engine.
	Name() string
	// Compile parses one condition source. Called once per conditioned step
	// at policy load; an error here fails the policy load.
	Compile(source string) (pipeline.ConditionProgram, error)
}

// Env is the read-only evaluation context handed to programs: findings
// recorded so far, step traces so far, and request meta.
type Env = pipeline.ConditionEnv

// Program is one compiled condition produced by Engine.Compile.
type Program = pipeline.ConditionProgram

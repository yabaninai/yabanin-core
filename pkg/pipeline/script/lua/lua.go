// Package lua is the OP-7 Lua condition engine (the owner's candidate):
// github.com/yuin/gopher-lua, a pure-Go Lua 5.1 VM, sandboxed for policy
// `when` conditions.
//
// SANDBOX MODEL (verified against gopher-lua v1.1.2 source):
//
//   - Budgets (deterministic first): gopher-lua has NO debug hooks, but its
//     context-enabled main loop calls ctx.Done() on EVERY instruction
//     dispatch, so Evaluate runs each chunk under a step budget
//     (DefaultMaxSteps VM dispatches) enforced by the VM itself —
//     machine-independent, immune to GC pauses and runner load — plus a
//     wall-clock ceiling (DefaultEvalTimeout, scaled on -race builds, see
//     race_on.go) that backstops single huge operations such as one massive
//     concat. A runaway chunk aborts with "evaluation budget exceeded" and
//     unrolls.
//   - Stdlib is an allowlist: base (pairs/ipairs/type/tonumber/tostring/
//     select/error/assert/next/rawget/rawequal/rawlen/pcall), string, table,
//     math. os/io/debug/load/loadstring/dofile/loadfile/require/print/_G/
//     setmetatable/getmetatable/getfenv/setfenv/rawset/collectgarbage and
//     math.random/math.randomseed are removed before any script runs.
//   - Allocation guards: string.rep/string.format/table.concat are wrapped
//     with a result-size cap (DefaultMaxStringResult). KNOWN GAP, documented
//     for the owner decision: the `..` concat operator is a VM opcode with
//     no hook, so `s = s .. s` loops can transiently allocate at roughly
//     wall-clock × machine copy rate before the deadline fires; the deadline
//     bounds the time and therefore the peak, but a precise per-engine
//     memory cap would require a gopher-lua fork.
//   - Recursion depth is bounded by Options.CallStackSize; data-stack growth
//     beyond the fixed registry size is refused.
//   - pcall stays available and is NOT an escape hatch (verified empirically
//     against v1.1.2): basePCall wraps the nested call in a Go-side PCall, so
//     a context abort raised inside a protected call is swallowed once and
//     re-raised by the main VM loop outside every Lua error barrier.
//   - Scripts see ONLY the condition env roots (findings, steps, meta —
//     contract in the parent package) plus the allowlisted stdlib. The chunk
//     must RETURN a boolean; anything else is an evaluation error, so a
//     condition can never fail open.
//
// The condition source may be a bare expression (`findings.count(...) > 0`)
// or a full chunk with an explicit `return`. Compilation happens once per
// source (sha256-keyed cache of the compiled chunk prototype); evaluation
// runs on pooled LStates whose globals are reset to the sealed set per call.
// Programs are safe for concurrent Evaluate; LStates are never shared
// between concurrent evaluations and are discarded after any error.
package lua

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	glua "github.com/yuin/gopher-lua"

	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/reireirei/yabanin/pkg/pipeline/script"
)

// Sandbox defaults. Budgets are ceilings: a typical condition finishes in
// microseconds and never approaches them (see bench_test.go in the parent
// package).
const (
	maxConditionSourceBytes = 16 << 10
	maxEnvItems             = 4096
	maxEnvBytes             = 1 << 20
	// DefaultEvalTimeout is the per-evaluation wall-clock CEILING. It only
	// backstops work between dispatch checks (one huge allocation-heavy
	// opcode); boundedness itself comes from DefaultMaxSteps. New scales it
	// by raceWallScale on -race builds (load tolerance, not semantics).
	DefaultEvalTimeout = 5 * time.Millisecond
	// DefaultMaxSteps is the deterministic per-evaluation budget of VM
	// instruction dispatches. It exceeds what a legit condition needs at the
	// env-size limit (a 4096-item scan costs ~250k dispatches), so the wall
	// ceiling stays the binding production bound while runaway scripts die
	// at the same dispatch count on every machine.
	DefaultMaxSteps = 1_000_000
	// raceWallScale is applied to wall ceilings on -race builds only.
	raceWallScale = 10
	// DefaultMaxStringResult caps string.rep/string.format/table.concat
	// results (1 MiB).
	DefaultMaxStringResult = 1 << 20
	// Call stack (recursion depth) and fixed data-stack size.
	luaCallStackSize = 256
	luaRegistrySize  = 8192
	// cacheLimit caps the compiled-chunk cache; on overflow the cache resets
	// (spike-simple, bounded memory, no eviction policy needed).
	cacheLimit = 1024
)

// Engine compiles Lua condition sources. Create with New, then register
// under Name ("lua") on pipeline.Engine.Scripts.
type Engine struct {
	evalTimeout time.Duration
	maxSteps    int64
	maxString   int

	pool      sync.Pool // *glua.LState with sealed stdlib
	evalSlots chan struct{}

	mu    sync.Mutex
	cache map[[sha256.Size]byte]*glua.FunctionProto
}

// Option configures an Engine.
type Option func(*Engine)

// WithEvalTimeout overrides the per-evaluation wall-clock ceiling; on -race
// builds New scales it by raceWallScale. The step budget is unaffected.
func WithEvalTimeout(d time.Duration) Option { return func(e *Engine) { e.evalTimeout = d } }

// WithMaxSteps overrides the deterministic per-evaluation VM dispatch
// budget; n <= 0 is ignored and the engine keeps its current budget.
func WithMaxSteps(n int64) Option {
	return func(e *Engine) {
		if n > 0 {
			e.maxSteps = n
		}
	}
}

// WithMaxStringResult overrides the guarded-stdlib result cap.
func WithMaxStringResult(n int) Option { return func(e *Engine) { e.maxString = n } }

// WithMaxWorkers sets the maximum number of concurrent VM evaluations. A
// value of zero or less is ignored and the engine keeps the
// script.DefaultMaxWorkers default set by New.
func WithMaxWorkers(n int) Option {
	return func(e *Engine) {
		if n > 0 {
			e.evalSlots = make(chan struct{}, n)
		}
	}
}

// New returns a Lua condition engine with sandbox defaults.
func New(opts ...Option) *Engine {
	e := &Engine{
		evalTimeout: DefaultEvalTimeout,
		maxSteps:    DefaultMaxSteps,
		maxString:   DefaultMaxStringResult,
		evalSlots:   make(chan struct{}, script.DefaultMaxWorkers),
		cache:       make(map[[sha256.Size]byte]*glua.FunctionProto),
	}
	for _, opt := range opts {
		opt(e)
	}
	if raceEnabled {
		e.evalTimeout *= raceWallScale
	}
	e.pool.New = func() any { return e.newState() }
	return e
}

// Name is the registry name policies reference via when_engine: "lua".
func (e *Engine) Name() string { return "lua" }

// Compile parses and compiles one condition source once (cache keyed by the
// source hash). Compile-time failures fail the policy load (seam contract).
func (e *Engine) Compile(source string) (pipeline.ConditionProgram, error) {
	if len(source) > maxConditionSourceBytes {
		return nil, fmt.Errorf("lua: source exceeds %d-byte limit", maxConditionSourceBytes)
	}
	key := sha256.Sum256([]byte(source))
	e.mu.Lock()
	if proto, ok := e.cache[key]; ok {
		e.mu.Unlock()
		return &program{engine: e, proto: proto}, nil
	}
	e.mu.Unlock()

	proto, err := e.compile(source)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	if len(e.cache) >= cacheLimit {
		e.cache = make(map[[sha256.Size]byte]*glua.FunctionProto)
	}
	e.cache[key] = proto
	e.mu.Unlock()
	return &program{engine: e, proto: proto}, nil
}

// compile runs the parser/compiler on a pooled state. Loading does not
// execute anything, so the state stays sealed and clean for reuse; a panic
// inside the pure-Go compiler on a pathological source is contained here
// (policy load time, admin-supplied input).
func (e *Engine) compile(source string) (proto *glua.FunctionProto, err error) {
	defer func() {
		if r := recover(); r != nil {
			proto, err = nil, fmt.Errorf("lua: compiler panic: %v", r)
		}
	}()
	L := e.acquire()
	defer e.release(L)

	if strings.TrimSpace(source) == "" {
		return nil, errors.New("lua: condition source is empty")
	}

	// Expression form first: Lua allows function CALLS as statements, so a
	// call-style condition (`findings.any(...)`) parses as a chunk too and
	// would silently discard its result in chunk mode. `return (source)`
	// only parses for genuine expressions; full chunks (statements, explicit
	// return) fall back to chunk mode.
	fn, chunkErr := L.Load(strings.NewReader("return ("+source+")"), "when(expr)")
	if chunkErr != nil {
		fnChunk, err := L.Load(strings.NewReader(source), "when")
		if err != nil {
			return nil, fmt.Errorf("lua: %w", chunkErr)
		}
		fn = fnChunk
	}
	return fn.Proto, nil
}

// program is one compiled Lua condition.
type program struct {
	engine *Engine
	proto  *glua.FunctionProto
}

// Evaluate runs the compiled chunk against env under the sandbox budget.
// Errors (sandbox aborts, type errors, runtime errors) are returned, never
// cause a false — the caller applies on_error semantics.
func (p *program) Evaluate(ctx context.Context, env pipeline.ConditionEnv) (bool, error) {
	if ctx == nil {
		return false, errors.New("lua: caller context is required")
	}
	if err := checkEnvironmentBudget(env); err != nil {
		return false, err
	}
	e := p.engine
	select {
	case e.evalSlots <- struct{}{}:
		defer func() { <-e.evalSlots }()
	case <-ctx.Done():
		return false, fmt.Errorf("lua: caller context: %w", ctx.Err())
	}
	L := e.acquire()
	clean := false
	defer func() {
		if clean {
			e.release(L)
		} else {
			L.Close() // discarded after any error; never reused
		}
	}()

	resetGlobals(L)
	setEnv(L, env)

	budget := newBudgetContext(ctx, e.maxSteps, e.evalTimeout)
	defer budget.stop()
	L.SetContext(budget)
	L.Push(L.NewFunctionFromProto(p.proto))
	err := L.PCall(0, 1, nil)
	L.RemoveContext()
	if err != nil {
		switch {
		case ctx.Err() != nil:
			return false, fmt.Errorf("lua: caller context: %w", ctx.Err())
		case errors.Is(budget.Err(), errStepBudget):
			return false, fmt.Errorf("lua: evaluation budget exceeded (%d steps): %w", e.maxSteps, err)
		case errors.Is(budget.Err(), errWallCeiling):
			return false, fmt.Errorf("lua: evaluation budget exceeded (%s wall): %w", e.evalTimeout, err)
		default:
			return false, fmt.Errorf("lua: %w", err)
		}
	}

	res := L.Get(-1)
	L.Pop(1)
	b, ok := res.(glua.LBool)
	if !ok {
		return false, fmt.Errorf("lua: condition must return a boolean, got %s", res.Type().String())
	}
	clean = true
	return bool(b), nil
}

func checkEnvironmentBudget(env pipeline.ConditionEnv) error {
	items := len(env.Findings) + len(env.Steps)
	bytes := 0
	add := func(value string) { bytes += len(value) }
	for _, finding := range env.Findings {
		add(finding.Step)
		add(finding.Category)
		add(finding.Severity)
		add(finding.Span)
		add(finding.Evidence)
		add(string(finding.Action))
	}
	for _, step := range env.Steps {
		add(step.Step)
		add(string(step.Outcome))
		add(step.Error)
	}
	if env.Meta != nil {
		add(env.Meta.Org)
		add(env.Meta.Key)
		add(env.Meta.Model)
		add(env.Meta.Provider)
		items += len(env.Meta.Tags) + len(env.Meta.Labels)
		for _, tag := range env.Meta.Tags {
			add(tag)
		}
		for key, value := range env.Meta.Labels {
			add(key)
			add(value)
		}
	}
	if items > maxEnvItems || bytes > maxEnvBytes {
		return fmt.Errorf("lua: evaluation input exceeds limits (items=%d bytes=%d)", items, bytes)
	}
	return nil
}

// acquire gets a sealed state from the pool.
func (e *Engine) acquire() *glua.LState {
	return e.pool.Get().(*glua.LState)
}

// release returns a clean state to the pool.
func (e *Engine) release(L *glua.LState) {
	e.pool.Put(L)
}

// newState builds one sandboxed LState: allowlisted stdlib only, guarded
// string operations, hard stack limits.
func (e *Engine) newState() *glua.LState {
	L := glua.NewState(glua.Options{
		SkipOpenLibs:    true,
		CallStackSize:   luaCallStackSize,
		RegistrySize:    luaRegistrySize,
		RegistryMaxSize: 0, // refuse registry growth
	})
	glua.OpenBase(L)
	glua.OpenString(L)
	glua.OpenTable(L)
	glua.OpenMath(L)
	sealGlobals(L, e.maxString)
	return L
}

// baseAllowlist is the only base library exposed to conditions.
var baseAllowlist = map[string]bool{
	"pairs": true, "ipairs": true, "next": true,
	"tonumber": true, "tostring": true, "type": true, "select": true,
	"error": true, "assert": true,
	"rawget": true, "rawequal": true, "rawlen": true,
	"pcall": true,
}

// sealGlobals deletes everything outside the allowlist from _G and wraps the
// allocation-capable stdlib functions with size-guarded versions.
func sealGlobals(L *glua.LState, maxString int) {
	keep := make(map[glua.LString]bool, len(baseAllowlist)+3)
	for name := range baseAllowlist {
		keep[glua.LString(name)] = true
	}
	for _, name := range []string{"string", "table", "math"} {
		keep[glua.LString(name)] = true
	}

	var foreign []glua.LValue
	L.Env.ForEach(func(k, _ glua.LValue) {
		if name, ok := k.(glua.LString); !ok || !keep[name] {
			foreign = append(foreign, k)
		}
	})
	for _, k := range foreign {
		L.Env.RawSetH(k, glua.LNil)
	}

	guardMath(L)
	guardStrings(L, maxString)
}

// guardMath removes the nondeterministic random source (fail-closed: any
// use raises "attempt to call a nil value (field 'random')").
func guardMath(L *glua.LState) {
	math, ok := L.GetGlobal("math").(*glua.LTable)
	if !ok {
		return
	}
	math.RawSetString("random", glua.LNil)
	math.RawSetString("randomseed", glua.LNil)
}

// guardStrings wraps string.rep/string.format/table.concat with a result
// size cap. The originals are captured per state (they belong to it).
func guardStrings(L *glua.LState, maxString int) {
	stringTbl, ok := L.GetGlobal("string").(*glua.LTable)
	if !ok {
		return
	}
	origRep, _ := stringTbl.RawGetString("rep").(*glua.LFunction)
	origFmt, _ := stringTbl.RawGetString("format").(*glua.LFunction)
	tableTbl, _ := L.GetGlobal("table").(*glua.LTable)
	origConcat, _ := tableTbl.RawGetString("concat").(*glua.LFunction)

	if origRep != nil {
		rep := origRep
		stringTbl.RawSetString("rep", L.NewClosure(func(L *glua.LState) int {
			s, _ := L.Get(1).(*glua.LString)
			n, okN := L.Get(2).(glua.LNumber)
			if s == nil || !okN {
				L.RaiseError("bad argument to string.rep (string, number expected)")
				return 0
			}
			total := int64(len(*s)) * int64(n)
			if total > int64(maxString) {
				L.RaiseError("string.rep result %d exceeds sandbox cap %d", total, maxString)
				return 0
			}
			L.Push(rep) //nolint:gocritic // original captured above
			L.Push(L.Get(1))
			L.Push(L.Get(2))
			L.Call(2, 1)
			return 1
		}))
	}
	if origFmt != nil {
		fmtFn := origFmt
		stringTbl.RawSetString("format", L.NewClosure(func(L *glua.LState) int {
			n := L.GetTop()
			L.Push(fmtFn)
			for i := 1; i <= n; i++ {
				L.Push(L.Get(i))
			}
			L.Call(n, 1)
			if s, ok := L.Get(-1).(*glua.LString); ok && len(*s) > maxString {
				L.RaiseError("string.format result %d exceeds sandbox cap %d", len(*s), maxString)
				return 0
			}
			return 1
		}))
	}
	if origConcat != nil && tableTbl != nil {
		concat := origConcat
		tableTbl.RawSetString("concat", L.NewClosure(func(L *glua.LState) int {
			n := L.GetTop()
			L.Push(concat)
			for i := 1; i <= n; i++ {
				L.Push(L.Get(i))
			}
			L.Call(n, 1)
			if s, ok := L.Get(-1).(*glua.LString); ok && len(*s) > maxString {
				L.RaiseError("table.concat result %d exceeds sandbox cap %d", len(*s), maxString)
				return 0
			}
			return 1
		}))
	}
}

// resetGlobals clears every global a previous evaluation may have set,
// restoring the sealed stdlib-only surface. Two-phase: collect, then delete.
func resetGlobals(L *glua.LState) {
	var foreign []glua.LValue
	L.Env.ForEach(func(k, _ glua.LValue) {
		sealed := false
		if name, ok := k.(glua.LString); ok {
			sealed = name == "string" || name == "table" || name == "math" || baseAllowlist[string(name)]
		}
		if !sealed {
			foreign = append(foreign, k)
		}
	})
	for _, k := range foreign {
		L.Env.RawSetH(k, glua.LNil)
	}
}

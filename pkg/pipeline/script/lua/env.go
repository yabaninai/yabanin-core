package lua

import (
	glua "github.com/yuin/gopher-lua"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// setEnv installs the per-evaluation condition env roots (findings, steps,
// meta — contract in the parent package) as fresh globals on a sealed state.
// All tables are rebuilt per call from the engine-provided snapshot; scripts
// can only read them.
func setEnv(L *glua.LState, env pipeline.ConditionEnv) {
	setFindings(L, env.Findings)
	setSteps(L, env.Steps)
	setMeta(L, env.Meta)
}

// setFindings exposes findings as an array table (records at 1..n) with
// collection methods any/all/none/count.
func setFindings(L *glua.LState, findings []pipeline.Finding) {
	tbl := L.NewTable()
	for i, f := range findings {
		tbl.RawSetInt(i+1, findingTable(L, f))
	}
	tbl.RawSetString("any", L.NewClosure(func(L *glua.LState) int {
		tbl, pred, ok := rootTable(L, "findings")
		if !ok {
			return 0
		}
		if pred == glua.LNil {
			L.RaiseError("findings.any(predicate): predicate function required")
			return 0
		}
		matched := false
		scanFindings(L, tbl, func() bool { return !matched }, func() {
			L.Push(pred)
			L.Push(L.Get(-2)) // current finding record (pushed by scanFindings)
			L.Call(1, 1)
			matched = matched || glua.LVAsBool(L.Get(-1))
			L.Pop(1)
		})
		L.Push(glua.LBool(matched))
		return 1
	}))
	tbl.RawSetString("all", L.NewClosure(func(L *glua.LState) int {
		tbl, pred, ok := rootTable(L, "findings")
		if !ok {
			return 0
		}
		if pred == glua.LNil {
			L.RaiseError("findings.all(predicate): predicate function required")
			return 0
		}
		// Contract: all() over an empty collection is false, not vacuously true.
		matched := tbl.Len() > 0
		scanFindings(L, tbl, func() bool { return matched }, func() {
			L.Push(pred)
			L.Push(L.Get(-2))
			L.Call(1, 1)
			matched = matched && glua.LVAsBool(L.Get(-1))
			L.Pop(1)
		})
		L.Push(glua.LBool(matched))
		return 1
	}))
	tbl.RawSetString("none", L.NewClosure(func(L *glua.LState) int {
		tbl, pred, ok := rootTable(L, "findings")
		if !ok {
			return 0
		}
		if pred == glua.LNil {
			L.RaiseError("findings.none(predicate): predicate function required")
			return 0
		}
		matched := false
		scanFindings(L, tbl, func() bool { return !matched }, func() {
			L.Push(pred)
			L.Push(L.Get(-2))
			L.Call(1, 1)
			matched = matched || glua.LVAsBool(L.Get(-1))
			L.Pop(1)
		})
		L.Push(glua.LBool(!matched))
		return 1
	}))
	tbl.RawSetString("count", L.NewClosure(func(L *glua.LState) int {
		tbl, pred, ok := rootTable(L, "findings")
		if !ok {
			return 0
		}
		n := 0
		scanFindings(L, tbl, func() bool { return true }, func() {
			if pred == glua.LNil {
				n++
				return
			}
			L.Push(pred)
			L.Push(L.Get(-2))
			L.Call(1, 1)
			if glua.LVAsBool(L.Get(-1)) {
				n++
			}
			L.Pop(1)
		})
		L.Push(glua.LNumber(n))
		return 1
	}))
	L.SetGlobal("findings", tbl)
}

// scanFindings iterates the array part of the findings table, pushing each
// record before invoking see. The record stays on the stack below any
// predicate result while see runs (see pops what it pushes).
func scanFindings(L *glua.LState, tbl *glua.LTable, more func() bool, see func()) {
	for i := 1; more() && i <= tbl.Len(); i++ {
		L.Push(tbl.RawGetInt(i))
		see()
		L.Pop(1)
	}
}

// setSteps exposes steps as a table keyed by step id (records) with the
// accessors from the env contract.
func setSteps(L *glua.LState, steps []pipeline.StepTrace) {
	tbl := L.NewTable()
	for _, st := range steps {
		tbl.RawSetH(glua.LString(st.Step), stepTable(L, st))
	}
	tbl.RawSetString("get", L.NewClosure(func(L *glua.LState) int {
		tbl, id, ok := rootTable(L, "steps")
		if !ok {
			return 0
		}
		L.Push(tbl.RawGetH(id))
		return 1
	}))
	outcomeOf := func(L *glua.LState) (string, bool) {
		tbl, id, ok := rootTable(L, "steps")
		if !ok {
			return "", false
		}
		rec, ok := tbl.RawGetH(id).(*glua.LTable)
		if !ok {
			return "", false
		}
		outcome, ok := rec.RawGetString("outcome").(glua.LString)
		return string(outcome), ok
	}
	isOutcome := func(want ...string) func(*glua.LState) int {
		return func(L *glua.LState) int {
			outcome, ok := outcomeOf(L)
			if !ok {
				L.Push(glua.LFalse)
				return 1
			}
			for _, w := range want {
				if outcome == w {
					L.Push(glua.LTrue)
					return 1
				}
			}
			L.Push(glua.LFalse)
			return 1
		}
	}
	tbl.RawSetString("ran", L.NewClosure(isOutcome("ran")))
	tbl.RawSetString("skipped", L.NewClosure(isOutcome("skipped")))
	tbl.RawSetString("failed", L.NewClosure(isOutcome("error", "timeout")))
	tbl.RawSetString("duration_ms", L.NewClosure(func(L *glua.LState) int {
		tbl, id, ok := rootTable(L, "steps")
		if !ok {
			return 0
		}
		rec, ok := tbl.RawGetH(id).(*glua.LTable)
		if !ok {
			L.Push(glua.LNil)
			return 1
		}
		L.Push(rec.RawGetString("duration_ms"))
		return 1
	}))
	tbl.RawSetString("outcome", L.NewClosure(func(L *glua.LState) int {
		tbl, id, ok := rootTable(L, "steps")
		if !ok {
			return 0
		}
		rec, ok := tbl.RawGetH(id).(*glua.LTable)
		if !ok {
			L.Push(glua.LNil)
			return 1
		}
		L.Push(rec.RawGetString("outcome"))
		return 1
	}))
	L.SetGlobal("steps", tbl)
}

// setMeta exposes the request meta with fields and the label/has_tag helpers.
func setMeta(L *glua.LState, meta *pipeline.RequestMeta) {
	tbl := L.NewTable()
	if meta != nil {
		tbl.RawSetString("org", strOrNil(meta.Org))
		tbl.RawSetString("key", strOrNil(meta.Key))
		tbl.RawSetString("model", strOrNil(meta.Model))
		tbl.RawSetString("provider", strOrNil(meta.Provider))
		labels := L.NewTable()
		for k, v := range meta.Labels {
			labels.RawSetH(glua.LString(k), glua.LString(v))
		}
		tbl.RawSetString("labels", labels)
		tags := L.NewTable()
		for i, t := range meta.Tags {
			tags.RawSetInt(i+1, glua.LString(t))
		}
		tbl.RawSetString("tags", tags)
	}
	tbl.RawSetString("label", L.NewClosure(func(L *glua.LState) int {
		tbl, name, ok := rootTable(L, "meta")
		if !ok {
			return 0
		}
		labels, ok := tbl.RawGetString("labels").(*glua.LTable)
		if !ok {
			L.Push(glua.LNil)
			return 1
		}
		L.Push(labels.RawGetH(name))
		return 1
	}))
	tbl.RawSetString("has_tag", L.NewClosure(func(L *glua.LState) int {
		tbl, tag, ok := rootTable(L, "meta")
		if !ok {
			return 0
		}
		tags, ok := tbl.RawGetString("tags").(*glua.LTable)
		if !ok {
			L.Push(glua.LFalse)
			return 1
		}
		for i := 1; i <= tags.Len(); i++ {
			if t, ok := tags.RawGetInt(i).(glua.LString); ok && t == tag {
				L.Push(glua.LTrue)
				return 1
			}
		}
		L.Push(glua.LFalse)
		return 1
	}))
	L.SetGlobal("meta", tbl)
}

// rootTable fetches an env root as a table and reads the first string
// argument. A script that overwrote a root with junk fails the evaluation
// (fail-closed), never panics.
func rootTable(L *glua.LState, name string) (*glua.LTable, glua.LValue, bool) {
	tbl, ok := L.GetGlobal(name).(*glua.LTable)
	if !ok {
		L.RaiseError("%s root was overwritten by the condition script", name)
		return nil, nil, false
	}
	return tbl, L.Get(1), true
}

func findingTable(L *glua.LState, f pipeline.Finding) *glua.LTable {
	t := L.NewTable()
	t.RawSetString("step", glua.LString(f.Step))
	t.RawSetString("category", glua.LString(f.Category))
	t.RawSetString("severity", glua.LString(f.Severity))
	t.RawSetString("span", glua.LString(f.Span))
	t.RawSetString("evidence", glua.LString(f.Evidence))
	t.RawSetString("action", glua.LString(f.Action))
	return t
}

func stepTable(L *glua.LState, st pipeline.StepTrace) *glua.LTable {
	t := L.NewTable()
	t.RawSetString("step", glua.LString(st.Step))
	t.RawSetString("duration_ms", glua.LNumber(float64(st.Duration.Nanoseconds())/1e6))
	t.RawSetString("outcome", glua.LString(st.Outcome))
	if st.Error != "" {
		t.RawSetString("error", glua.LString(st.Error))
	}
	return t
}

func strOrNil(s string) glua.LValue {
	if s == "" {
		return glua.LNil
	}
	return glua.LString(s)
}

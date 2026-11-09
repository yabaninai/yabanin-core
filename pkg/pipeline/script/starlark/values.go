package starlark

import (
	"fmt"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// This file builds the frozen Starlark views of the condition env (contract
// in the parent package): findings/steps/meta roots with helper methods.
// Every value is rebuilt per evaluation and frozen, so conditions can read
// but never mutate the snapshot.

// findingsValue exposes findings.any/all/none/count and findings.list.
func findingsValue(findings []pipeline.Finding) starlark.Value {
	view := &findingsView{records: make([]starlark.Value, 0, len(findings))}
	for _, f := range findings {
		view.records = append(view.records, starlarkstruct.FromStringDict(starlarkstruct.Default, starlark.StringDict{
			"step":     starlark.String(f.Step),
			"category": starlark.String(f.Category),
			"severity": starlark.String(f.Severity),
			"span":     starlark.String(f.Span),
			"evidence": starlark.String(f.Evidence),
			"action":   starlark.String(f.Action),
		}))
	}
	list := starlark.NewList(view.records)
	dict := starlark.StringDict{
		"any":   starlark.NewBuiltin("findings.any", view.any),
		"all":   starlark.NewBuiltin("findings.all", view.all),
		"none":  starlark.NewBuiltin("findings.none", view.none),
		"count": starlark.NewBuiltin("findings.count", view.count),
		"list":  list,
	}
	val := starlarkstruct.FromStringDict(starlarkstruct.Default, dict)
	val.Freeze()
	return val
}

// findingsView carries the per-evaluation finding records for the bound
// helper builtins.
type findingsView struct {
	records []starlark.Value
}

func (v *findingsView) each(thread *starlark.Thread, pred starlark.Callable, visit func(matched bool)) error {
	for _, rec := range v.records {
		res, err := starlark.Call(thread, pred, starlark.Tuple{rec}, nil)
		if err != nil {
			return err
		}
		matched, ok := res.(starlark.Bool)
		if !ok {
			return fmt.Errorf("findings predicate must return a bool, got %s", res.Type())
		}
		visit(bool(matched))
	}
	return nil
}

func predicate(args starlark.Tuple) (starlark.Callable, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("expected exactly 1 predicate argument, got %d", len(args))
	}
	pred, ok := args[0].(starlark.Callable)
	if !ok {
		return nil, fmt.Errorf("predicate must be callable, got %s", args[0].Type())
	}
	return pred, nil
}

func (v *findingsView) any(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	pred, err := predicate(args)
	if err != nil {
		return nil, fmt.Errorf("findings.any: %w", err)
	}
	matched := false
	err = v.each(thread, pred, func(m bool) { matched = matched || m })
	if err != nil {
		return nil, err
	}
	return starlark.Bool(matched), nil
}

func (v *findingsView) all(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	pred, err := predicate(args)
	if err != nil {
		return nil, fmt.Errorf("findings.all: %w", err)
	}
	// Contract: all() over an empty collection is false, not vacuously true.
	matched := len(v.records) > 0
	err = v.each(thread, pred, func(m bool) { matched = matched && m })
	if err != nil {
		return nil, err
	}
	return starlark.Bool(matched), nil
}

func (v *findingsView) none(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	pred, err := predicate(args)
	if err != nil {
		return nil, fmt.Errorf("findings.none: %w", err)
	}
	matched := false
	err = v.each(thread, pred, func(m bool) { matched = matched || m })
	if err != nil {
		return nil, err
	}
	return starlark.Bool(!matched), nil
}

func (v *findingsView) count(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	if len(args) == 0 {
		return starlark.MakeInt(len(v.records)), nil
	}
	pred, err := predicate(args)
	if err != nil {
		return nil, fmt.Errorf("findings.count: %w", err)
	}
	n := 0
	err = v.each(thread, pred, func(m bool) {
		if m {
			n++
		}
	})
	if err != nil {
		return nil, err
	}
	return starlark.MakeInt(n), nil
}

// stepsValue exposes steps.get/ran/skipped/failed/duration_ms/outcome.
func stepsValue(steps []pipeline.StepTrace) starlark.Value {
	byID := make(map[string]pipeline.StepTrace, len(steps))
	records := make(map[string]starlark.Value, len(steps))
	for _, st := range steps {
		byID[st.Step] = st
		records[st.Step] = starlarkstruct.FromStringDict(starlarkstruct.Default, starlark.StringDict{
			"step":        starlark.String(st.Step),
			"duration_ms": starlark.Float(float64(st.Duration.Nanoseconds()) / 1e6),
			"outcome":     starlark.String(st.Outcome),
			"error":       nilOrString(st.Error),
		})
	}
	view := &stepsView{byID: byID, records: records}
	dict := starlark.StringDict{
		"get":         starlark.NewBuiltin("steps.get", view.get),
		"ran":         starlark.NewBuiltin("steps.ran", view.isOutcome([]pipeline.StepOutcome{pipeline.StepRan})),
		"skipped":     starlark.NewBuiltin("steps.skipped", view.isOutcome([]pipeline.StepOutcome{pipeline.StepSkipped})),
		"failed":      starlark.NewBuiltin("steps.failed", view.isOutcome([]pipeline.StepOutcome{pipeline.StepError, pipeline.StepTimeout})),
		"duration_ms": starlark.NewBuiltin("steps.duration_ms", view.durationMs),
		"outcome":     starlark.NewBuiltin("steps.outcome", view.outcome),
	}
	val := starlarkstruct.FromStringDict(starlarkstruct.Default, dict)
	val.Freeze()
	return val
}

// stepsView carries the per-evaluation step records for the bound helpers.
type stepsView struct {
	byID    map[string]pipeline.StepTrace
	records map[string]starlark.Value
}

func id(args starlark.Tuple) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("expected exactly 1 id argument, got %d", len(args))
	}
	id, ok := args[0].(starlark.String)
	if !ok {
		return "", fmt.Errorf("id must be a string, got %s", args[0].Type())
	}
	return string(id), nil
}

func (v *stepsView) get(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	id, err := id(args)
	if err != nil {
		return nil, fmt.Errorf("steps.get: %w", err)
	}
	rec, ok := v.records[id]
	if !ok {
		return starlark.None, nil
	}
	return rec, nil
}

func (v *stepsView) isOutcome(want []pipeline.StepOutcome) func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	return func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		id, err := id(args)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", b.Name(), err)
		}
		st, ok := v.byID[id]
		if !ok {
			return starlark.False, nil
		}
		for _, w := range want {
			if st.Outcome == w {
				return starlark.True, nil
			}
		}
		return starlark.False, nil
	}
}

func (v *stepsView) durationMs(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	id, err := id(args)
	if err != nil {
		return nil, fmt.Errorf("steps.duration_ms: %w", err)
	}
	st, ok := v.byID[id]
	if !ok {
		return starlark.None, nil
	}
	return starlark.Float(float64(st.Duration.Nanoseconds()) / 1e6), nil
}

func (v *stepsView) outcome(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	id, err := id(args)
	if err != nil {
		return nil, fmt.Errorf("steps.outcome: %w", err)
	}
	st, ok := v.byID[id]
	if !ok {
		return starlark.None, nil
	}
	return starlark.String(st.Outcome), nil
}

// metaValue exposes meta.org/key/model/provider/labels/tags plus the
// label(name) and has_tag(tag) helpers.
func metaValue(meta *pipeline.RequestMeta) starlark.Value {
	view := &metaView{meta: meta}
	var org, key, model, provider starlark.Value = starlark.None, starlark.None, starlark.None, starlark.None
	if meta != nil {
		org, key = nilOrString(meta.Org), nilOrString(meta.Key)
		model, provider = nilOrString(meta.Model), nilOrString(meta.Provider)
	}
	dict := starlark.StringDict{
		"org":      org,
		"key":      key,
		"model":    model,
		"provider": provider,
		"labels":   labelsDict(meta),
		"tags":     tagsList(meta),
		"label":    starlark.NewBuiltin("meta.label", view.label),
		"has_tag":  starlark.NewBuiltin("meta.has_tag", view.hasTag),
	}
	val := starlarkstruct.FromStringDict(starlarkstruct.Default, dict)
	val.Freeze()
	return val
}

// metaView carries the per-evaluation meta for the bound helpers.
type metaView struct {
	meta *pipeline.RequestMeta
}

func (v *metaView) label(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	name, err := id(args)
	if err != nil {
		return nil, fmt.Errorf("meta.label: %w", err)
	}
	if v.meta == nil {
		return starlark.None, nil
	}
	if val, ok := v.meta.Labels[name]; ok {
		return starlark.String(val), nil
	}
	return starlark.None, nil
}

func (v *metaView) hasTag(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	tag, err := id(args)
	if err != nil {
		return nil, fmt.Errorf("meta.has_tag: %w", err)
	}
	if v.meta == nil {
		return starlark.False, nil
	}
	for _, t := range v.meta.Tags {
		if t == tag {
			return starlark.True, nil
		}
	}
	return starlark.False, nil
}

func labelsDict(meta *pipeline.RequestMeta) starlark.Value {
	dict := starlark.NewDict(4)
	if meta != nil {
		for k, val := range meta.Labels {
			_ = dict.SetKey(starlark.String(k), starlark.String(val)) // fresh mutable dict, cannot fail
		}
	}
	dict.Freeze()
	return dict
}

func tagsList(meta *pipeline.RequestMeta) starlark.Value {
	list := starlark.NewList([]starlark.Value{})
	if meta != nil {
		for _, t := range meta.Tags {
			_ = list.Append(starlark.String(t)) // fresh mutable list, cannot fail
		}
	}
	list.Freeze()
	return list
}

func nilOrString(s string) starlark.Value {
	if s == "" {
		return starlark.None
	}
	return starlark.String(s)
}

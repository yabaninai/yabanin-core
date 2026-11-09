package llmjudge

import (
	"context"
	"fmt"
	"strings"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// Reserved and optional step params. "model" and "prompt_ref" are merged in
// by the core from the llm_judge kind spec; mode/categories/threshold travel
// in the step's params map (strict YAML: anything else is a load error).
const (
	paramModel     = "model"
	paramPromptRef = "prompt_ref"
	paramMode      = "mode"
	paramThreshold = "threshold"
	paramCategory  = "categories"
)

// newJudge validates params, loads the prompt and compiles its template.
// Everything here runs at policy compile time — a bad judge step can never
// reach a live request.
func newJudge(deps Deps, params map[string]any) (pipeline.Step, error) {
	if deps.Client == nil {
		return nil, fmt.Errorf("llm_judge: no JudgeClient wired — register the step with llmjudge.Register(registry, llmjudge.Deps{...}) at gateway startup (see package doc)")
	}

	modelRef, err := paramString(params, paramModel)
	if err != nil || modelRef == "" {
		return nil, fmt.Errorf("llm_judge: params.%s is required", paramModel)
	}
	promptRef, err := paramString(params, paramPromptRef)
	if err != nil || promptRef == "" {
		return nil, fmt.Errorf("llm_judge: prompt_ref is required (e.g. \"judges/toxicity@2\")")
	}

	mode := DefaultMode
	if raw, ok := params[paramMode]; ok && raw != nil {
		m := Mode(fmt.Sprint(raw))
		if !m.Valid() {
			return nil, fmt.Errorf("llm_judge: %s %q: want input|output", paramMode, raw)
		}
		mode = m
	}

	threshold := DefaultThreshold
	if raw, ok := params[paramThreshold]; ok && raw != nil {
		t, err := paramFloat(raw)
		if err != nil {
			return nil, fmt.Errorf("llm_judge: %s: %w", paramThreshold, err)
		}
		if t <= 0 || t > 1 {
			return nil, fmt.Errorf("llm_judge: %s %v: must be in (0, 1]", paramThreshold, raw)
		}
		threshold = t
	}

	categories, err := paramStringSlice(params, paramCategory)
	if err != nil {
		return nil, fmt.Errorf("llm_judge: %s: %w", paramCategory, err)
	}

	prompts := deps.Prompts
	if prompts == nil {
		prompts = EmbeddedPromptSource{}
	}
	prompt, err := prompts.Load(context.Background(), promptRef)
	if err != nil {
		return nil, fmt.Errorf("llm_judge: %w", err)
	}
	tpl, err := compilePromptTemplate(prompt.Ref, prompt.Body)
	if err != nil {
		return nil, fmt.Errorf("llm_judge: %w", err)
	}

	return &Judge{
		client:     deps.Client,
		tpl:        tpl,
		promptRef:  promptRef,
		modelRef:   modelRef,
		mode:       mode,
		categories: categories,
		threshold:  threshold,
	}, nil
}

// paramString reads a required-ish string param. YAML gives us string,
// fmt.Sprint covers the number-as-string corner with a clear upstream error.
func paramString(params map[string]any, key string) (string, error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return "", nil
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("param %s: want string, got %T", key, raw)
	}
	return strings.TrimSpace(s), nil
}

// paramStringSlice reads a []string param, accepting both typed slices and
// YAML-decoded []interface{} values.
func paramStringSlice(params map[string]any, key string) ([]string, error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return nil, nil
	}
	items, ok := raw.([]any)
	if !ok {
		if ss, isTyped := raw.([]string); isTyped {
			return ss, nil
		}
		return nil, fmt.Errorf("param %s: want list of strings, got %T", key, raw)
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("param %s: want list of strings, got element %T", key, item)
		}
		if strings.TrimSpace(s) == "" {
			return nil, fmt.Errorf("param %s: empty category is not allowed", key)
		}
		out = append(out, strings.TrimSpace(s))
	}
	return out, nil
}

// paramFloat reads a numeric param (YAML decodes 0.8 as float64, 1 as int).
func paramFloat(raw any) (float64, error) {
	switch v := raw.(type) {
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case int:
		return float64(v), nil
	case int64:
		return float64(v), nil
	default:
		return 0, fmt.Errorf("want a number, got %T", raw)
	}
}

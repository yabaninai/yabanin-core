// LiteLLM proxy-config dry-run engine (N16-P02-T03). Walks the parsed YAML
// document once, in source order, classifying every field against the
// compatibility matrix in litellm_migrate.go. Nothing here mutates
// configuration: the only outputs are the report and its text rendering.
package clientconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// LiteLLMDryRun parses an untrusted LiteLLM proxy config and produces the
// dry-run migration report. It never applies anything and never returns a
// report that contains secret values: parse-level failures are errors, and
// every field-level problem is a finding inside an otherwise successful
// report.
func LiteLLMDryRun(data []byte) (*LiteLLMMigrationReport, error) {
	root, err := litellmDecode(data)
	if err != nil {
		return nil, err
	}
	pin := LiteLLMConfigPin()
	rep := &LiteLLMMigrationReport{
		Schema: LiteLLMDryRunSchema,
		Source: LiteLLMReportSource{
			Format:         pin.Format,
			PinnedUpstream: pin.PinnedUpstream,
			Notice:         pin.Notice,
		},
		Scope: LiteLLMScope{
			Migrated:    append([]string(nil), litellmScopeMigrated...),
			NotMigrated: append([]LiteLLMScopeItem(nil), litellmScopeNotMigrated...),
		},
	}
	w := &litellmWalker{
		rep:      rep,
		groups:   map[string][]*litellmDeployment{},
		provider: map[string][]string{},
	}
	if err := w.walkRoot(root); err != nil {
		return nil, err
	}
	w.resolveGroups()
	w.resolveAliases()
	w.resolveFallbacks()
	w.buildPlan()
	w.summarize()
	return rep, nil
}

// litellmDecode strictly decodes exactly one YAML document whose root is a
// mapping. Empty input, trailing documents and non-mapping roots are hard
// errors (untrusted input is never silently repaired or truncated).
func litellmDecode(data []byte) (*yaml.Node, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	var root yaml.Node
	if err := dec.Decode(&root); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("parse litellm proxy config: empty config")
		}
		return nil, fmt.Errorf("parse litellm proxy config: %w", err)
	}
	if err := dec.Decode(&yaml.Node{}); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, fmt.Errorf("parse litellm proxy config: trailing data: %w", err)
		}
		return nil, fmt.Errorf("parse litellm proxy config: trailing data after the first document")
	}
	doc := &root
	if doc.Kind == yaml.DocumentNode {
		if len(doc.Content) == 0 {
			return nil, fmt.Errorf("parse litellm proxy config: empty config")
		}
		doc = doc.Content[0]
	}
	doc = litellmResolve(doc)
	if doc.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("parse litellm proxy config: top level must be a mapping (got %s)", litellmNodeShape(doc))
	}
	return doc, nil
}

func litellmResolve(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

// litellmNodeShape renders a non-scalar value as a shape summary. Raw
// composite values are never inlined into the report: unknown mappings can
// carry credentials.
func litellmNodeShape(n *yaml.Node) string {
	n = litellmResolve(n)
	if n == nil {
		return "<null>"
	}
	switch n.Kind {
	case yaml.MappingNode:
		return fmt.Sprintf("<mapping: %d keys>", len(n.Content)/2)
	case yaml.SequenceNode:
		return fmt.Sprintf("<sequence: %d items>", len(n.Content))
	case yaml.ScalarNode:
		return n.Value
	default:
		return "<unknown>"
	}
}

// litellmScalar returns a scrub-ready string for a scalar node. Composite
// nodes yield their shape summary so raw credential-bearing structures are
// never copied into the report.
func litellmScalar(n *yaml.Node) string {
	n = litellmResolve(n)
	if n == nil {
		return ""
	}
	if n.Kind != yaml.ScalarNode {
		return litellmNodeShape(n)
	}
	if n.Tag == "!!null" {
		return ""
	}
	return n.Value
}

// litellmInt reads a strict decimal integer off a scalar node.
func litellmInt(n *yaml.Node) (int64, bool) {
	n = litellmResolve(n)
	if n == nil || n.Kind != yaml.ScalarNode || n.Tag != "!!int" {
		return 0, false
	}
	v, err := strconv.ParseInt(strings.TrimSpace(n.Value), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

type litellmKV struct {
	key *yaml.Node
	val *yaml.Node
	// dup marks every occurrence of a key that appears more than once in
	// the mapping. The mapping-level duplicate-key conflict already refuses
	// the ambiguity (YAML decoders would silently keep only the last
	// value), so dup occurrences never emit value findings; secret-ledger
	// recording still happens so redaction stays complete.
	dup bool
}

// litellmMappingPairs iterates a mapping node in source order and reports
// duplicate keys as problems (YAML decoders would silently overwrite them).
func litellmMappingPairs(n *yaml.Node) (pairs []litellmKV, dupProblems []string, ok bool) {
	n = litellmResolve(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil, nil, false
	}
	type keyOcc struct {
		first int
		count int
	}
	occ := map[string]*keyOcc{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := n.Content[i]
		o, known := occ[k.Value]
		if !known {
			occ[k.Value] = &keyOcc{first: i, count: 1}
			continue
		}
		o.count++
		if o.count == 2 {
			dupProblems = append(dupProblems,
				fmt.Sprintf("duplicate key %q (first at line %d, duplicate at line %d)", k.Value, n.Content[o.first].Line, k.Line))
		}
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], litellmResolve(n.Content[i+1])
		pairs = append(pairs, litellmKV{key: k, val: v, dup: occ[k.Value].count > 1})
	}
	return pairs, dupProblems, true
}

// litellmDeployment is one model_list[] entry being classified.
type litellmDeployment struct {
	index      int
	path       string
	name       string
	target     string // canonical id accepted as a Yabanin provider
	canonical  string // folded LiteLLM provider id (even when refused)
	model      string
	apiBase    bool
	wildcard   bool
	conflicted bool
	caps       map[string]bool
	capsOrder  []string
	limits     LiteLLMPlanLimits
	hasLimits  bool
}

type litellmAliasReq struct {
	alias, target, path string
}

type litellmFallbackReq struct {
	group string
	chain []string
	path  string
	star  bool
}

type litellmWalker struct {
	rep          *LiteLLMMigrationReport
	groupOrder   []string
	groups       map[string][]*litellmDeployment
	deployments  []*litellmDeployment
	aliasReqs    []litellmAliasReq
	fallbackReqs []litellmFallbackReq
	provider     map[string][]string // canonical id → target provider refs (for unknown-provider refusals)
}

func (w *litellmWalker) add(list *[]LiteLLMFinding, f LiteLLMFinding) {
	f.SourceValue = redactLiteLLMValue(f.SourceValue)
	*list = append(*list, f)
}

func (w *litellmWalker) transfer(f LiteLLMFinding)   { w.add(&w.rep.Transferable, f) }
func (w *litellmWalker) difference(f LiteLLMFinding) { w.add(&w.rep.Differences, f) }
func (w *litellmWalker) conflict(f LiteLLMFinding)   { w.add(&w.rep.Conflicts, f) }
func (w *litellmWalker) refuse(f LiteLLMFinding)     { w.add(&w.rep.Unsupported, f) }

func (w *litellmWalker) secret(path, field string) {
	w.rep.Secrets = append(w.rep.Secrets, LiteLLMSecret{Path: path, Field: field})
}

func (w *litellmWalker) walkRoot(root *yaml.Node) error {
	pairs, dups, ok := litellmMappingPairs(root)
	if !ok {
		return fmt.Errorf("parse litellm proxy config: top level must be a mapping")
	}
	w.reportDups("$", dups)
	for _, kv := range pairs {
		key := kv.key.Value
		switch key {
		case "model_list":
			if err := w.walkModelList(kv.val); err != nil {
				return err
			}
		case "router_settings":
			w.walkRuleSection(kv.val, "router_settings", litellmRouterRules)
		case "litellm_settings":
			w.walkRuleSection(kv.val, "litellm_settings", litellmSettingsRules)
		case "general_settings":
			w.walkRuleSection(kv.val, "general_settings", litellmGeneralRules)
		case "environment_variables":
			w.walkEnvironmentVariables(kv.val)
		default:
			w.refuse(LiteLLMFinding{
				Path: "$." + key, Kind: LiteLLMKindCapability, Disposition: LiteLLMRefused,
				SourceValue: litellmScalar(kv.val),
				Detail: fmt.Sprintf("top-level section %q is not part of the pinned import contract (supported sections: %s); nothing is read from it",
					key, strings.Join(litellmSupportedSections, ", ")),
			})
		}
	}
	return nil
}

func (w *litellmWalker) reportDups(prefix string, problems []string) {
	for _, p := range problems {
		w.conflict(LiteLLMFinding{
			Path: prefix, Kind: LiteLLMKindSetting, Disposition: LiteLLMConflict,
			Detail: p + " — YAML decoders would silently keep only the last value; the ambiguity is refused",
		})
	}
}

func (w *litellmWalker) walkModelList(seq *yaml.Node) error {
	seq = litellmResolve(seq)
	if seq.Kind != yaml.SequenceNode {
		w.conflict(LiteLLMFinding{
			Path: "$.model_list", Kind: LiteLLMKindRoute, Disposition: LiteLLMConflict,
			SourceValue: litellmNodeShape(seq),
			Detail:      "model_list must be a sequence of deployment entries",
		})
		return nil
	}
	for i := 0; i < len(seq.Content); i++ {
		w.walkDeployment(i, fmt.Sprintf("model_list[%d]", i), seq.Content[i])
	}
	return nil
}

func (w *litellmWalker) walkDeployment(i int, path string, node *yaml.Node) {
	d := &litellmDeployment{index: i, path: path, caps: map[string]bool{}}
	w.deployments = append(w.deployments, d)
	pairs, dups, ok := litellmMappingPairs(litellmResolve(node))
	w.reportDups(path, dups)
	if len(dups) > 0 {
		// The deployment entry itself is ambiguous; the conflict above is
		// the refusal, so the entry can never reach the plan.
		d.conflicted = true
	}
	if !ok {
		w.conflict(LiteLLMFinding{
			Path: path, Kind: LiteLLMKindRoute, Disposition: LiteLLMConflict,
			SourceValue: litellmNodeShape(node),
			Detail:      "deployment entry must be a mapping with model_name and litellm_params",
		})
		d.conflicted = true
		return
	}

	var customProvider string
	var rawModel string
	haveModel := false
	haveParams := false
	haveName := false

	for _, kv := range pairs {
		key := kv.key.Value
		switch key {
		case "model_name":
			haveName = true
			if kv.dup {
				continue
			}
			d.name = strings.TrimSpace(litellmScalar(kv.val))
			if d.name == "" {
				w.conflict(LiteLLMFinding{
					Path: path + ".model_name", Kind: LiteLLMKindRoute, Disposition: LiteLLMConflict,
					Detail: "model_name is required and must be a non-empty scalar; an unnamed model group cannot become a catalog row",
				})
				d.conflicted = true
			}
			if strings.Contains(d.name, "*") {
				d.wildcard = true
				w.refuse(LiteLLMFinding{
					Path: path + ".model_name", Kind: LiteLLMKindRoute, Disposition: LiteLLMRefused,
					SourceValue: d.name,
					Detail:      fmt.Sprintf("wildcard model group %q: the catalog admits explicit (provider, model) rows only; list the served models explicitly", d.name),
				})
			}
		case "litellm_params":
			haveParams = true
			if kv.dup {
				continue
			}
			lp := litellmResolve(kv.val)
			lpPairs, lpDups, lpOK := litellmMappingPairs(lp)
			w.reportDups(path+".litellm_params", lpDups)
			if len(lpDups) > 0 {
				// Duplicate keys inside litellm_params make the deployment
				// identity and limits ambiguous; the conflicts above are the
				// refusal, so the deployment can never reach the plan.
				d.conflicted = true
			}
			if !lpOK {
				w.conflict(LiteLLMFinding{
					Path: path + ".litellm_params", Kind: LiteLLMKindRoute, Disposition: LiteLLMConflict,
					SourceValue: litellmNodeShape(lp),
					Detail:      "litellm_params must be a mapping; the deployment identity (provider/model) cannot be read",
				})
				d.conflicted = true
				continue
			}
			for _, pkv := range lpPairs {
				switch pkv.key.Value {
				case "model":
					haveModel = true
					rawModel = litellmScalar(pkv.val)
				case "custom_llm_provider":
					customProvider = litellmScalar(pkv.val)
				case "tpm":
					if pkv.dup {
						continue
					}
					w.walkLimit(pkv.val, path+".litellm_params.tpm", "tpm", &d.limits.MaxTPM, d)
				case "rpm":
					if pkv.dup {
						continue
					}
					w.walkLimit(pkv.val, path+".litellm_params.rpm", "rpm", &d.limits.MaxRPM, d)
				case "api_base":
					// The override fact survives duplicate-key ambiguity;
					// the semantic difference is stated only for an
					// unambiguous value.
					d.apiBase = true
					if pkv.dup {
						continue
					}
					rule := litellmParamFieldRules["api_base"]
					w.difference(LiteLLMFinding{
						Path: path + ".litellm_params.api_base", Kind: rule.Kind, Disposition: LiteLLMDecision,
						SourceValue:     litellmScalar(pkv.val),
						Target:          rule.Target,
						SourceSemantics: rule.SourceSemantics,
						TargetSemantics: rule.TargetSemantics,
						Detail:          rule.Detail,
					})
				default:
					w.applyRule(litellmParamFieldRules, pkv.key, pkv.val, path+".litellm_params", "litellm_params", pkv.dup)
				}
			}
		case "model_info":
			if kv.dup {
				continue
			}
			w.walkModelInfo(kv.val, path+".model_info", d)
		default:
			w.refuse(LiteLLMFinding{
				Path: path + "." + key, Kind: LiteLLMKindSetting, Disposition: LiteLLMRefused,
				SourceValue: litellmScalar(kv.val),
				Detail:      fmt.Sprintf("field %q is not in the pinned compatibility matrix for a model_list entry; nothing is read from it", key),
			})
		}
	}

	if !haveParams {
		w.conflict(LiteLLMFinding{
			Path: path, Kind: LiteLLMKindRoute, Disposition: LiteLLMConflict,
			Detail: "litellm_params is required; without it the deployment identity (provider/model) cannot be verified",
		})
		d.conflicted = true
	}
	if !haveName {
		w.conflict(LiteLLMFinding{
			Path: path + ".model_name", Kind: LiteLLMKindRoute, Disposition: LiteLLMConflict,
			Detail: "model_name is required; an unnamed deployment cannot become a client-facing catalog row",
		})
		d.conflicted = true
	}
	if !haveModel && !d.conflicted {
		w.conflict(LiteLLMFinding{
			Path: path + ".litellm_params.model", Kind: LiteLLMKindRoute, Disposition: LiteLLMConflict,
			Detail: "litellm_params.model is required; the upstream model identity cannot be verified",
		})
		d.conflicted = true
	}
	// Identity is always computed (even for already-conflicted deployments)
	// so group duplication analysis sees the (provider, model) pairs;
	// resolveIdentity suppresses duplicate findings for conflicted entries.
	w.resolveIdentity(d, rawModel, customProvider)
	if d.name != "" && !d.wildcard {
		if _, seen := w.groups[d.name]; !seen {
			w.groupOrder = append(w.groupOrder, d.name)
		}
		w.groups[d.name] = append(w.groups[d.name], d)
	}
}

// resolveIdentity splits litellm_params.model into provider and model using
// the same prefix folding as the pricing importer, falling back to
// custom_llm_provider when the model carries no provider prefix. It always
// fills d.canonical/d.target/d.model; findings are emitted only while the
// deployment was still unconflicted on entry.
func (w *litellmWalker) resolveIdentity(d *litellmDeployment, rawModel, customProvider string) {
	report := !d.conflicted
	canonical := ""
	if idx := strings.Index(rawModel, "/"); idx >= 0 {
		prefix := rawModel[:idx]
		d.model = rawModel[idx+1:]
		if prefix != "" {
			canonical = litellmCanonicalProvider(prefix)
		}
	} else if strings.TrimSpace(customProvider) != "" {
		d.model = rawModel
		canonical = litellmCanonicalProvider(customProvider)
		if report {
			w.transfer(LiteLLMFinding{
				Path: d.path + ".litellm_params.custom_llm_provider", Kind: LiteLLMKindSetting, Disposition: LiteLLMTransfer,
				SourceValue: customProvider,
				Target:      "provider id of the catalog row",
				Detail:      fmt.Sprintf("model %q carries no provider prefix; the provider is taken from custom_llm_provider → %q", rawModel, canonical),
			})
		}
	}
	if canonical == "" {
		d.conflicted = true
		if report {
			w.conflict(LiteLLMFinding{
				Path: d.path + ".litellm_params.model", Kind: LiteLLMKindRoute, Disposition: LiteLLMConflict,
				SourceValue: rawModel,
				Detail:      "provider cannot be determined: the model needs a \"provider/model\" prefix or a custom_llm_provider value; refusing to guess",
			})
		}
		return
	}
	d.canonical = canonical
	target, ok := litellmProviderTargets[canonical]
	if !ok {
		d.conflicted = true
		if report {
			w.refuse(LiteLLMFinding{
				Path: d.path + ".litellm_params.model", Kind: LiteLLMKindCapability, Disposition: LiteLLMRefused,
				SourceValue: rawModel,
				Detail: fmt.Sprintf("provider %q has no Yabanin adapter in the pinned provider target list; the entry is refused rather than force-mapped (supported targets: %s)",
					canonical, strings.Join(sortedProviderTargets(), ", ")),
			})
		}
		return
	}
	d.target = target
	if d.wildcard {
		// The wildcard group name was already refused; do not propose a
		// catalog row for a deployment whose client-facing route is refused.
		return
	}
	if strings.Contains(rawModel, "*") || strings.Contains(d.model, "*") {
		d.wildcard = true
		if report {
			w.refuse(LiteLLMFinding{
				Path: d.path + ".litellm_params.model", Kind: LiteLLMKindRoute, Disposition: LiteLLMRefused,
				SourceValue: rawModel,
				Detail:      "wildcard route: LiteLLM would serve every model of the provider; the catalog admits explicit (provider, model) rows only — list the models explicitly",
			})
		}
		return
	}
	if d.model == "" {
		d.conflicted = true
		if report {
			w.conflict(LiteLLMFinding{
				Path: d.path + ".litellm_params.model", Kind: LiteLLMKindRoute, Disposition: LiteLLMConflict,
				SourceValue: rawModel,
				Detail:      "model id after the provider prefix is empty; an empty upstream model cannot become a catalog row",
			})
		}
		return
	}
	if !report {
		return
	}
	w.transfer(LiteLLMFinding{
		Path: d.path, Kind: LiteLLMKindRoute, Disposition: LiteLLMTransfer,
		SourceValue: d.name,
		Target:      fmt.Sprintf("catalog row %s/%s", d.target, d.model),
		Detail: fmt.Sprintf("model %q (provider %q → %q) transfers as a catalog row; client-facing group name follows as an alias when it differs",
			rawModel, d.canonical, d.target),
	})
}

// walkLimit classifies one tpm/rpm value. Verified semantics: both sides use
// tokens (requests) per minute as positive integers. Zero and negative
// values are conflicts — LiteLLM reads 0 as "block all traffic" while a
// catalog zero means "unset (unlimited)", so importing 0 would silently lift
// the limit.
func (w *litellmWalker) walkLimit(node *yaml.Node, path, field string, into *int64, d *litellmDeployment) {
	v, ok := litellmInt(node)
	raw := litellmScalar(node)
	if !ok {
		w.conflict(LiteLLMFinding{
			Path: path, Kind: LiteLLMKindLimit, Disposition: LiteLLMConflict,
			SourceValue: raw,
			Detail:      fmt.Sprintf("%s must be a plain decimal integer (got %q); unsupported limit values never pass silently", field, raw),
		})
		d.conflicted = true
		return
	}
	if v < 0 {
		w.conflict(LiteLLMFinding{
			Path: path, Kind: LiteLLMKindLimit, Disposition: LiteLLMConflict,
			SourceValue: raw,
			Detail:      fmt.Sprintf("negative %s limit cannot transfer: a negative rate limit is not a valid bound on either side", field),
		})
		d.conflicted = true
		return
	}
	if v == 0 {
		w.conflict(LiteLLMFinding{
			Path: path, Kind: LiteLLMKindLimit, Disposition: LiteLLMConflict,
			SourceValue: raw,
			Detail:      fmt.Sprintf("%s=0 means \"block all traffic\" in LiteLLM but \"unset (unlimited)\" in the catalog; importing it would silently lift the limit — the operator must choose an explicit positive bound", field),
		})
		d.conflicted = true
		return
	}
	*into = v
	d.hasLimits = true
	w.transfer(LiteLLMFinding{
		Path: path, Kind: LiteLLMKindLimit, Disposition: LiteLLMTransfer,
		SourceValue: raw,
		Target:      "catalog limits." + map[string]string{"tpm": "max_tpm", "rpm": "max_rpm"}[field],
		Detail:      fmt.Sprintf("%s=%d transfers verbatim (units verified: per-minute counters on both sides)", field, v),
	})
	w.difference(LiteLLMFinding{
		Path: path, Kind: LiteLLMKindLimit, Disposition: LiteLLMDecision,
		Target:          "catalog limits." + map[string]string{"tpm": "max_tpm", "rpm": "max_rpm"}[field],
		SourceSemantics: fmt.Sprintf("LiteLLM enforces %s=%d as a router rate limit (requests fail once the per-minute budget is exhausted)", field, v),
		TargetSemantics: "Yabanin stores the bound as documented catalog data; per-model router enforcement is not configured by this import",
		Detail:          "the value transfers with verified units; the enforcement posture differs and is stated here so the operator does not assume an active limiter",
	})
}

func (w *litellmWalker) walkModelInfo(node *yaml.Node, path string, d *litellmDeployment) {
	mi := litellmResolve(node)
	pairs, dups, ok := litellmMappingPairs(mi)
	w.reportDups(path, dups)
	if len(dups) > 0 {
		// Duplicate keys make the capability/limit values ambiguous; the
		// conflicts above are the refusal, so the deployment can never
		// reach the plan.
		d.conflicted = true
	}
	if !ok {
		w.conflict(LiteLLMFinding{
			Path: path, Kind: LiteLLMKindSetting, Disposition: LiteLLMConflict,
			SourceValue: litellmNodeShape(mi),
			Detail:      "model_info must be a mapping",
		})
		return
	}
	for _, kv := range pairs {
		if kv.dup {
			continue
		}
		key := kv.key.Value
		switch key {
		case "mode":
			mode := strings.TrimSpace(litellmScalar(kv.val))
			capKey, mapped := litellmModeCapabilities[mode]
			if !mapped {
				w.refuse(LiteLLMFinding{
					Path: path + ".mode", Kind: LiteLLMKindCapability, Disposition: LiteLLMRefused,
					SourceValue: mode,
					Detail:      fmt.Sprintf("mode %q has no mapping in the pinned catalog capability vocabulary; the capability is refused rather than guessed", mode),
				})
				continue
			}
			if !d.caps[capKey] {
				d.caps[capKey] = true
				d.capsOrder = append(d.capsOrder, capKey)
			}
			w.transfer(LiteLLMFinding{
				Path: path + ".mode", Kind: LiteLLMKindCapability, Disposition: LiteLLMTransfer,
				SourceValue: mode,
				Target:      "catalog capabilities." + capKey,
				Detail:      fmt.Sprintf("mode %q → capability %q", mode, capKey),
			})
		case "max_output_tokens":
			w.walkInfoLimit(kv.val, path+".max_output_tokens", "max_output_tokens", &d.limits.MaxOutputTokens, d)
		default:
			w.applyRule(litellmModelInfoRules, kv.key, kv.val, path, "model_info", kv.dup)
		}
	}
}

// walkInfoLimit classifies model_info.max_output_tokens (verified: both
// sides document the per-completion output cap).
func (w *litellmWalker) walkInfoLimit(node *yaml.Node, path, field string, into *int64, d *litellmDeployment) {
	v, ok := litellmInt(node)
	raw := litellmScalar(node)
	if !ok {
		w.conflict(LiteLLMFinding{
			Path: path, Kind: LiteLLMKindLimit, Disposition: LiteLLMConflict,
			SourceValue: raw,
			Detail:      fmt.Sprintf("%s must be a plain decimal integer (got %q); unsupported limit values never pass silently", field, raw),
		})
		return
	}
	if v <= 0 {
		w.conflict(LiteLLMFinding{
			Path: path, Kind: LiteLLMKindLimit, Disposition: LiteLLMConflict,
			SourceValue: raw,
			Detail:      fmt.Sprintf("%s=%d cannot transfer: zero reads as \"unset\" in the catalog and negative bounds are invalid — the operator must choose an explicit positive bound", field, v),
		})
		return
	}
	*into = v
	d.hasLimits = true
	w.transfer(LiteLLMFinding{
		Path: path, Kind: LiteLLMKindLimit, Disposition: LiteLLMTransfer,
		SourceValue: raw,
		Target:      "catalog limits." + field,
		Detail:      fmt.Sprintf("%s=%d transfers verbatim (both sides document the per-completion output cap)", field, v),
	})
}

// applyRule applies a matrix row to a source field. Fields that are not in
// the matrix are reported as unsupported — the explicit-disposition
// guarantee means an unknown field can never pass silently. A duplicate-key
// occurrence carries no value findings: the mapping-level duplicate-key
// conflict already refuses the ambiguity; secret-shaped keys still enter
// the redaction ledger.
func (w *litellmWalker) applyRule(rules map[string]litellmFieldRule, keyNode, valNode *yaml.Node, prefix, section string, dup bool) {
	key := keyNode.Value
	rule, known := rules[key]
	path := prefix + "." + key
	secretShaped := (known && rule.Secret) || litellmSecretKeyName.MatchString(key)
	if dup {
		if secretShaped {
			w.secret(path, key)
		}
		return
	}
	if !known {
		if secretShaped {
			w.secret(path, key)
			w.refuse(LiteLLMFinding{
				Path: path, Kind: LiteLLMKindSecret, Disposition: LiteLLMRefused,
				SourceValue: LiteLLMRedacted,
				Detail:      fmt.Sprintf("field %q is not in the pinned compatibility matrix for %s and is credential-shaped; its value is redacted and never read", key, section),
			})
			return
		}
		w.refuse(LiteLLMFinding{
			Path: path, Kind: LiteLLMKindSetting, Disposition: LiteLLMRefused,
			SourceValue: litellmScalar(valNode),
			Detail:      fmt.Sprintf("field %q is not in the pinned compatibility matrix for %s; nothing is read from it and it will not transfer silently", key, section),
		})
		return
	}
	if secretShaped {
		w.secret(path, key)
		w.refuse(LiteLLMFinding{
			Path: path, Kind: LiteLLMKindSecret, Disposition: LiteLLMRefused,
			SourceValue: LiteLLMRedacted,
			Target:      rule.Target,
			Detail:      rule.Detail,
		})
		return
	}
	switch rule.Disposition {
	case LiteLLMDecision:
		w.difference(LiteLLMFinding{
			Path: path, Kind: rule.Kind, Disposition: LiteLLMDecision,
			SourceValue:     litellmScalar(valNode),
			Target:          rule.Target,
			SourceSemantics: rule.SourceSemantics,
			TargetSemantics: rule.TargetSemantics,
			Detail:          rule.Detail,
		})
	case LiteLLMConflict:
		w.conflict(LiteLLMFinding{
			Path: path, Kind: rule.Kind, Disposition: LiteLLMConflict,
			SourceValue: litellmScalar(valNode),
			Target:      rule.Target,
			Detail:      rule.Detail,
		})
	default: // LiteLLMRefused and any transfer-less rule
		w.refuse(LiteLLMFinding{
			Path: path, Kind: rule.Kind, Disposition: LiteLLMRefused,
			SourceValue: litellmScalar(valNode),
			Target:      rule.Target,
			Detail:      rule.Detail,
		})
	}
}

func (w *litellmWalker) walkRuleSection(node *yaml.Node, section string, rules map[string]litellmFieldRule) {
	sec := litellmResolve(node)
	pairs, dups, ok := litellmMappingPairs(sec)
	w.reportDups("$."+section, dups)
	if !ok {
		w.conflict(LiteLLMFinding{
			Path: "$." + section, Kind: LiteLLMKindSetting, Disposition: LiteLLMConflict,
			SourceValue: litellmNodeShape(sec),
			Detail:      fmt.Sprintf("%s must be a mapping", section),
		})
		return
	}
	for _, kv := range pairs {
		switch {
		case section == "router_settings" && kv.key.Value == "model_group_alias":
			w.collectAliases(kv.val)
		case section == "router_settings" && kv.key.Value == "fallbacks":
			w.collectFallbacks(kv.val)
		default:
			w.applyRule(rules, kv.key, kv.val, "$."+section, section, kv.dup)
		}
	}
}

func (w *litellmWalker) walkEnvironmentVariables(node *yaml.Node) {
	env := litellmResolve(node)
	pairs, dups, ok := litellmMappingPairs(env)
	w.reportDups("$.environment_variables", dups)
	if !ok {
		w.refuse(LiteLLMFinding{
			Path: "$.environment_variables", Kind: LiteLLMKindSecret, Disposition: LiteLLMRefused,
			SourceValue: litellmNodeShape(env),
			Detail:      "environment_variables is not a mapping; its values would be environment/credential material and are never read",
		})
		return
	}
	for _, kv := range pairs {
		path := "$.environment_variables." + kv.key.Value
		w.secret(path, kv.key.Value)
		if kv.dup {
			// The duplicate-key conflict already refuses the ambiguity;
			// the redaction ledger stays complete.
			continue
		}
		w.refuse(LiteLLMFinding{
			Path: path, Kind: LiteLLMKindSecret, Disposition: LiteLLMRefused,
			SourceValue: LiteLLMRedacted,
			Detail:      "environment variables are credential/configuration material; values are redacted and never imported",
		})
	}
}

func (w *litellmWalker) collectAliases(node *yaml.Node) {
	ma := litellmResolve(node)
	pairs, dups, ok := litellmMappingPairs(ma)
	w.reportDups("$.router_settings.model_group_alias", dups)
	if !ok {
		w.conflict(LiteLLMFinding{
			Path: "$.router_settings.model_group_alias", Kind: LiteLLMKindRoute, Disposition: LiteLLMConflict,
			SourceValue: litellmNodeShape(ma),
			Detail:      "model_group_alias must be a mapping of alias → model group",
		})
		return
	}
	for _, kv := range pairs {
		if kv.dup {
			// The duplicate-key conflict above already refuses the
			// ambiguity; a duplicated alias cannot also resolve.
			continue
		}
		w.aliasReqs = append(w.aliasReqs, litellmAliasReq{
			alias:  strings.TrimSpace(litellmScalar(kv.key)),
			target: strings.TrimSpace(litellmScalar(kv.val)),
			path:   "$.router_settings.model_group_alias." + kv.key.Value,
		})
	}
}

func (w *litellmWalker) collectFallbacks(node *yaml.Node) {
	seq := litellmResolve(node)
	if seq.Kind != yaml.SequenceNode {
		w.conflict(LiteLLMFinding{
			Path: "$.router_settings.fallbacks", Kind: LiteLLMKindRoute, Disposition: LiteLLMConflict,
			SourceValue: litellmNodeShape(seq),
			Detail:      "fallbacks must be a sequence of {group: [chain]} mappings",
		})
		return
	}
	for i, item := range seq.Content {
		path := fmt.Sprintf("$.router_settings.fallbacks[%d]", i)
		pairs, dups, ok := litellmMappingPairs(item)
		w.reportDups(path, dups)
		if !ok || len(pairs) != 1 {
			w.conflict(LiteLLMFinding{
				Path: path, Kind: LiteLLMKindRoute, Disposition: LiteLLMConflict,
				SourceValue: litellmNodeShape(item),
				Detail:      "each fallbacks entry must be a single-key {group: [chain]} mapping",
			})
			continue
		}
		kv := pairs[0]
		group := strings.TrimSpace(litellmScalar(kv.key))
		chainNode := litellmResolve(kv.val)
		if chainNode == nil || chainNode.Kind != yaml.SequenceNode {
			w.conflict(LiteLLMFinding{
				Path: path, Kind: LiteLLMKindRoute, Disposition: LiteLLMConflict,
				SourceValue: litellmScalar(kv.val),
				Detail:      fmt.Sprintf("fallback chain for group %q must be a sequence of model group names", group),
			})
			continue
		}
		chain := make([]string, 0, len(chainNode.Content))
		for _, c := range chainNode.Content {
			chain = append(chain, litellmScalar(c))
		}
		w.fallbackReqs = append(w.fallbackReqs, litellmFallbackReq{
			group: group, chain: chain, path: path, star: group == "*",
		})
	}
}

// resolveGroups marks duplicated model groups as conflicts. LiteLLM
// load-balances several deployments behind one model group; the catalog
// admits exactly one (provider, model) row, so the ambiguity is refused
// until the operator picks a single deployment.
func (w *litellmWalker) resolveGroups() {
	for _, name := range w.groupOrder {
		deps := w.groups[name]
		if len(deps) < 2 {
			continue
		}
		seenPairs := map[string]bool{}
		var pairs []string
		for _, d := range deps {
			d.conflicted = true
			p := d.target + "/" + d.model
			if d.target == "" {
				p = "<unresolved identity>"
			}
			if !seenPairs[p] {
				seenPairs[p] = true
				pairs = append(pairs, p)
			}
		}
		detail := fmt.Sprintf("model group %q has %d deployments (LiteLLM load-balances across them); the catalog admits exactly one (provider, model) row — pick a single deployment before applying", name, len(deps))
		if len(pairs) > 1 {
			detail = fmt.Sprintf("model group %q has %d deployments across different targets (%s); cross-provider failover inside a group cannot be represented as one catalog row — pick a single deployment before applying",
				name, len(deps), strings.Join(pairs, ", "))
		}
		w.conflict(LiteLLMFinding{
			Path:        "model_list[model_name=" + name + "]",
			Kind:        LiteLLMKindRoute,
			Disposition: LiteLLMConflict,
			SourceValue: name,
			Detail:      detail,
		})
	}
}

// resolveAliases classifies model_group_alias entries against the collected
// model groups.
func (w *litellmWalker) resolveAliases() {
	groupNames := map[string]bool{}
	for _, n := range w.groupOrder {
		groupNames[n] = true
	}
	assigned := map[string]bool{}
	for _, req := range w.aliasReqs {
		if req.alias == "" || req.target == "" {
			w.conflict(LiteLLMFinding{
				Path: req.path, Kind: LiteLLMKindRoute, Disposition: LiteLLMConflict,
				Detail: "model_group_alias entries need a non-empty alias and target group",
			})
			continue
		}
		deps, ok := w.groups[req.target]
		if !ok {
			w.conflict(LiteLLMFinding{
				Path: req.path, Kind: LiteLLMKindRoute, Disposition: LiteLLMConflict,
				SourceValue: req.alias,
				Detail:      fmt.Sprintf("alias %q points at unknown model group %q; a dangling route is never transferred", req.alias, req.target),
			})
			continue
		}
		var pairs []string
		for _, d := range deps {
			if !d.conflicted {
				p := d.target + "/" + d.model
				if !containsString(pairs, p) {
					pairs = append(pairs, p)
				}
			}
		}
		if len(pairs) != 1 {
			w.conflict(LiteLLMFinding{
				Path: req.path, Kind: LiteLLMKindRoute, Disposition: LiteLLMConflict,
				SourceValue: req.alias,
				Detail:      fmt.Sprintf("alias %q cannot resolve to a single catalog row (group %q is conflicted or ambiguous)", req.alias, req.target),
			})
			continue
		}
		parts := strings.SplitN(pairs[0], "/", 2)
		if req.alias == parts[1] {
			w.conflict(LiteLLMFinding{
				Path: req.path, Kind: LiteLLMKindRoute, Disposition: LiteLLMConflict,
				SourceValue: req.alias,
				Detail:      fmt.Sprintf("alias %q shadows the canonical model name of %s; the catalog rejects shadowing aliases", req.alias, pairs[0]),
			})
			continue
		}
		if groupNames[req.alias] {
			w.conflict(LiteLLMFinding{
				Path: req.path, Kind: LiteLLMKindRoute, Disposition: LiteLLMConflict,
				SourceValue: req.alias,
				Detail:      fmt.Sprintf("alias %q collides with an existing model group name; the catalog cannot carry both", req.alias),
			})
			continue
		}
		if assigned[req.alias] {
			w.conflict(LiteLLMFinding{
				Path: req.path, Kind: LiteLLMKindRoute, Disposition: LiteLLMConflict,
				SourceValue: req.alias,
				Detail:      fmt.Sprintf("alias %q is assigned to more than one catalog row; the ambiguity is refused", req.alias),
			})
			continue
		}
		assigned[req.alias] = true
		w.transfer(LiteLLMFinding{
			Path: req.path, Kind: LiteLLMKindRoute, Disposition: LiteLLMTransfer,
			SourceValue: req.alias,
			Target:      fmt.Sprintf("catalog aliases of %s", pairs[0]),
			Detail:      fmt.Sprintf("alias %q → %s (aliases resolve within their provider in the catalog)", req.alias, pairs[0]),
		})
		w.provider[pairs[0]] = append(w.provider[pairs[0]], req.alias)
	}
}

// resolveFallbacks classifies router fallback chains. Per-group chains have
// no representable equivalent (Yabanin has one global fallback model), so
// they are decisions, never silent transfers.
func (w *litellmWalker) resolveFallbacks() {
	for _, req := range w.fallbackReqs {
		chain := strings.Join(req.chain, ", ")
		if req.star {
			w.difference(LiteLLMFinding{
				Path: req.path, Kind: LiteLLMKindRoute, Disposition: LiteLLMDecision,
				SourceValue:     chain,
				Target:          "gateway fallback_model (deployment configuration)",
				SourceSemantics: "catch-all fallback for every model group",
				TargetSemantics: "one global fallback model configured at deployment level",
				Detail:          "the catch-all can map to the single global fallback only if the chain has exactly one entry; the operator applies it explicitly — nothing auto-transfers",
			})
			continue
		}
		if _, ok := w.groups[req.group]; !ok {
			w.conflict(LiteLLMFinding{
				Path: req.path, Kind: LiteLLMKindRoute, Disposition: LiteLLMConflict,
				SourceValue: chain,
				Detail:      fmt.Sprintf("fallback chain for unknown model group %q is a dangling route and is never transferred", req.group),
			})
			continue
		}
		w.difference(LiteLLMFinding{
			Path: req.path, Kind: LiteLLMKindRoute, Disposition: LiteLLMDecision,
			SourceValue:     chain,
			Target:          "gateway fallback_model (deployment configuration)",
			SourceSemantics: fmt.Sprintf("per-group fallback chain %q → [%s]", req.group, chain),
			TargetSemantics: "a single global fallback model; per-model fallback chains do not exist",
			Detail:          "collapsing the chain would silently weaken the fallback semantics; the operator must configure the fallback explicitly",
		})
	}
}

// buildPlan merges the non-conflicted deployments into deterministic catalog
// rows. Multiple groups naming the same upstream model merge into one row
// with combined aliases, mirroring catalog uniqueness of (provider, model).
func (w *litellmWalker) buildPlan() {
	order := []string{}
	byPair := map[string]*LiteLLMPlanEntry{}
	for _, d := range w.deployments {
		if d.conflicted || d.wildcard || d.target == "" || d.model == "" || d.name == "" {
			continue
		}
		key := d.target + "/" + d.model
		entry, ok := byPair[key]
		if !ok {
			entry = &LiteLLMPlanEntry{
				Action:       "catalog.upsert",
				Provider:     d.target,
				Model:        d.model,
				Capabilities: map[string]bool{},
				SourcePaths:  []string{},
			}
			if d.hasLimits {
				lim := d.limits
				entry.Limits = &lim
			}
			byPair[key] = entry
			order = append(order, key)
		} else {
			if d.hasLimits && entry.Limits == nil {
				lim := d.limits
				entry.Limits = &lim
			}
		}
		if d.name != d.model && !containsString(entry.Aliases, d.name) {
			entry.Aliases = append(entry.Aliases, d.name)
		}
		for _, c := range d.capsOrder {
			entry.Capabilities[c] = true
		}
		if !containsString(entry.SourcePaths, d.path) {
			entry.SourcePaths = append(entry.SourcePaths, d.path)
		}
	}
	for _, key := range order {
		entry := byPair[key]
		for _, alias := range w.provider[key] {
			if !containsString(entry.Aliases, alias) {
				entry.Aliases = append(entry.Aliases, alias)
			}
		}
		sort.Strings(entry.Aliases)
		// Entries without capabilities carry a nil map so the JSON
		// omitempty tag drops the field and the plan shape stays uniform.
		if len(entry.Capabilities) == 0 {
			entry.Capabilities = nil
		}
		w.rep.Plan = append(w.rep.Plan, *entry)
	}
}

func (w *litellmWalker) summarize() {
	s := &w.rep.Summary
	s.Transferable = len(w.rep.Transferable)
	s.Differences = len(w.rep.Differences)
	s.Conflicts = len(w.rep.Conflicts)
	s.Unsupported = len(w.rep.Unsupported)
	s.Secrets = len(w.rep.Secrets)
	s.PlanEntries = len(w.rep.Plan)
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func sortedProviderTargets() []string {
	targets := make([]string, 0, len(litellmProviderTargets))
	for k := range litellmProviderTargets {
		targets = append(targets, k)
	}
	sort.Strings(targets)
	return targets
}

// RenderLiteLLMReport renders the operator-facing text summary. It is
// deterministic and never contains secret values (values only ever appear
// from the already-scrubbed finding fields).
func RenderLiteLLMReport(r *LiteLLMMigrationReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "LiteLLM migration dry-run report (schema %d)\n", r.Schema)
	fmt.Fprintf(&b, "source: %s, pinned upstream: %s\n", r.Source.Format, r.Source.PinnedUpstream)
	b.WriteString("DRY RUN ONLY — nothing was applied; review this report before any apply (I65).\n")
	b.WriteString("transfers: " + strings.Join(r.Scope.Migrated, "; ") + "\n")
	for _, item := range r.Scope.NotMigrated {
		fmt.Fprintf(&b, "NOT migrated: %s — %s\n", item.Item, item.Reason)
	}
	fmt.Fprintf(&b, "summary: %d transferable, %d semantic differences, %d conflicts, %d unsupported, %d secrets redacted, %d plan entries\n",
		r.Summary.Transferable, r.Summary.Differences, r.Summary.Conflicts, r.Summary.Unsupported, r.Summary.Secrets, r.Summary.PlanEntries)
	section := func(title string, list []LiteLLMFinding) {
		if len(list) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n%s (%d):\n", title, len(list))
		for _, f := range list {
			fmt.Fprintf(&b, "  - [%s/%s] %s\n", f.Disposition, f.Kind, f.Path)
			if f.SourceValue != "" {
				fmt.Fprintf(&b, "      source: %s\n", f.SourceValue)
			}
			if f.Target != "" {
				fmt.Fprintf(&b, "      target: %s\n", f.Target)
			}
			if f.SourceSemantics != "" {
				fmt.Fprintf(&b, "      litellm: %s\n", f.SourceSemantics)
			}
			if f.TargetSemantics != "" {
				fmt.Fprintf(&b, "      yabanin: %s\n", f.TargetSemantics)
			}
			fmt.Fprintf(&b, "      %s\n", f.Detail)
		}
	}
	section("transferable", r.Transferable)
	section("semantic differences", r.Differences)
	section("conflicts", r.Conflicts)
	section("unsupported", r.Unsupported)
	if len(r.Secrets) > 0 {
		fmt.Fprintf(&b, "\nsecrets redacted (%d paths, values never included):\n", len(r.Secrets))
		for _, s := range r.Secrets {
			fmt.Fprintf(&b, "  - %s (%s)\n", s.Path, s.Field)
		}
	}
	if len(r.Plan) > 0 {
		fmt.Fprintf(&b, "\nplan preview (%d catalog rows; apply is a separate reviewed step):\n", len(r.Plan))
		for _, p := range r.Plan {
			fmt.Fprintf(&b, "  - %s %s/%s", p.Action, p.Provider, p.Model)
			if len(p.Aliases) > 0 {
				fmt.Fprintf(&b, " aliases=%s", strings.Join(p.Aliases, ","))
			}
			if p.Limits != nil {
				var lims []string
				if p.Limits.MaxTPM > 0 {
					lims = append(lims, fmt.Sprintf("max_tpm=%d", p.Limits.MaxTPM))
				}
				if p.Limits.MaxRPM > 0 {
					lims = append(lims, fmt.Sprintf("max_rpm=%d", p.Limits.MaxRPM))
				}
				if p.Limits.MaxOutputTokens > 0 {
					lims = append(lims, fmt.Sprintf("max_output_tokens=%d", p.Limits.MaxOutputTokens))
				}
				fmt.Fprintf(&b, " limits=[%s]", strings.Join(lims, ","))
			}
			if len(p.Capabilities) > 0 {
				caps := make([]string, 0, len(p.Capabilities))
				for c := range p.Capabilities {
					caps = append(caps, c)
				}
				sort.Strings(caps)
				fmt.Fprintf(&b, " capabilities=%s", strings.Join(caps, ","))
			}
			fmt.Fprintf(&b, " sources=%s\n", strings.Join(p.SourcePaths, ","))
		}
	}
	return b.String()
}

// LiteLLMReportJSON renders the deterministic JSON form of a report.
func LiteLLMReportJSON(r *LiteLLMMigrationReport) (string, error) {
	body, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", fmt.Errorf("render litellm migration report: %w", err)
	}
	return string(body) + "\n", nil
}

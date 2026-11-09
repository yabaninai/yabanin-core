package evaluator

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// NamespaceRouting is the identity namespace for routing rules in the
// rule-trace vocabulary (CORE-TRACE-05: namespaces policy/step/routing/
// tool-policy). CORE-TRACE-04 stamps this namespace into routing decisions.
const NamespaceRouting = "routing"

// MatchRecord identifies the exact rule version that matched during
// evaluation — audit-grade identity frozen at match time (CORE-TRACE-04):
// later edits or deletes of the rule never change what past requests
// recorded, because Version is derived from the rule's content, not from a
// mutable counter.
type MatchRecord struct {
	Namespace string
	RuleID    string
	Version   string // Rule.ContentVersion() captured at match time
}

// ContentVersion returns a deterministic content hash of the rule's
// effective configuration: SHA-256 over ID, OrgID, MatchExpr, TargetModel,
// Priority and Enabled, joined with 0x1f unit separators, lowercase hex,
// truncated to 16 chars. Editing any of these fields changes the version;
// unrelated rules in the same set do not. The hash is per-rule identity for
// request history — it is deliberately independent of the snapshot-set
// revision (rulesRevision), which changes whenever ANY rule in the org
// changes.
func (r Rule) ContentVersion() string {
	h := sha256.New()
	writeField := func(s string) {
		_, _ = h.Write([]byte(s))
		_, _ = h.Write([]byte{0x1f})
	}
	writeField(r.ID)
	writeField(r.OrgID)
	writeField(r.MatchExpr)
	writeField(r.TargetModel)
	writeField(strconv.Itoa(r.Priority))
	if r.Enabled {
		_, _ = h.Write([]byte{1})
	} else {
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// EvaluateMatch finds the target of the highest-priority enabled rule whose
// compiled expression evaluates to true, exactly like Evaluate, and returns
// the matched rule's identity record (nil when nothing matched, the snapshot
// is nil, or the context belongs to a different organization). Evaluate
// delegates here so recorded identity can never drift from actual selection.
func (s *Snapshot) EvaluateMatch(ctx Context, modelRequested string) (string, *MatchRecord) {
	if s == nil || ctx.OrgID != s.orgID {
		return "", nil
	}
	for i := range s.rules {
		cr := &s.rules[i]
		if cr.ast != nil && cr.ast.evaluate(ctx, modelRequested) {
			return cr.rule.TargetModel, &MatchRecord{
				Namespace: NamespaceRouting,
				RuleID:    cr.rule.ID,
				Version:   cr.rule.ContentVersion(),
			}
		}
	}
	return "", nil
}

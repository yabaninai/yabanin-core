package sovereign

import "fmt"

// CNGuard is a defensive double-check that CN models are NEVER served to an
// org without explicit cn_allowed=true. It runs AFTER the policy filter
// (PB4.5) as belt-and-suspenders against: stale cache, race conditions,
// misconfiguration, or future code regressions. The guard does NOT trust
// the policy's Allows() result for the CN dimension — it re-asserts the CN
// rule directly.
func CNGuard(p Policy, m ModelMeta) error {
	if m.CNFlagged && !p.CNAllowed {
		return ErrCNModelBlocked{Model: m.ModelName, Jurisdiction: p.BuyerJurisdiction}
	}
	return nil
}

// ErrCNModelBlocked is returned when the guard blocks a CN model. Logged at
// CRITICAL (security event) by the router.
type ErrCNModelBlocked struct {
	Model        string
	Jurisdiction string
}

func (e ErrCNModelBlocked) Error() string {
	return fmt.Sprintf("CN model %q blocked (cn_allowed=false, jurisdiction=%q)",
		e.Model, e.Jurisdiction)
}

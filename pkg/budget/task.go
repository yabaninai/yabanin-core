package budget

import (
	"regexp"
)

// TaskHeaderPattern is the accepted shape for the X-Yabanin-Task header:
// 1..128 chars of [A-Za-z0-9._:-]. It identifies a logical task so per-task
// spend, budgets (G3) and CTOR analytics (G4) can be attributed.
var TaskHeaderPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// ValidTaskID reports whether s is a well-formed X-Yabanin-Task value. An empty
// string is valid (an untagged request) and maps to the '(untagged)' bucket
// downstream; anything else must match TaskHeaderPattern.
func ValidTaskID(s string) bool {
	if s == "" {
		return true
	}
	return TaskHeaderPattern.MatchString(s)
}

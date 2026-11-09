package license

import "os"

// readLocalFile reads local files whose paths come from operator/config input:
// CLI flags (--key-file, --license…), environment variables, or repo-shipped
// defaults under deploy/. Those inputs are chosen by the person running the
// process, never by external request data, so G304's variable-path finding is
// documented at this single choke point instead of at every call site.
func readLocalFile(path string) ([]byte, error) {
	return os.ReadFile(path) //nolint:gosec // G304: operator/config path trust boundary (see doc comment)
}

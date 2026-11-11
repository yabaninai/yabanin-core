// Fixture head: MovableHelper relocated verbatim. Must be reported as
// moved (content-identical), never re-measured as new or blocking.
func MovableHelper(a int) int {
	if a < 0 {
		return -a
	}
	return a
}

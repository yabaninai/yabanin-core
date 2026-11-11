// Fixture head (reverse control): MovableHelper relocated with a modified
// body; must measure as added, never as moved.
func MovableHelper(a int) int {
	if a < 0 {
		return -a
	}
	return 2 * a
}

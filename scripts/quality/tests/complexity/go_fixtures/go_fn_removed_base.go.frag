// Fixture base: RemovedThing exists only at base. Deleted functions must
// not appear anywhere in the head report.
func RemovedThing(a int) int {
	if a > 0 {
		return a
	}
	return 0
}

// Fixture head: BorderlineFn added with cyclomatic 12 = 1 + 11 ifs
// (hand-counted). The 11-15 band requires a review receipt.
func BorderlineFn(x int) int {
	n := 0
	if x > 1 {
		n++
	}
	if x > 2 {
		n += 2
	}
	if x > 3 {
		n += 3
	}
	if x > 4 {
		n += 4
	}
	if x > 5 {
		n += 5
	}
	if x > 6 {
		n += 6
	}
	if x > 7 {
		n += 7
	}
	if x > 8 {
		n += 8
	}
	if x > 9 {
		n += 9
	}
	if x > 10 {
		n += 10
	}
	if x > 11 {
		n += 11
	}
	return n
}

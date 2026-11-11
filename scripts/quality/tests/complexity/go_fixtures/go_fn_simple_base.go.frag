// Fixture base: SimpleChanged, cyclomatic 8 = 1 + 7 ifs (hand-counted).
func SimpleChanged(x int) int {
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
	return n
}

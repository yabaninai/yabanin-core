// Fixture head: SimpleChanged with a modified body, cyclomatic 8 = 1 + 7
// ifs. A changed body inside the <=10 band must classify as ok.
func SimpleChanged(x int) int {
	total := 0
	if x >= 10 {
		total += 1
	}
	if x >= 20 {
		total += 2
	}
	if x >= 30 {
		total += 3
	}
	if x >= 40 {
		total += 4
	}
	if x >= 50 {
		total += 5
	}
	if x >= 60 {
		total += 6
	}
	if x >= 70 {
		total += 7
	}
	return total
}

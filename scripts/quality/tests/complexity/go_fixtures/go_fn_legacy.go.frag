// Fixture: untouched legacy function. Cyclomatic 25 = 1 + 24 if/else-if
// branches (hand-counted oracle; the runner asserts the exact value).
func LegacyUntouched(x int) int {
	if x == 1 {
		return 10
	} else if x == 2 {
		return 20
	} else if x == 3 {
		return 30
	} else if x == 4 {
		return 40
	} else if x == 5 {
		return 50
	} else if x == 6 {
		return 60
	} else if x == 7 {
		return 70
	} else if x == 8 {
		return 80
	} else if x == 9 {
		return 90
	} else if x == 10 {
		return 100
	} else if x == 11 {
		return 110
	} else if x == 12 {
		return 120
	} else if x == 13 {
		return 130
	} else if x == 14 {
		return 140
	} else if x == 15 {
		return 150
	} else if x == 16 {
		return 160
	} else if x == 17 {
		return 170
	} else if x == 18 {
		return 180
	} else if x == 19 {
		return 190
	} else if x == 20 {
		return 200
	} else if x == 21 {
		return 210
	} else if x == 22 {
		return 220
	} else if x == 23 {
		return 230
	} else if x == 24 {
		return 240
	}
	return 0
}

// Fixture head: the base HeavyOriginal was removed and reappears here
// renamed and reformatted — a genuine move carrying its cyclomatic-18 debt.
func HeavyMovedDebt(x int) int {
	n := 0

	if x>1 { n++ }
	if x > 2 {
		n += 2
	}

	if x>3 { n+=3 }
	if x > 4 {
		n += 4
	}
	if x > 5 {
		n += 5
	}
	if x>6 { n+=6 }
	if x > 7 {
		n += 7
	}
	if x > 8 {
		n += 8
	}
	if x>9 { n+=9 }

	if x > 10 {
		n += 10
	}
	if x > 11 {
		n += 11
	}
	if x > 12 {
		n += 12
	}
	if x>13 { n+=13 }
	if x > 14 {
		n += 14
	}
	if x > 15 {
		n += 15
	}
	if x > 16 {
		n += 16
	}

	if x>17 { n+=17 }
	return   n
}

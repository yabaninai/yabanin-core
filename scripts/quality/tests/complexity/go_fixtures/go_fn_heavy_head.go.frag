// Fixture head: HeavyChanged at cyclomatic 18 (hand-counted: for+elseif+
// 5 case clauses+&&+plain ifs); must block naming HeavyChanged.
func HeavyChanged(v []int) int {
	n := 0
	for _, x := range v {
		if x > 10 {
			n += x
		} else if x > 5 {
			n += 2 * x
		}
		switch x % 4 {
		case 0:
			n++
		case 1:
			n += 2
		case 2:
			n += 3
		case 3:
			n += 4
		default:
			n--
		}
		if x > 0 && x < 100 {
			n++
		}
		if n > 1000 {
			n = 1000
		}
		if n < -1000 {
			n = -1000
		}
		if x == 7 {
			n += 7
		}
		if x == 11 {
			n += 11
		}
		if x == 13 {
			n += 13
		}
		if x == 17 {
			n += 17
		}
		if x == 19 {
			n += 19
		}
	}
	return n
}

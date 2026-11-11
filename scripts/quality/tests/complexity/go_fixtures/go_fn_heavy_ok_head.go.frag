// Fixture head (reverse control): HeavyChanged refactored to cyclomatic 8
// = 1 + 7 ifs; proves blocking binds to the body, not the name.
func HeavyChanged(x int) int {
	n := 0
	if x > 10 {
		n += 10
	}
	if x > 20 {
		n += 20
	}
	if x > 30 {
		n += 30
	}
	if x > 40 {
		n += 40
	}
	if x > 50 {
		n += 50
	}
	if x > 60 {
		n += 60
	}
	if x > 70 {
		n += 70
	}
	return n
}

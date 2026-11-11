// Fixture base: un-gofmt'ed FmtOne (cyclomatic 4) and FmtTwo (3),
// hand-counted; head reformats both without touching bodies.
func   FmtOne (x int ) int {
	n:=0
	if x>0 { n=n+1 }
	if x>1 {n=n+2}
	if x>2 {n=n+3}
	return   n
}

func FmtTwo (xs   []int) int {
	total := 0
	for _, x := range xs {
		if x%2 == 0 { total += x }
	}
	return total
}

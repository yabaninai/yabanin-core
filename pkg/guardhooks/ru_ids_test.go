package guardhooks

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func indepINN10(d []int) int {
	coef := []int{2, 4, 10, 3, 5, 9, 4, 6, 8}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += coef[i] * d[i]
	}
	return (sum % 11) % 10
}

func indepINN12(d []int) (int, int) {
	c11 := []int{7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
	c12 := []int{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
	s11 := 0
	for i := 0; i < 10; i++ {
		s11 += c11[i] * d[i]
	}
	d11 := (s11 % 11) % 10
	s12 := 0
	body := append(append([]int{}, d[:10]...), d11)
	for i := 0; i < 11; i++ {
		s12 += c12[i] * body[i]
	}
	return d11, (s12 % 11) % 10
}

func indepSNILSKey(d []int) (int, bool) {
	n := 0
	for i := 0; i < 9; i++ {
		n = n*10 + d[i]
	}
	if n <= 1001998 {
		return 0, true
	}
	w := []int{9, 8, 7, 6, 5, 4, 3, 2, 1}
	s := 0
	for i := 0; i < 9; i++ {
		s += d[i] * w[i]
	}
	switch {
	case s < 100:
		return s, false
	case s == 100 || s == 101:
		return 0, false
	default:
		k := s % 101
		if k == 100 {
			return 0, false
		}
		return k, false
	}
}

func indepOGRN(head string, mod int) int {
	n, _ := strconv.ParseInt(head, 10, 64)
	return int((n % int64(mod)) % 10)
}

func joinDigits(d []int) string {
	b := strings.Builder{}
	for _, n := range d {
		b.WriteString(strconv.Itoa(n))
	}
	return b.String()
}

func confidenceOf(text, detector string) float64 {
	for _, f := range FindAll(text, ruDetectors()) {
		if f.Detector == detector {
			return f.Confidence
		}
	}
	return -1
}

func corruptDigit(s string, i int) string {
	b := []byte(s)
	b[i] = byte('0' + (int(b[i]-'0')+1)%10)
	return string(b)
}

func TestRUINN_IndependentChecksumAndCorruption(t *testing.T) {
	body10 := []int{1, 0, 0, 0, 0, 0, 0, 0, 1}
	num10 := joinDigits(append(append([]int{}, body10...), indepINN10(body10)))
	require.InDelta(t, 1, confidenceOf(num10, "ru:inn10"), 0.001)
	for i := 0; i < len(num10); i++ {
		bad := corruptDigit(num10, i)
		require.Less(t, confidenceOf(bad, "ru:inn10"), 1.0)
	}

	body12 := []int{1, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	c11, c12 := indepINN12(body12)
	num12 := joinDigits(append(append([]int{}, body12...), c11, c12))
	require.InDelta(t, 1, confidenceOf(num12, "ru:inn12"), 0.001)
	for i := 0; i < len(num12); i++ {
		bad := corruptDigit(num12, i)
		require.Less(t, confidenceOf(bad, "ru:inn12"), 1.0)
	}
	require.InDelta(t, 0.6, confidenceOf("1234567890", "ru:inn10"), 0.001)
}

func TestRUSNILS_ExampleAndBoundaries(t *testing.T) {
	require.InDelta(t, 1, confidenceOf("112-233-445 95", "ru:snils-flex"), 0.001)
	d := digitsOf("11223344595")
	key, formatOnly := indepSNILSKey(d)
	require.False(t, formatOnly)
	require.Equal(t, 95, key)

	// Weighted sums 100, 101 and 202. The control digits are 00.
	for _, raw := range []string{"920-000-003 00", "920-000-004 00", "997-000-000 00"} {
		require.InDelta(t, 1, confidenceOf(raw, "ru:snils-flex"), 0.001, raw)
	}
	require.InDelta(t, 0.9, confidenceOf("001-001-998 99", "ru:snils-flex"), 0.001)
	require.InDelta(t, 0.6, confidenceOf("001-001-999 00", "ru:snils-flex"), 0.001)
}

func TestRUOGRN_IndependentChecksumAndCorruption(t *testing.T) {
	head13 := "102770013219"
	num13 := head13 + strconv.Itoa(indepOGRN(head13, 11))
	require.InDelta(t, 1, confidenceOf(num13, "ru:ogrn"), 0.001)
	for i := 0; i < len(num13); i++ {
		require.InDelta(t, -1, confidenceOf(corruptDigit(num13, i), "ru:ogrn"), 0.001)
	}
	head15 := "30450011600015"
	// 14 digits; drop the last of this placeholder and append the check.
	head15 = head15[:14]
	num15 := head15 + strconv.Itoa(indepOGRN(head15, 13))
	require.InDelta(t, 1, confidenceOf(num15, "ru:ogrnip"), 0.001)
	for i := 0; i < len(num15); i++ {
		require.InDelta(t, -1, confidenceOf(corruptDigit(num15, i), "ru:ogrnip"), 0.001)
	}
}

func TestRUPassport_NeedsContext(t *testing.T) {
	bare := "45 06 123456"
	require.InDelta(t, -1, confidenceOf(bare, "ru:passport"), 0.001)
	require.InDelta(t, 0.9, confidenceOf("паспорт "+bare, "ru:passport"), 0.001)
	require.InDelta(t, 0.9, confidenceOf("PASSPORT 4506 123456", "ru:passport"), 0.001)
	require.InDelta(t, 0.9, confidenceOf("серия 4506123456", "ru:passport"), 0.001)
	require.InDelta(t, -1, confidenceOf("паспорт"+strings.Repeat(" ", 61)+bare, "ru:passport"), 0.001)
	require.InDelta(t, 0.9, confidenceOf("паспорт"+strings.Repeat(" ", 50)+bare, "ru:passport"), 0.001)
	require.Empty(t, New(ModeLog).Scan(bare))
	require.NotEmpty(t, New(ModeLog).Scan("паспорт "+bare))
}

func TestRUPhone_NotInsideLongerNumber(t *testing.T) {
	require.InDelta(t, 0.8, confidenceOf("+7 (900) 111-22-33", "ru:phone"), 0.001)
	require.InDelta(t, 0.8, confidenceOf("8 900 111 22 33", "ru:phone"), 0.001)
	require.InDelta(t, -1, confidenceOf("899911122334", "ru:phone"), 0.001)
	require.InDelta(t, -1, confidenceOf("12389991112233", "ru:phone"), 0.001)
	require.Empty(t, New(ModeLog).Scan("call +7 (900) 111-22-33"))
}

func TestRUEmail_BelowScanThreshold(t *testing.T) {
	require.InDelta(t, 0.8, confidenceOf("write user@example.com please", "ru:email"), 0.001)
	require.Empty(t, New(ModeLog).Scan("write user@example.com please"))
	out := New(ModeRedact).Redact("write user@example.com and паспорт 45 06 123456 and +7 900 111 22 33")
	require.Contains(t, out, "[REDACTED_EMAIL]")
	require.Contains(t, out, "[REDACTED_PASSPORT]")
	require.Contains(t, out, "[REDACTED_PHONE]")
	require.NotContains(t, out, "user@example.com")
}

func TestRUScan_PlainDigitsStayClean(t *testing.T) {
	require.Empty(t, New(ModeLog).Scan("the year code is 1234567890 done"))
	require.Empty(t, New(ModeLog).Scan("Number 500100732259 in the log (not a valid INN)."))
}

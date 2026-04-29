package policy

import "strings"

// IsWeakPIN returns true if the PIN matches a known weak pattern. The
// detection is conservative: it accepts a PIN if no rule fires, so the
// false-negative rate (weak PIN classified as strong) is the relevant
// safety metric. Common patterns:
//
//   - All-same-digit ("0000", "1111")
//   - Strict ascending or descending consecutive sequence ("1234", "9876")
//   - Two-digit repetition ("1212", "121212")
//   - Top-most-common literal blocklist (top 20 PINs from DataGenetics 2012
//     analysis of 3.4M leaked PINs, plus calendar-year patterns)
//
// Rules are length-agnostic where possible. For PINs that contain
// non-digits, IsWeakPIN returns false (they are out of scope here — the
// generator emits only digits).
func IsWeakPIN(pin string) bool {
	if pin == "" {
		return true
	}
	for _, r := range pin {
		if r < '0' || r > '9' {
			return false
		}
	}
	if isAllSame(pin) {
		return true
	}
	if isStrictSequence(pin, +1) || isStrictSequence(pin, -1) {
		return true
	}
	if isShortRepetition(pin) {
		return true
	}
	if commonPINBlocklist[pin] {
		return true
	}
	if isCalendarYear(pin) {
		return true
	}
	return false
}

func isAllSame(pin string) bool {
	if len(pin) < 2 {
		return false
	}
	first := pin[0]
	for i := 1; i < len(pin); i++ {
		if pin[i] != first {
			return false
		}
	}
	return true
}

// isStrictSequence reports whether pin is a strict step-of-`step` sequence,
// e.g. "1234" (step=+1) or "9876" (step=-1). Sequences must have length>=4
// to qualify (avoids classifying "12" or "21" as weak).
func isStrictSequence(pin string, step int) bool {
	if len(pin) < 4 {
		return false
	}
	for i := 1; i < len(pin); i++ {
		if int(pin[i])-int(pin[i-1]) != step {
			return false
		}
	}
	return true
}

// isShortRepetition reports whether pin is composed of repeats of a 2-digit
// or 3-digit subpattern, e.g. "1212", "121212", "123123". Length must be a
// multiple of the period and at least 2x the period.
func isShortRepetition(pin string) bool {
	for _, period := range []int{2, 3} {
		if len(pin) >= 2*period && len(pin)%period == 0 {
			head := pin[:period]
			ok := true
			for i := period; i < len(pin); i += period {
				if pin[i:i+period] != head {
					ok = false
					break
				}
			}
			if ok {
				return true
			}
		}
	}
	return false
}

// isCalendarYear reports whether a 4-digit PIN looks like a calendar year
// 1900-2099 — the largest single class of memorable PINs in real-world
// leaks (DataGenetics 2012 identified ~7% of all 4-digit PINs as years).
func isCalendarYear(pin string) bool {
	if len(pin) != 4 {
		return false
	}
	if !strings.HasPrefix(pin, "19") && !strings.HasPrefix(pin, "20") {
		return false
	}
	return true
}

// commonPINBlocklist is the top 20 most-frequently-chosen 4-digit PINs from
// the DataGenetics 2012 analysis (Berry, "PIN analysis", 2012). Each
// individually accounts for >0.5% of all PINs in the leaked dataset and
// together they cover ~26% of all chosen PINs.
//
// Source: https://www.datagenetics.com/blog/september32012/index.html
var commonPINBlocklist = map[string]bool{
	"1234": true, "1111": true, "0000": true, "1212": true,
	"7777": true, "1004": true, "2000": true, "4444": true,
	"2222": true, "6969": true, "9999": true, "3333": true,
	"5555": true, "6666": true, "1313": true, "8888": true,
	"4321": true, "2001": true, "1010": true, "1122": true,
}

package jcs

import (
	"errors"
	"strconv"
)

// ErrNonFiniteNumber is returned when a JSON number is NaN or ±Inf. RFC 8785
// (and I-JSON) forbid these; a signed export must never contain one.
var ErrNonFiniteNumber = errors.New("jcs: non-finite number (NaN/Inf) is not permitted")

// esNumber serializes a float64 exactly as ECMAScript's Number::toString
// (base 10) does — which is the number serialization RFC 8785 §3.2.2.3
// mandates, and which JavaScript's JSON.stringify (the producer,
// _shared/canonical.ts) emits. Getting this byte-identical is the crux of
// cross-language signature reproduction.
//
// The algorithm (ECMA-262 Number::toString): for a finite non-zero value,
// choose the shortest decimal digit string s (k digits, 10^(k-1) <= s < 10^k)
// and integer n such that s × 10^(n-k) == value. Then:
//
//	k <= n <= 21      → s followed by (n-k) zeros            (e.g. 100)
//	0 <  n <= 21      → s[:n] "." s[n:]                      (e.g. 1.5, 123.456)
//	-6 < n <= 0       → "0." (-n zeros) s                    (e.g. 0.99, 0.001)
//	otherwise         → s[0] ["." s[1:]] "e" sign |n-1|      (e.g. 1e+21, 1e-7)
//
// Go's strconv.FormatFloat(abs, 'e', -1, 64) yields the shortest round-trip
// digits + a base-10 exponent, from which s, k and n are recovered.
func esNumber(f float64) (string, error) {
	if f != f { // NaN
		return "", ErrNonFiniteNumber
	}
	if f > 1.7976931348623157e308 || f < -1.7976931348623157e308 {
		return "", ErrNonFiniteNumber // ±Inf
	}
	// ECMAScript: both +0 and -0 stringify to "0".
	if f == 0 {
		return "0", nil
	}

	sign := ""
	if f < 0 {
		sign = "-"
		f = -f
	}

	// Shortest scientific form: "d.dddde±XX" (Go always includes a sign and
	// at least two exponent digits, and drops the '.' when a single digit).
	sci := strconv.FormatFloat(f, 'e', -1, 64)

	// Split mantissa and exponent.
	ei := -1
	for i := 0; i < len(sci); i++ {
		if sci[i] == 'e' {
			ei = i
			break
		}
	}
	if ei < 0 {
		// Should not happen with the 'e' format; fall back defensively.
		return sign + sci, nil
	}
	mant := sci[:ei]
	exp, err := strconv.Atoi(sci[ei+1:])
	if err != nil {
		return "", err
	}

	// Digits s = mantissa with the '.' removed; k = len(s).
	digits := make([]byte, 0, len(mant))
	for i := 0; i < len(mant); i++ {
		if mant[i] != '.' {
			digits = append(digits, mant[i])
		}
	}
	// Strip any trailing zeros (shortest form should have none, but be safe so
	// k is minimal and the ES rules pick the right branch).
	for len(digits) > 1 && digits[len(digits)-1] == '0' {
		digits = digits[:len(digits)-1]
	}
	s := string(digits)
	k := len(s)
	// The first digit sits at 10^exp, so the decimal point is after position
	// n = exp + 1 relative to the start of s.
	n := exp + 1

	var out string
	switch {
	case k <= n && n <= 21:
		// Integer with (n-k) trailing zeros.
		buf := make([]byte, 0, n)
		buf = append(buf, s...)
		for i := 0; i < n-k; i++ {
			buf = append(buf, '0')
		}
		out = string(buf)
	case 0 < n && n <= 21:
		out = s[:n] + "." + s[n:]
	case -6 < n && n <= 0:
		buf := make([]byte, 0, 2+(-n)+k)
		buf = append(buf, '0', '.')
		for i := 0; i < -n; i++ {
			buf = append(buf, '0')
		}
		buf = append(buf, s...)
		out = string(buf)
	default:
		// Exponential. Exponent value is n-1.
		e := n - 1
		esign := "+"
		if e < 0 {
			esign = "-"
			e = -e
		}
		if k == 1 {
			out = s + "e" + esign + strconv.Itoa(e)
		} else {
			out = s[:1] + "." + s[1:] + "e" + esign + strconv.Itoa(e)
		}
	}
	return sign + out, nil
}

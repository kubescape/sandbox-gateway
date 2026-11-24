package hostset

import (
	"errors"
	"strings"
)

// CheckWidth applies the host pattern width rule to one hostPatterns entry.
// The policy compiler applies the same rule when it writes an object; the
// node applies it again because an object can be written by hand.
//
// A pattern passes when:
//
//  1. at most one label carries '*',
//  2. its last two labels are literal, and
//  3. a letter or digit stands outside the last two labels (a hyphen alone
//     does not count).
//
// A name without '*' always passes. The rule reads the pattern alone, with
// no public-suffix list, so "*.foo.co.uk" passes.
func CheckWidth(pattern string) error {
	if pattern == "" {
		return errors.New("empty pattern")
	}
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '*':
		default:
			return errors.New("pattern has a character that is not a lower-case letter, a digit, '-', '.' or '*': " + pattern)
		}
	}
	if strings.Contains(pattern, "**") {
		return errors.New("doubled wildcard: " + pattern)
	}
	labels := strings.Split(pattern, ".")
	for _, l := range labels {
		if l == "" {
			return errors.New("empty label (or a trailing dot): " + pattern)
		}
	}
	if !strings.Contains(pattern, "*") {
		return nil
	}
	if len(labels) < 3 {
		return errors.New("wildcard in the last two labels: " + pattern)
	}
	wild := 0
	for _, l := range labels {
		if strings.Contains(l, "*") {
			wild++
		}
	}
	if wild > 1 {
		return errors.New("more than one label carries a wildcard: " + pattern)
	}
	for _, l := range labels[len(labels)-2:] {
		if strings.Contains(l, "*") {
			return errors.New("wildcard in the last two labels: " + pattern)
		}
	}
	for _, l := range labels[:len(labels)-2] {
		for i := 0; i < len(l); i++ {
			if c := l[i]; (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
				return nil
			}
		}
	}
	return errors.New("nothing literal outside the last two labels: " + pattern)
}

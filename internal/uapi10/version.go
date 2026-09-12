// Copyright (C) 2026 Amutable GmbH

// Package uapi10 implements the version comparison algorithm of the [UAPI.10
// version format] specification, matching systemd's strverscmp_improved().
//
// [UAPI.10 version format]: https://uapi-group.org/specifications/specs/version_format_specification/
package uapi10

import (
	"cmp"
	"strings"
)

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func isValidVersionChar(c byte) bool {
	return isDigit(c) || isAlpha(c) || c == '-' || c == '.' || c == '~' || c == '^'
}

// first returns the first byte of s, or 0 if s is empty (mirroring the NUL
// terminator in the C implementation).
func first(s string) byte {
	if s == "" {
		return 0
	}
	return s[0]
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// prefixLen returns the length of the leading run of bytes matching pred.
func prefixLen(s string, pred func(byte) bool) int {
	n := 0
	for n < len(s) && pred(s[n]) {
		n++
	}
	return n
}

// cmpSeparator handles a separator prefix shared by both strings. If exactly
// one string starts with sep, that string is older and (result, true) is
// returned. If both do, the separator is consumed from both.
func cmpSeparator(a, b *string, sep byte) (int, bool) {
	aHas, bHas := first(*a) == sep, first(*b) == sep
	if aHas != bHas {
		if aHas {
			return -1, true
		}
		return 1, true
	}
	if aHas {
		*a, *b = (*a)[1:], (*b)[1:]
	}
	return 0, false
}

// Compare compares two version strings, returning -1 if a is older than b, 0
// if they are equivalent, and +1 if a is newer than b.
func Compare(a, b string) int {
	// As in strverscmp_improved(), empty strings are compared before invalid
	// characters are dropped.
	if a == "" || b == "" {
		return strings.Compare(a, b)
	}
	for {
		// Drop leading invalid characters.
		a = a[prefixLen(a, func(c byte) bool { return !isValidVersionChar(c) }):]
		b = b[prefixLen(b, func(c byte) bool { return !isValidVersionChar(c) }):]

		// '~' (pre-release) sorts before the end of the string, so it must be
		// handled before the end-of-string check.
		if r, done := cmpSeparator(&a, &b, '~'); done {
			return r
		}
		// A string that has ended is older than one with more segments.
		if a == "" || b == "" {
			return cmp.Compare(first(a), first(b))
		}
		// Handle the separators '-' (release), '^' (patched release) and '.'
		// (point release).
		for _, sep := range []byte{'-', '^', '.'} {
			if r, done := cmpSeparator(&a, &b, sep); done {
				return r
			}
		}

		if isDigit(first(a)) || isDigit(first(b)) {
			aa, bb := prefixLen(a, isDigit), prefixLen(b, isDigit)
			// A numeric segment is newer than an alphabetic (or empty) one.
			if r := cmp.Compare(btoi(aa != 0), btoi(bb != 0)); r != 0 {
				return r
			}
			aNum, bNum := strings.TrimLeft(a[:aa], "0"), strings.TrimLeft(b[:bb], "0")
			if r := cmp.Compare(len(aNum), len(bNum)); r != 0 {
				return r
			}
			if r := strings.Compare(aNum, bNum); r != 0 {
				return r
			}
			a, b = a[aa:], b[bb:]
		} else {
			aa, bb := prefixLen(a, isAlpha), prefixLen(b, isAlpha)
			n := min(aa, bb)
			if r := strings.Compare(a[:n], b[:n]); r != 0 {
				return r
			}
			// Longer is newer, e.g. abc vs abcde.
			if r := cmp.Compare(aa, bb); r != 0 {
				return r
			}
			a, b = a[aa:], b[bb:]
		}
	}
}

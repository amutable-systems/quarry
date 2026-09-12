// Copyright (C) 2026 Amutable GmbH

package uapi10_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.amutable.dev/quarry/internal/uapi10"
)

// orderedVersions is the ordering example from the specification (and
// strverscmp_improved).
var orderedVersions = []string{
	"122.1",
	"123~rc1-1",
	"123",
	"123-a",
	"123-a.1",
	"123-1",
	"123-1.1",
	"123^post1",
	"123.a-1",
	"123.1-1",
	"123a-1",
	"124-1",
}

func TestCompareOrdering(t *testing.T) {
	for i, a := range orderedVersions {
		assert.Equal(t, 0, uapi10.Compare(a, a), "%q == %q", a, a)
		for _, b := range orderedVersions[i+1:] {
			assert.Equal(t, -1, uapi10.Compare(a, b), "%q < %q", a, b)
			assert.Equal(t, 1, uapi10.Compare(b, a), "%q > %q", b, a)
		}
	}
}

func TestCompareEquivalent(t *testing.T) {
	for _, tc := range [][2]string{
		{"", ""},
		{"00123", "123"},
		{"123_a", "123a"}, // invalid characters are dropped
		{"1.0", "1.0"},
		{"~", "~"},
	} {
		assert.Equal(t, 0, uapi10.Compare(tc[0], tc[1]), "%q == %q", tc[0], tc[1])
	}
}

func TestCompareMisc(t *testing.T) {
	for _, tc := range []struct {
		older, newer string
	}{
		{"", "1"},
		{"", "~1"}, // empty is older than anything, even a pre-release
		{"1", "1.0"},
		{"1.0", "1.0.1"},
		{"1.9", "1.10"},
		{"2~rc1", "2"},
		{"2~rc1", "2~rc2"},
		{"1.0-1", "1.0^1"},
		{"B", "a"}, // in ASCII order, capitals sort lower
		{"abc", "abcde"},
		{"1.a", "1.1"}, // numeric segments are newer than alphabetic ones
		{"0.0.1~rc1", "0.0.1"},
		{"0.0.1", "0.0.1-rc1"}, // only '~' marks a pre-release
	} {
		assert.Equal(t, -1, uapi10.Compare(tc.older, tc.newer), "%q < %q", tc.older, tc.newer)
		assert.Equal(t, 1, uapi10.Compare(tc.newer, tc.older), "%q > %q", tc.newer, tc.older)
	}
}

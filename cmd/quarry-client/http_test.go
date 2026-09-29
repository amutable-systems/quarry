//go:build http

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package client

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidSysupdatePath(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		// Plain filenames
		{"foo.raw", true},
		{"image_1.2.3_x86-64.efi", true},
		// Interior slashes are now allowed (subdirectory entries)
		{"images/build-42/foo.raw", true},
		{"a/b/c/d.raw", true},
		// Empty, current and parent directory references are rejected
		{"", false},
		{".", false},
		{"..", false},
		{"foo/..", false},
		{"../foo", false},
		{"foo/../bar", false},
		{"foo/./bar", false},
		// Absolute paths and empty components are rejected
		{"/foo", false},
		{"/", false},
		{"foo//bar", false},
		{"foo/", false},
		// Overly long paths are rejected
		{strings.Repeat("a", 4097), false},
	} {
		assert.Equal(t, tc.want, validSysupdatePath(tc.path), "path %q", tc.path)
	}
}

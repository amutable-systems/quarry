// Copyright (C) 2026 Amutable GmbH

package uapi16_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.amutable.dev/quarry/internal/uapi16"
)

func TestValidateName(t *testing.T) {
	for _, test := range []struct {
		name  string
		valid bool
	}{
		// Plain names and nested paths are all fine.
		{"FooOS.raw", true},
		{"subdir/FooOS.raw", true},
		{"a/b/c/d.txt", true},
		{"...", true},
		{"..foo", true},
		{"naïve-ünïcödé.raw", true},
		// Manifest names are only forbidden for the directory the manifest
		// itself describes.
		{"subdir/Uapi16Manifest", true},
		{"subdir/Uapi16Manifest.gz", true},
		// Paths must be relative and normalised.
		{"", false},
		{"/FooOS.raw", false},
		{"FooOS.raw/", false},
		{"a//b", false},
		{".", false},
		{"..", false},
		{"./FooOS.raw", false},
		{"../FooOS.raw", false},
		{"a/./b", false},
		{"a/../b", false},
		{"a/.", false},
		{"a/..", false},
		// No control characters.
		{"foo\x00bar", false},
		{"foo\nbar", false},
		{"foo\tbar", false},
		{"foo\x7fbar", false},
		// Invalid UTF-8.
		{"foo\xffbar", false},
		// Manifest filenames in the described directory.
		{"Uapi16Manifest", false},
		{"Uapi16Manifest.gz", false},
		{"Uapi16Manifest.zst", false},
		{"Uapi16Manifest/foo", false},
		{"Uapi16Manifest.d/foo", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := uapi16.ValidateName(test.name)
			if test.valid {
				require.NoError(t, err, "name %q should be valid", test.name)
			} else {
				require.ErrorIs(t, err, uapi16.ErrInvalidName, "name %q should be invalid", test.name)
			}
		})
	}
}

// "Uapi16ManifestFoo" only collides if the prefix is followed by a dot.
func TestValidateNameManifestPrefix(t *testing.T) {
	require.NoError(t, uapi16.ValidateName(uapi16.Filename+"Foo"))
	require.ErrorIs(t, uapi16.ValidateName(uapi16.Filename+".Foo"), uapi16.ErrInvalidName)
}

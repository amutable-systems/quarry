// Copyright (C) 2026 Amutable GmbH

package uapi16

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"unicode/utf8"
)

// ErrInvalidName is returned by [ValidateName] (and thus [Writer.WriteFile])
// if a file name cannot be represented in a UAPI.16 manifest.
var ErrInvalidName = errors.New("invalid uapi.16 file name")

// ValidateName checks whether the given name can be used as the [File.Name] of
// a file object. Names must be normalised relative POSIX paths consisting of
// valid UTF-8 with no control characters, and the first path component may not
// collide with the name of a manifest file. Names that do not follow these
// rules simply cannot be encoded in a manifest.
//
// A wrapped [ErrInvalidName] error is returned for invalid names.
func ValidateName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: name is empty", ErrInvalidName)
	}
	if !utf8.ValidString(name) {
		return fmt.Errorf("%w %q: name is not valid utf-8", ErrInvalidName, name)
	}
	for _, ch := range name {
		if ch <= 0x1f || ch == 0x7f {
			return fmt.Errorf("%w %q: name contains control character %q", ErrInvalidName, name, ch)
		}
	}
	// UAPI.16 explicitly uses slash-separated paths so do not use filepath.
	if path.IsAbs(name) {
		return fmt.Errorf("%w %q: name is an absolute path", ErrInvalidName, name)
	}
	if path.Clean(name) != name { //nolint:forbidigo // purely lexical, never touches the filesystem
		return fmt.Errorf("%w %q: name is not a normalised path", ErrInvalidName, name)
	}
	// Detect leading ".."s and single-element "."s generically.
	for component := range strings.SplitSeq(name, "/") {
		switch component {
		case ".", "..":
			return fmt.Errorf("%w %q: name contains a forbidden %q component", ErrInvalidName, name, component)
		}
	}
	// A manifest is never listed in itself, so the entry it would occupy in the
	// directory it describes cannot be used. Deeper components are fine, as
	// those name entries in subdirectories.
	if first, _, _ := strings.Cut(name, "/"); first == Filename || strings.HasPrefix(first, Filename+".") {
		return fmt.Errorf("%w %q: name collides with manifest filename %q", ErrInvalidName, name, Filename)
	}
	return nil
}

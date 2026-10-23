// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package serde

import (
	"errors"
	"fmt"
)

// ErrMissingField is returned (usually wrapped) when a required field is
// missing entirely. [Validator] implementations should wrap it when reporting
// missing required fields.
var ErrMissingField = errors.New("missing required field")

// UnknownTypeError is returned when the tag of a [Union] value does not match
// any of its variants.
type UnknownTypeError struct {
	Union string // [UnionOptions.Name]
	Tag   string
}

func (err *UnknownTypeError) Error() string {
	return fmt.Sprintf("unsupported %s type %q", err.Union, err.Tag)
}

// UnknownFieldError is returned when a variant of a [Union] is given a field
// that it does not declare. Only the first unknown field is reported.
type UnknownFieldError struct {
	Union string // [UnionOptions.Name]
	Tag   string
	// Field is the name of the unknown field (for TOML, this is the full
	// dotted key of the field).
	Field string
}

func (err *UnknownFieldError) Error() string {
	return fmt.Sprintf("%s %q has unsupported field %q", err.Union, err.Tag, err.Field)
}

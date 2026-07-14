// Copyright (C) 2026 Amutable GmbH

package keystore

import (
	"errors"
	"fmt"
)

// withDriver is the concrete option type returned by [WithDriver].
type withDriver string

func (withDriver) IsOption()         {}
func (withDriver) IsGenerateOption() {}
func (withDriver) IsRotateOption()   {}
func (withDriver) IsImportOption()   {}

func (d withDriver) Apply(s *genericState) error {
	if d == "" {
		return errors.New("WithDriver: driver name cannot be empty")
	}
	// Last-wins -- a later [WithDriver] overrides an earlier one, and user
	// options override [CopyParameters]-derived ones.
	s.driver = string(d)
	return nil
}

func (d withDriver) String() string { return fmt.Sprintf("WithDriver(%q)", string(d)) }

// WithDriver returns an option that pins the driver used for the
// operation. If not given, [Store] picks a fallback ([DefaultDriver] for
// [Store.GenerateKey], the source key's driver for [Store.RotateKey]).
func WithDriver(name string) GenericOption {
	return withDriver(name)
}

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

// withKeyType is the concrete option type returned by [WithKeyType].
type withKeyType string

func (withKeyType) IsOption()         {}
func (withKeyType) IsGenerateOption() {}
func (withKeyType) IsRotateOption()   {}
func (withKeyType) IsImportOption()   {}

func (k withKeyType) keyTypeParam() (string, error) {
	if k == "" {
		return "", errors.New("WithKeyType: keytype cannot be empty")
	}
	return string(k), nil
}

// Apply intentionally does nothing. The keytype needs to be resolved
// before any state pass runs (and conflict-checking is
// order-independent), so the actual value goes through keyTypeParam. This
// method only exists so that the option is marked as consumed by the
// generic pass.
func (k withKeyType) Apply(*genericState) error { return nil }

func (k withKeyType) String() string { return fmt.Sprintf("WithKeyType(%q)", string(k)) }

// WithKeyType returns an option that pins the TUF keytype (e.g.
// [tufmetadata.KeyTypeECDSA_SHA2_P256]) for the operation.
//
// Note that TUF keytypes only name the key algorithm family. Despite the
// go-tuf constant names, [tufmetadata.KeyTypeECDSA_SHA2_P256] is just
// "ecdsa" -- it does not specify a curve or digest. All parameters other
// than the algorithm family come from driver defaults or keytype-specific
// options like [WithCurve] and [WithRSABits], and those options already
// imply their own keytype. As such, WithKeyType is only needed to select
// a non-default key algorithm with default parameters. Combining options
// with mismatched keytypes is an error, regardless of the option order.
func WithKeyType(keyType string) GenericOption {
	return withKeyType(keyType)
}

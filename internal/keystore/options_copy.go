// Copyright (C) 2026 Amutable GmbH

package keystore

import (
	"crypto/rsa"
	"fmt"
)

// Expander is a [RotateOption] that [Store.RotateKey] replaces with a set
// of derived options based on the source key. Currently only
// [CopyParameters] implements this.
type Expander interface {
	RotateOption
	Expand(key *GenericKey) ([]RotateOption, error)
}

// DeriveRotateOptions returns the [RotateOption]s needed to reproduce as
// much of the given key's parameters as can be recovered from its public
// key. Driver-specific options are not included -- those come from drivers
// implementing [ParameterReporter].
func DeriveRotateOptions(key *GenericKey) ([]RotateOption, error) {
	out := []RotateOption{
		WithDriver(key.Driver),
		WithKeyType(key.Public.Type),
	}
	pubKey, err := key.Public.ToPublicKey()
	if err != nil {
		return nil, fmt.Errorf("cannot derive rotate options for key %s: cannot decode public key: %w", key, err)
	}
	switch p := pubKey.(type) {
	case *rsa.PublicKey:
		out = append(out, WithRSABits(p.N.BitLen()))
	default:
		// Ed25519 and ECDSA P-256 have no further tunables observable from
		// the public key.
		_ = p
	}
	return out, nil
}

// copyParameters is the concrete type behind [CopyParameters]. It
// intentionally has no Apply method -- [Store.RotateKey] expands it before
// the resolver is built, so it never takes part in a state pass. If passed
// to a hand-built [NewRotateResolver] it is treated like any other
// unsupported option by [Resolver.CheckUnconsumed].
type copyParameters struct{}

func (copyParameters) IsOption()       {}
func (copyParameters) IsRotateOption() {}

func (copyParameters) Expand(key *GenericKey) ([]RotateOption, error) {
	return DeriveRotateOptions(key)
}

func (copyParameters) String() string { return "CopyParameters()" }

// CopyParameters returns a [RotateOption] that makes [Store.RotateKey]
// reproduce the source key's parameters as faithfully as possible: the
// driver and keytype, any parameters recoverable from the public key (such
// as the RSA modulus length), and any driver-specific parameters reported
// through [ParameterReporter].
//
// User-supplied options always take precedence over the copied parameters,
// so CopyParameters combined with [WithRSABits](4096) over a 3072-bit
// source key produces a 4096-bit replacement. This includes changing the
// keytype entirely, in which case the copied keytype-specific parameters
// are dropped.
func CopyParameters() RotateOption {
	return copyParameters{}
}

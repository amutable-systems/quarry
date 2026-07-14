// Copyright (C) 2026 Amutable GmbH

package keystore

import (
	"crypto/elliptic"
	"errors"
	"fmt"

	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
)

// ECDSAState is the keytype-specific state for ECDSA key generation,
// filled by [ApplyOptions].
type ECDSAState struct {
	// Curve is the requested elliptic curve. Nil means no [WithCurve]
	// option was given and the driver should use its default (in practice
	// always [elliptic.P256], the only TUF-supported curve).
	Curve elliptic.Curve
}

// withCurve is the concrete option type returned by [WithCurve].
type withCurve struct {
	curve elliptic.Curve
}

func (withCurve) IsOption()         {}
func (withCurve) IsGenerateOption() {}
func (withCurve) IsRotateOption()   {}

// keyTypeParam implies the ECDSA keytype. The curve is validated here so
// that unsupported curves are rejected even if the ECDSA state pass never
// runs.
func (c withCurve) keyTypeParam() (string, error) {
	if c.curve == nil {
		return "", errors.New("WithCurve: curve cannot be nil")
	}
	// NIST P-256 is the only ECDSA curve TUF supports. Use pointer-equality
	// against the stdlib's singleton to reject other curves explicitly.
	if c.curve != elliptic.P256() {
		return "", fmt.Errorf("WithCurve: only NIST P-256 is supported (TUF does not support other curves), got %s", c.curve.Params().Name)
	}
	return tufmetadata.KeyTypeECDSA_SHA2_P256, nil
}

func (c withCurve) Apply(s *ECDSAState) error {
	s.Curve = c.curve
	return nil
}

func (c withCurve) String() string {
	if c.curve == nil {
		return "WithCurve(<nil>)"
	}
	return fmt.Sprintf("WithCurve(%s)", c.curve.Params().Name)
}

// WithCurve returns an option that requests an ECDSA key on the given
// curve. Only NIST P-256 ([elliptic.P256]) is accepted, as TUF does not
// support any other ECDSA curves. WithCurve implies the ECDSA keytype, so
// a separate [WithKeyType] is not needed.
func WithCurve(c elliptic.Curve) GenerateRotateOption {
	return withCurve{curve: c}
}

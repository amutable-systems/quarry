// Copyright (C) 2026 Amutable GmbH

package keystore

import (
	"fmt"

	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
)

// MinRSABits is the smallest RSA modulus length accepted by [WithRSABits].
const MinRSABits = 2048

// RSAState is the keytype-specific state for RSA key generation, filled by
// [ApplyOptions].
type RSAState struct {
	// Bits is the RSA modulus length. Zero means no [WithRSABits] option
	// was given and the driver should use its default.
	Bits int
}

// withRSABits is the concrete option type returned by [WithRSABits].
type withRSABits int

func (withRSABits) IsOption()         {}
func (withRSABits) IsGenerateOption() {}
func (withRSABits) IsRotateOption()   {}

// keyTypeParam implies the RSA keytype. The bit size is validated here so
// that invalid sizes are rejected even if the RSA state pass never runs.
func (b withRSABits) keyTypeParam() (string, error) {
	if int(b) < MinRSABits {
		return "", fmt.Errorf("WithRSABits: bit size %d is below the minimum (%d)", int(b), MinRSABits)
	}
	return tufmetadata.KeyTypeRSASSA_PSS_SHA256, nil
}

func (b withRSABits) Apply(s *RSAState) error {
	// Last-wins -- a later [WithRSABits] overrides an earlier one, and user
	// options override [CopyParameters]-derived ones.
	s.Bits = int(b)
	return nil
}

func (b withRSABits) String() string { return fmt.Sprintf("WithRSABits(%d)", int(b)) }

// WithRSABits returns an option that pins the RSA modulus length in bits.
// WithRSABits implies the RSA keytype, so a separate [WithKeyType] is not
// needed. Bit sizes below [MinRSABits] are rejected.
func WithRSABits(n int) GenerateRotateOption {
	return withRSABits(n)
}

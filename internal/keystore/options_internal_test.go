// Copyright (C) 2026 Amutable GmbH

package keystore

import (
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
)

// These tests exercise the derived-vs-user option tiering used by
// [Store.RotateKey] for [CopyParameters]. The derived tier is only
// reachable through the internal constructor.

func TestResolverDerived_UserDriverOverrides(t *testing.T) {
	r, err := newResolver(
		[]Option{WithDriver("insecure")},
		[]Option{WithDriver("pkcs11")},
	)
	require.NoError(t, err)
	assert.Equal(t, "pkcs11", r.DriverName())
}

func TestResolverDerived_DriverUsedWhenNoUserOverride(t *testing.T) {
	r, err := newResolver(
		[]Option{WithDriver("insecure")},
		nil,
	)
	require.NoError(t, err)
	assert.Equal(t, "insecure", r.DriverName())
}

func TestResolverDerived_KeyTypeUsedWhenNoUserSignal(t *testing.T) {
	r, err := newResolver(
		[]Option{WithKeyType(tufmetadata.KeyTypeRSASSA_PSS_SHA256), WithRSABits(3072)},
		[]Option{WithDriver("insecure")}, // no user keytype signal
	)
	require.NoError(t, err)
	assert.Equal(t, tufmetadata.KeyTypeRSASSA_PSS_SHA256, r.KeyTypeName())

	var rs RSAState
	require.NoError(t, ApplyOptions(r, &rs))
	assert.Equal(t, 3072, rs.Bits)
	assert.NoError(t, r.CheckUnconsumed())
}

func TestResolverDerived_UserKeyTypeDiscardsDerivedSignals(t *testing.T) {
	// A user keytype signal (here implied by WithCurve) discards all
	// derived keytype signals, so migrating an RSA source key to ECDSA is
	// not a conflict.
	r, err := newResolver(
		[]Option{WithKeyType(tufmetadata.KeyTypeRSASSA_PSS_SHA256), WithRSABits(3072)},
		[]Option{WithCurve(elliptic.P256())},
	)
	require.NoError(t, err)
	assert.Equal(t, tufmetadata.KeyTypeECDSA_SHA2_P256, r.KeyTypeName())

	// The derived WithRSABits never fires (no RSA pass for an ECDSA key)
	// but derived options are exempt from the unconsumed check.
	var es ECDSAState
	require.NoError(t, ApplyOptions(r, &es))
	assert.NoError(t, r.CheckUnconsumed())
}

func TestResolverDerived_UserBitsOverrideDerived(t *testing.T) {
	// User options are applied after derived ones, so the user bits win.
	r, err := newResolver(
		[]Option{WithKeyType(tufmetadata.KeyTypeRSASSA_PSS_SHA256), WithRSABits(3072)},
		[]Option{WithRSABits(4096)},
	)
	require.NoError(t, err)
	assert.Equal(t, tufmetadata.KeyTypeRSASSA_PSS_SHA256, r.KeyTypeName())

	var rs RSAState
	require.NoError(t, ApplyOptions(r, &rs))
	assert.Equal(t, 4096, rs.Bits)
}

func TestResolverDerived_UserConflictStillErrors(t *testing.T) {
	// Discarding the derived tier must not relax conflict checking among
	// user options.
	_, err := newResolver(
		[]Option{WithKeyType(tufmetadata.KeyTypeRSASSA_PSS_SHA256)},
		[]Option{WithCurve(elliptic.P256()), WithRSABits(4096)},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "conflicting keytypes")
}

func TestResolverDerived_InvalidDerivedParameters(t *testing.T) {
	// A derived option failing validation (such as a legacy source key
	// with a sub-minimum RSA modulus) must error and name its origin.
	_, err := newResolver(
		[]Option{WithRSABits(1024)},
		nil,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid derived key parameters")
	assert.Contains(t, err.Error(), "minimum")
}

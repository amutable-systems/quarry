// Copyright (C) 2026 Amutable GmbH

package keystore_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/keystore"
)

// keyFromPublicKey wraps a Go crypto public key as a
// [keystore.GenericKey].
func keyFromPublicKey(t *testing.T, driver string, pub any) *keystore.GenericKey { //nolint:unparam // driver is part of the derived parameters under test
	t.Helper()
	tufKey, err := tufmetadata.KeyFromPublicKey(pub)
	require.NoError(t, err)
	return &keystore.GenericKey{
		Driver: driver,
		Public: *tufKey,
	}
}

func mustResolveRotate(t *testing.T, opts []keystore.RotateOption) *keystore.Resolver {
	t.Helper()
	res, err := keystore.NewRotateResolver(opts)
	require.NoError(t, err)
	return res
}

func TestDeriveRotateOptions_Ed25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key := keyFromPublicKey(t, "insecure", pub)

	opts, err := keystore.DeriveRotateOptions(key)
	require.NoError(t, err)

	res := mustResolveRotate(t, opts)
	assert.Equal(t, "insecure", res.DriverName())
	assert.Equal(t, tufmetadata.KeyTypeEd25519, res.KeyTypeName())

	// Ed25519 has no further per-keytype state to apply.
	assert.NoError(t, res.CheckUnconsumed())
}

func TestDeriveRotateOptions_ECDSAP256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key := keyFromPublicKey(t, "insecure", &priv.PublicKey)

	opts, err := keystore.DeriveRotateOptions(key)
	require.NoError(t, err)

	res := mustResolveRotate(t, opts)
	assert.Equal(t, "insecure", res.DriverName())
	assert.Equal(t, tufmetadata.KeyTypeECDSA_SHA2_P256, res.KeyTypeName())

	// ECDSA P-256 has no further per-keytype state to apply.
	assert.NoError(t, res.CheckUnconsumed())
}

func TestDeriveRotateOptions_RSA(t *testing.T) {
	for _, bits := range []int{2048, 3072, 4096} {
		t.Run(fmt.Sprintf("RSA-%d", bits), func(t *testing.T) {
			priv, err := rsa.GenerateKey(rand.Reader, bits)
			require.NoError(t, err)
			key := keyFromPublicKey(t, "insecure", &priv.PublicKey)

			opts, err := keystore.DeriveRotateOptions(key)
			require.NoError(t, err)

			res := mustResolveRotate(t, opts)
			assert.Equal(t, "insecure", res.DriverName())
			assert.Equal(t, tufmetadata.KeyTypeRSASSA_PSS_SHA256, res.KeyTypeName())

			var rs keystore.RSAState
			require.NoError(t, keystore.ApplyOptions(res, &rs))
			assert.Equal(t, bits, rs.Bits, "derived bits should match source modulus length")
			assert.NoError(t, res.CheckUnconsumed())
		})
	}
}

// CopyParameters must be a RotateOption (and Expander) but not a
// GenerateOption, so that Store.RotateKey's marker re-check rejects any
// unexpanded leak.
func TestCopyParameters_Markers(t *testing.T) {
	var opt keystore.Option = keystore.CopyParameters()

	_, isRotate := opt.(keystore.RotateOption)
	_, isGenerate := opt.(keystore.GenerateOption)
	_, isImport := opt.(keystore.ImportOption)
	_, isExport := opt.(keystore.ExportOption)
	assert.True(t, isRotate, "CopyParameters must implement RotateOption")
	assert.False(t, isGenerate, "CopyParameters must not implement GenerateOption")
	assert.False(t, isImport, "CopyParameters must not implement ImportOption")
	assert.False(t, isExport, "CopyParameters must not implement ExportOption")

	// And the Expander interface (so Store.RotateKey expands it).
	_, isExpander := opt.(keystore.Expander)
	assert.True(t, isExpander, "CopyParameters must implement Expander")
}

// CopyParameters has no Apply, so a hand-built rotate resolver must
// report it as unsupported rather than silently ignoring it.
func TestCopyParameters_UnconsumedInHandBuiltResolver(t *testing.T) {
	res, err := keystore.NewRotateResolver([]keystore.RotateOption{
		keystore.CopyParameters(),
	})
	require.NoError(t, err)

	err = res.CheckUnconsumed()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported option")
	assert.Contains(t, err.Error(), "CopyParameters()")
}

func TestCopyParameters_String(t *testing.T) {
	assert.Equal(t, "CopyParameters()", fmt.Sprint(keystore.CopyParameters()))
}

func TestCopyParameters_Expand(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	key := keyFromPublicKey(t, "insecure", &priv.PublicKey)

	expander, ok := keystore.CopyParameters().(keystore.Expander)
	require.True(t, ok)

	opts, err := expander.Expand(key)
	require.NoError(t, err)

	res := mustResolveRotate(t, opts)
	assert.Equal(t, "insecure", res.DriverName())
	assert.Equal(t, tufmetadata.KeyTypeRSASSA_PSS_SHA256, res.KeyTypeName())

	var rs keystore.RSAState
	require.NoError(t, keystore.ApplyOptions(res, &rs))
	assert.Equal(t, 2048, rs.Bits)
}

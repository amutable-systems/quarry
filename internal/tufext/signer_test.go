// Copyright (C) 2026 Amutable GmbH

//go:build insecure

package tufext_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/keystore"
	_ "go.amutable.dev/quarry/internal/keystore/insecure"
	"go.amutable.dev/quarry/internal/tufext"
)

func insecureDriver(t *testing.T) keystore.Driver {
	t.Helper()
	driver, ok := keystore.GetDriver("insecure")
	require.True(t, ok, "insecure driver must be registered")
	return driver
}

// verifyTUFSignature creates a root metadata that trusts the given key for the
// specified role, then uses go-tuf's VerifyDelegate to verify the signed
// metadata is valid from a TUF perspective.
func verifyTUFSignature(t *testing.T, roleName string, key *keystore.GenericKey, signedMeta any) {
	t.Helper()
	root := tufmetadata.Root()
	err := root.Signed.AddKey(&key.Public, roleName)
	require.NoError(t, err)
	err = root.VerifyDelegate(roleName, signedMeta)
	assert.NoError(t, err, "go-tuf VerifyDelegate should accept the signature")
}

func generateInsecureKey(ctx context.Context, t *testing.T) *keystore.GenericKey {
	t.Helper()
	key, err := insecureDriver(t).GenerateKey(ctx)
	require.NoError(t, err)
	return key
}

func importInsecureKey(ctx context.Context, t *testing.T, privKey crypto.PrivateKey) *keystore.GenericKey {
	t.Helper()
	key, err := insecureDriver(t).ImportKey(ctx, privKey)
	require.NoError(t, err)
	return key
}

func TestSignRole_Ed25519(t *testing.T) {
	ctx := context.Background()
	key := generateInsecureKey(ctx, t)

	meta := tufmetadata.Root()
	sig, err := tufext.SignRole(ctx, meta, key)
	require.NoError(t, err)
	require.NotNil(t, sig)

	// Verify the signature was appended to metadata.
	require.Len(t, meta.Signatures, 1)
	assert.Equal(t, meta.Signatures[0].KeyID, sig.KeyID)
	assert.Equal(t, meta.Signatures[0].Signature, sig.Signature)

	// Verify the key ID matches.
	keyID, err := key.ID()
	require.NoError(t, err)
	assert.Equal(t, string(keyID), sig.KeyID)

	// Verify the signature is valid.
	pubKey, err := key.Public.ToPublicKey()
	require.NoError(t, err)
	edPub, ok := pubKey.(ed25519.PublicKey)
	require.True(t, ok)

	// Re-encode the signed payload in canonical JSON (same as SignRole does).
	payload, err := cjson.EncodeCanonical(meta.Signed)
	require.NoError(t, err)
	assert.True(t, ed25519.Verify(edPub, payload, sig.Signature))

	// Verify using go-tuf's VerifyDelegate.
	verifyTUFSignature(t, tufmetadata.ROOT, key, meta)
}

func TestSignRole_ECDSA(t *testing.T) {
	ctx := context.Background()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	key := importInsecureKey(ctx, t, privKey)

	meta := tufmetadata.Snapshot()
	sig, err := tufext.SignRole(ctx, meta, key)
	require.NoError(t, err)
	require.NotNil(t, sig)

	require.Len(t, meta.Signatures, 1)

	// Verify the ECDSA signature.
	payload, err := cjson.EncodeCanonical(meta.Signed)
	require.NoError(t, err)

	// ECDSA needs the payload hashed first (SHA-256).
	hash := sha256.Sum256(payload)
	assert.True(t, ecdsa.VerifyASN1(&privKey.PublicKey, hash[:], sig.Signature))

	// Verify using go-tuf's VerifyDelegate.
	verifyTUFSignature(t, tufmetadata.SNAPSHOT, key, meta)
}

func TestSignRole_RSA(t *testing.T) {
	ctx := context.Background()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	key := importInsecureKey(ctx, t, privKey)

	meta := tufmetadata.Timestamp()
	sig, err := tufext.SignRole(ctx, meta, key)
	require.NoError(t, err)
	require.NotNil(t, sig)

	require.Len(t, meta.Signatures, 1)

	// Verify the RSA-PSS signature.
	payload, err := cjson.EncodeCanonical(meta.Signed)
	require.NoError(t, err)

	hash := sha256.Sum256(payload)
	err = rsa.VerifyPSS(&privKey.PublicKey, crypto.SHA256, hash[:], sig.Signature, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})
	require.NoError(t, err)

	// Verify using go-tuf's VerifyDelegate.
	verifyTUFSignature(t, tufmetadata.TIMESTAMP, key, meta)
}

func TestSignRole_MultipleSignatures(t *testing.T) {
	ctx := context.Background()

	key1 := generateInsecureKey(ctx, t)
	key2 := generateInsecureKey(ctx, t)

	meta := tufmetadata.Root()

	sig1, err := tufext.SignRole(ctx, meta, key1)
	require.NoError(t, err)

	sig2, err := tufext.SignRole(ctx, meta, key2)
	require.NoError(t, err)

	require.Len(t, meta.Signatures, 2)
	assert.NotEqual(t, sig1.KeyID, sig2.KeyID)
	assert.Equal(t, sig1.KeyID, meta.Signatures[0].KeyID)
	assert.Equal(t, sig2.KeyID, meta.Signatures[1].KeyID)
}

func TestSignRole_AllRoleTypes(t *testing.T) {
	ctx := context.Background()
	key := generateInsecureKey(ctx, t)

	pubKey, err := key.Public.ToPublicKey()
	require.NoError(t, err)
	edPub, ok := pubKey.(ed25519.PublicKey)
	require.True(t, ok, "expected ed25519.PublicKey")

	verifyEd25519 := func(t *testing.T, sig *tufmetadata.Signature, signed any) {
		t.Helper()
		payload, err := cjson.EncodeCanonical(signed)
		require.NoError(t, err)
		assert.True(t, ed25519.Verify(edPub, payload, sig.Signature))
	}

	t.Run("Root", func(t *testing.T) {
		meta := tufmetadata.Root()
		sig, err := tufext.SignRole(ctx, meta, key)
		require.NoError(t, err)
		verifyEd25519(t, sig, meta.Signed)
		verifyTUFSignature(t, tufmetadata.ROOT, key, meta)
	})

	t.Run("Snapshot", func(t *testing.T) {
		meta := tufmetadata.Snapshot()
		sig, err := tufext.SignRole(ctx, meta, key)
		require.NoError(t, err)
		verifyEd25519(t, sig, meta.Signed)
		verifyTUFSignature(t, tufmetadata.SNAPSHOT, key, meta)
	})

	t.Run("Targets", func(t *testing.T) {
		meta := tufmetadata.Targets()
		sig, err := tufext.SignRole(ctx, meta, key)
		require.NoError(t, err)
		verifyEd25519(t, sig, meta.Signed)
		verifyTUFSignature(t, tufmetadata.TARGETS, key, meta)
	})

	t.Run("Timestamp", func(t *testing.T) {
		meta := tufmetadata.Timestamp()
		sig, err := tufext.SignRole(ctx, meta, key)
		require.NoError(t, err)
		verifyEd25519(t, sig, meta.Signed)
		verifyTUFSignature(t, tufmetadata.TIMESTAMP, key, meta)
	})
}

func TestSignRole_BadDriver(t *testing.T) {
	ctx := context.Background()

	key := generateInsecureKey(ctx, t)
	key.Driver = "nonexistent"

	meta := tufmetadata.Root()
	_, err := tufext.SignRole(ctx, meta, key)
	assert.Error(t, err)
}

func TestSignRole_UnsupportedKeyScheme(t *testing.T) {
	ctx := context.Background()

	key := generateInsecureKey(ctx, t)
	// Mangle the key scheme to something unsupported.
	key.Public.Scheme = "unsupported-scheme"

	meta := tufmetadata.Root()
	_, err := tufext.SignRole(ctx, meta, key)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported by TUF")
}

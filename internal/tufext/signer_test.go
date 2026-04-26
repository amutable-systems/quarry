//go:build insecure

// Copyright (C) 2026 Amutable GmbH

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

	meta := tufext.DefaultRoot()
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

	meta := tufext.DefaultSnapshot()
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

	meta := tufext.DefaultTimestamp()
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

	meta := tufext.DefaultRoot()

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
		meta := tufext.DefaultRoot()
		sig, err := tufext.SignRole(ctx, meta, key)
		require.NoError(t, err)
		verifyEd25519(t, sig, meta.Signed)
		verifyTUFSignature(t, tufmetadata.ROOT, key, meta)
	})

	t.Run("Snapshot", func(t *testing.T) {
		meta := tufext.DefaultSnapshot()
		sig, err := tufext.SignRole(ctx, meta, key)
		require.NoError(t, err)
		verifyEd25519(t, sig, meta.Signed)
		verifyTUFSignature(t, tufmetadata.SNAPSHOT, key, meta)
	})

	t.Run("Targets", func(t *testing.T) {
		meta := tufext.DefaultTargets()
		sig, err := tufext.SignRole(ctx, meta, key)
		require.NoError(t, err)
		verifyEd25519(t, sig, meta.Signed)
		verifyTUFSignature(t, tufmetadata.TARGETS, key, meta)
	})

	t.Run("Timestamp", func(t *testing.T) {
		meta := tufext.DefaultTimestamp()
		sig, err := tufext.SignRole(ctx, meta, key)
		require.NoError(t, err)
		verifyEd25519(t, sig, meta.Signed)
		verifyTUFSignature(t, tufmetadata.TIMESTAMP, key, meta)
	})
}

func TestSignRole_ReplacesExistingSignature(t *testing.T) {
	ctx := context.Background()
	key := generateInsecureKey(ctx, t)

	meta := tufext.DefaultRoot()

	// Sign once.
	sig1, err := tufext.SignRole(ctx, meta, key)
	require.NoError(t, err)
	require.Len(t, meta.Signatures, 1)

	// Modify the metadata so the second signature is different.
	meta.Signed.Version = 2

	// Sign again with the same key.
	sig2, err := tufext.SignRole(ctx, meta, key)
	require.NoError(t, err)

	// There should still be exactly one signature, not two.
	require.Len(t, meta.Signatures, 1)
	assert.Equal(t, sig2.KeyID, meta.Signatures[0].KeyID)
	assert.Equal(t, sig2.Signature, meta.Signatures[0].Signature)

	// The new signature should differ from the old one (since the payload changed).
	assert.NotEqual(t, sig1.Signature, sig2.Signature)

	// Verify the new signature is valid against the updated payload.
	verifyTUFSignature(t, tufmetadata.ROOT, key, meta)
}

func TestSignRole_ReplacesExistingSignature_PreservesOtherKeys(t *testing.T) {
	ctx := context.Background()

	key1 := generateInsecureKey(ctx, t)
	key2 := generateInsecureKey(ctx, t)

	meta := tufext.DefaultRoot()

	// Sign with both keys.
	_, err := tufext.SignRole(ctx, meta, key1)
	require.NoError(t, err)
	_, err = tufext.SignRole(ctx, meta, key2)
	require.NoError(t, err)
	require.Len(t, meta.Signatures, 2)

	// Modify the metadata and re-sign with key1 only.
	meta.Signed.Version = 2
	sig1New, err := tufext.SignRole(ctx, meta, key1)
	require.NoError(t, err)

	// Should still have exactly two signatures.
	require.Len(t, meta.Signatures, 2)

	// key2's signature should be first (unchanged), key1's new signature should be second.
	key2ID, err := key2.ID()
	require.NoError(t, err)
	assert.Equal(t, string(key2ID), meta.Signatures[0].KeyID)
	assert.Equal(t, sig1New.KeyID, meta.Signatures[1].KeyID)

	// The new key1 signature should verify against the updated payload.
	verifyTUFSignature(t, tufmetadata.ROOT, key1, meta)
}

func TestSignRole_ReplacesExistingSignature_DuplicateKeyIDs(t *testing.T) {
	ctx := context.Background()
	key := generateInsecureKey(ctx, t)
	keyID, err := key.ID()
	require.NoError(t, err)

	t.Run("Garbled", func(t *testing.T) {
		meta := tufext.DefaultRoot()

		// Manually inject multiple garbled signatures with the same key ID,
		// simulating a malformed state from an external tool.
		meta.Signatures = []tufmetadata.Signature{
			{KeyID: string(keyID), Signature: []byte("garbled-1")},
			{KeyID: string(keyID), Signature: []byte("garbled-2")},
			{KeyID: string(keyID), Signature: []byte("garbled-3")},
		}

		sig, err := tufext.SignRole(ctx, meta, key)
		require.NoError(t, err)

		// All three garbled entries should be replaced by a single valid signature.
		require.Len(t, meta.Signatures, 1)
		assert.Equal(t, sig.KeyID, meta.Signatures[0].KeyID)
		assert.Equal(t, sig.Signature, meta.Signatures[0].Signature)

		verifyTUFSignature(t, tufmetadata.ROOT, key, meta)
	})

	t.Run("RealDuplicates", func(t *testing.T) {
		meta := tufext.DefaultRoot()

		// Produce a real signature, then manually duplicate it in the slice.
		realSig, err := tufext.SignRole(ctx, meta, key)
		require.NoError(t, err)
		require.Len(t, meta.Signatures, 1)

		meta.Signatures = append(meta.Signatures,
			tufmetadata.Signature{KeyID: realSig.KeyID, Signature: realSig.Signature},
			tufmetadata.Signature{KeyID: realSig.KeyID, Signature: realSig.Signature},
		)
		require.Len(t, meta.Signatures, 3)

		// Re-sign with the same key -- should collapse all three into one.
		meta.Signed.Version = 2
		sig, err := tufext.SignRole(ctx, meta, key)
		require.NoError(t, err)

		require.Len(t, meta.Signatures, 1)
		assert.Equal(t, sig.KeyID, meta.Signatures[0].KeyID)
		assert.Equal(t, sig.Signature, meta.Signatures[0].Signature)
		assert.NotEqual(t, realSig.Signature, sig.Signature, "signature should differ after payload change")

		verifyTUFSignature(t, tufmetadata.ROOT, key, meta)
	})

	t.Run("InterleavedWithOtherKeys", func(t *testing.T) {
		key2 := generateInsecureKey(ctx, t)
		key3 := generateInsecureKey(ctx, t)
		key2ID, err := key2.ID()
		require.NoError(t, err)
		key3ID, err := key3.ID()
		require.NoError(t, err)

		meta := tufext.DefaultRoot()

		// Manually build a [key1, key2, key1, key3, key1] signature list.
		meta.Signatures = []tufmetadata.Signature{
			{KeyID: string(keyID), Signature: []byte("old-1")},
			{KeyID: string(key2ID), Signature: []byte("key2-sig")},
			{KeyID: string(keyID), Signature: []byte("old-2")},
			{KeyID: string(key3ID), Signature: []byte("key3-sig")},
			{KeyID: string(keyID), Signature: []byte("old-3")},
		}

		sig, err := tufext.SignRole(ctx, meta, key)
		require.NoError(t, err)

		// Result should be [key2, key3, key1] -- other keys preserve
		// relative order, key1 duplicates all removed, new sig appended.
		require.Len(t, meta.Signatures, 3)
		assert.Equal(t, string(key2ID), meta.Signatures[0].KeyID)
		assert.EqualValues(t, []byte("key2-sig"), meta.Signatures[0].Signature)
		assert.Equal(t, string(key3ID), meta.Signatures[1].KeyID)
		assert.EqualValues(t, []byte("key3-sig"), meta.Signatures[1].Signature)
		assert.Equal(t, sig.KeyID, meta.Signatures[2].KeyID)
		assert.Equal(t, sig.Signature, meta.Signatures[2].Signature)

		verifyTUFSignature(t, tufmetadata.ROOT, key, meta)
	})
}

func TestSignRole_BadDriver(t *testing.T) {
	ctx := context.Background()

	key := generateInsecureKey(ctx, t)
	key.Driver = "nonexistent"

	meta := tufext.DefaultRoot()
	_, err := tufext.SignRole(ctx, meta, key)
	assert.Error(t, err)
}

func TestSignRole_UnsupportedKeyScheme(t *testing.T) {
	ctx := context.Background()

	key := generateInsecureKey(ctx, t)
	// Mangle the key scheme to something unsupported.
	key.Public.Scheme = "unsupported-scheme"

	meta := tufext.DefaultRoot()
	_, err := tufext.SignRole(ctx, meta, key)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported by TUF")
}

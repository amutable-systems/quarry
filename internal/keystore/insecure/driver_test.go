//go:build insecure

// Copyright (C) 2026 Amutable GmbH

package insecure_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.amutable.dev/quarry/internal/keystore"
	"go.amutable.dev/quarry/internal/keystore/insecure"
)

func TestDriverName(t *testing.T) {
	assert.Equal(t, "insecure", insecure.Driver.Name())
}

func TestDriverRegistered(t *testing.T) {
	driver, ok := keystore.GetDriver("insecure")
	require.True(t, ok, "insecure driver should be registered")
	assert.Equal(t, insecure.Driver, driver)
}

func TestGenerateKey(t *testing.T) {
	ctx := context.Background()

	key, err := insecure.Driver.GenerateKey(ctx)
	require.NoError(t, err)
	require.NotNil(t, key)

	assert.Equal(t, "insecure", key.Driver)
	assert.Equal(t, keystore.KeyTypeEd25519, key.KeyType())

	keyID, err := key.ID()
	require.NoError(t, err)
	assert.True(t, keyID.IsValid(), "generated key should have a valid ID")
}

func TestGenerateKeyProducesDifferentKeys(t *testing.T) {
	ctx := context.Background()

	key1, err := insecure.Driver.GenerateKey(ctx)
	require.NoError(t, err)

	key2, err := insecure.Driver.GenerateKey(ctx)
	require.NoError(t, err)

	id1, err := key1.ID()
	require.NoError(t, err)
	id2, err := key2.ID()
	require.NoError(t, err)

	assert.NotEqual(t, id1, id2, "two generated keys should have different IDs")
}

func TestGetSigner(t *testing.T) {
	ctx := context.Background()

	key, err := insecure.Driver.GenerateKey(ctx)
	require.NoError(t, err)

	signer, err := insecure.Driver.GetSigner(ctx, key)
	require.NoError(t, err)
	require.NotNil(t, signer)

	// Verify the signer can actually sign.
	msg := []byte("test message")
	signerOpts := key.KeyType().SignerOpts()
	sig, err := signer.Sign(rand.Reader, msg, signerOpts)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)

	// Verify the signature using the public key.
	pubKey, ok := signer.Public().(ed25519.PublicKey)
	require.True(t, ok, "expected ed25519.PublicKey")
	assert.True(t, ed25519.Verify(pubKey, msg, sig))
}

func TestExportKey(t *testing.T) {
	ctx := context.Background()

	key, err := insecure.Driver.GenerateKey(ctx)
	require.NoError(t, err)

	exported, err := insecure.Driver.ExportKey(ctx, key)
	require.NoError(t, err)
	require.NotNil(t, exported)

	// ExportKey returns a crypto.Signer for the insecure driver.
	signer, ok := exported.(crypto.Signer)
	require.True(t, ok, "exported key should be a crypto.Signer")

	// The signer should produce valid signatures.
	msg := []byte("export test")
	sig, err := signer.Sign(rand.Reader, msg, crypto.Hash(0))
	require.NoError(t, err)

	pubKey, ok := signer.Public().(ed25519.PublicKey)
	require.True(t, ok, "expected ed25519.PublicKey")
	assert.True(t, ed25519.Verify(pubKey, msg, sig))
}

func TestImportKey_Ed25519(t *testing.T) {
	ctx := context.Background()

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	genericKey, err := insecure.Driver.ImportKey(ctx, privKey)
	require.NoError(t, err)
	require.NotNil(t, genericKey)

	assert.Equal(t, "insecure", genericKey.Driver)
	assert.Equal(t, keystore.KeyTypeEd25519, genericKey.KeyType())

	// Verify the imported key produces the same signer.
	signer, err := insecure.Driver.GetSigner(ctx, genericKey)
	require.NoError(t, err)
	assert.True(t, pubKey.Equal(signer.Public()), "imported key should have the same public key")
}

func TestImportKey_ECDSA(t *testing.T) {
	ctx := context.Background()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	genericKey, err := insecure.Driver.ImportKey(ctx, privKey)
	require.NoError(t, err)
	require.NotNil(t, genericKey)

	assert.Equal(t, "insecure", genericKey.Driver)
	assert.Equal(t, keystore.KeyTypeECDSA_SHA2_P256, genericKey.KeyType())

	signer, err := insecure.Driver.GetSigner(ctx, genericKey)
	require.NoError(t, err)
	assert.True(t, privKey.PublicKey.Equal(signer.Public()), "imported ECDSA key should match")
}

func TestImportKey_RSA(t *testing.T) {
	ctx := context.Background()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	genericKey, err := insecure.Driver.ImportKey(ctx, privKey)
	require.NoError(t, err)
	require.NotNil(t, genericKey)

	assert.Equal(t, "insecure", genericKey.Driver)
	assert.Equal(t, keystore.KeyTypeRSASSA_PSS_SHA256, genericKey.KeyType())

	signer, err := insecure.Driver.GetSigner(ctx, genericKey)
	require.NoError(t, err)
	assert.True(t, privKey.PublicKey.Equal(signer.Public()), "imported RSA key should match")
}

func TestImportKey_InvalidType(t *testing.T) {
	ctx := context.Background()

	_, err := insecure.Driver.ImportKey(ctx, "not a key")
	assert.Error(t, err, "importing a non-key should fail")
}

func TestRoundTrip_GenerateExportImport(t *testing.T) {
	ctx := context.Background()

	// Generate a key.
	original, err := insecure.Driver.GenerateKey(ctx)
	require.NoError(t, err)

	// Export the key.
	exported, err := insecure.Driver.ExportKey(ctx, original)
	require.NoError(t, err)

	// The exported value from insecure is a crypto.Signer, which is also a
	// CommonPrivateKey. Re-import it.
	reimported, err := insecure.Driver.ImportKey(ctx, exported)
	require.NoError(t, err)

	// The keys should be equivalent.
	origID, err := original.ID()
	require.NoError(t, err)
	reimportedID, err := reimported.ID()
	require.NoError(t, err)
	assert.Equal(t, origID, reimportedID, "round-tripped key should have the same ID")
}

func TestExportKey_ECDSA(t *testing.T) {
	ctx := context.Background()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	genericKey, err := insecure.Driver.ImportKey(ctx, privKey)
	require.NoError(t, err)

	exported, err := insecure.Driver.ExportKey(ctx, genericKey)
	require.NoError(t, err)

	signer, ok := exported.(crypto.Signer)
	require.True(t, ok, "exported ECDSA key should be a crypto.Signer")
	assert.True(t, privKey.PublicKey.Equal(signer.Public()), "exported public key should match original")
}

func TestExportKey_RSA(t *testing.T) {
	ctx := context.Background()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	genericKey, err := insecure.Driver.ImportKey(ctx, privKey)
	require.NoError(t, err)

	exported, err := insecure.Driver.ExportKey(ctx, genericKey)
	require.NoError(t, err)

	signer, ok := exported.(crypto.Signer)
	require.True(t, ok, "exported RSA key should be a crypto.Signer")
	assert.True(t, privKey.PublicKey.Equal(signer.Public()), "exported public key should match original")
}

func TestRoundTrip_ImportExportImport_ECDSA(t *testing.T) {
	ctx := context.Background()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Import → Export → Re-import.
	imported, err := insecure.Driver.ImportKey(ctx, privKey)
	require.NoError(t, err)

	exported, err := insecure.Driver.ExportKey(ctx, imported)
	require.NoError(t, err)

	reimported, err := insecure.Driver.ImportKey(ctx, exported)
	require.NoError(t, err)

	importedID, err := imported.ID()
	require.NoError(t, err)
	reimportedID, err := reimported.ID()
	require.NoError(t, err)
	assert.Equal(t, importedID, reimportedID, "round-tripped ECDSA key should have the same ID")
}

func TestRoundTrip_ImportExportImport_RSA(t *testing.T) {
	ctx := context.Background()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Import → Export → Re-import.
	imported, err := insecure.Driver.ImportKey(ctx, privKey)
	require.NoError(t, err)

	exported, err := insecure.Driver.ExportKey(ctx, imported)
	require.NoError(t, err)

	reimported, err := insecure.Driver.ImportKey(ctx, exported)
	require.NoError(t, err)

	importedID, err := imported.ID()
	require.NoError(t, err)
	reimportedID, err := reimported.ID()
	require.NoError(t, err)
	assert.Equal(t, importedID, reimportedID, "round-tripped RSA key should have the same ID")
}

func TestGetSigner_WrongDriver(t *testing.T) {
	ctx := context.Background()

	// Create a GenericKey with a wrong driver name.
	key, err := insecure.Driver.GenerateKey(ctx)
	require.NoError(t, err)

	key.Driver = "nonexistent"
	_, err = insecure.Driver.GetSigner(ctx, key)
	assert.Error(t, err, "GetSigner should fail for wrong driver name")
}

func TestGetSigner_CorruptKeyData(t *testing.T) {
	ctx := context.Background()

	key, err := insecure.Driver.GenerateKey(ctx)
	require.NoError(t, err)

	// Corrupt the key data so PKCS#8 parsing fails.
	key.Data = []byte(`"aW52YWxpZA=="`)
	_, err = insecure.Driver.GetSigner(ctx, key)
	assert.Error(t, err)
}

func TestGetSigner_MismatchedPublicKey(t *testing.T) {
	ctx := context.Background()

	key1, err := insecure.Driver.GenerateKey(ctx)
	require.NoError(t, err)

	key2, err := insecure.Driver.GenerateKey(ctx)
	require.NoError(t, err)

	// Put key1's private key data with key2's public key.
	key1.Public = key2.Public
	_, err = insecure.Driver.GetSigner(ctx, key1)
	assert.Error(t, err, "mismatched public key should be detected")
}

func TestGetSigner_InvalidJSON(t *testing.T) {
	ctx := context.Background()

	key, err := insecure.Driver.GenerateKey(ctx)
	require.NoError(t, err)

	// Set invalid JSON as key data.
	key.Data = []byte(`{invalid`)
	_, err = insecure.Driver.GetSigner(ctx, key)
	assert.Error(t, err)
}

func TestExportKey_WrongDriver(t *testing.T) {
	ctx := context.Background()

	key, err := insecure.Driver.GenerateKey(ctx)
	require.NoError(t, err)

	key.Driver = "nonexistent"
	_, err = insecure.Driver.ExportKey(ctx, key)
	assert.Error(t, err)
}

// Copyright (C) 2026 Amutable GmbH

package keystore_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
	"golang.org/x/sys/unix"

	"go.amutable.dev/quarry/internal/keystore"
	"go.amutable.dev/quarry/internal/keystore/keyopts"
)

const testDriverName = "test-driver"

// testDriver is a minimal keystore.Driver used to test GenericKey methods
// without depending on the insecure driver.
type testDriver struct {
	// signers maps key IDs to their corresponding signers, populated by
	// generateTestKey.
	signers map[string]crypto.Signer
}

func (d *testDriver) Name() string { return testDriverName }

func (d *testDriver) GenerateKey(_ context.Context, _ ...keyopts.GenerateOption) (*keystore.GenericKey, error) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	tufKey, err := tufmetadata.KeyFromPublicKey(privKey.Public())
	if err != nil {
		return nil, err
	}
	key := &keystore.GenericKey{
		Driver: d.Name(),
		Public: *tufKey,
	}
	id, err := key.ID()
	if err != nil {
		return nil, err
	}
	d.signers[string(id)] = privKey
	return key, nil
}

func (d *testDriver) ImportKey(context.Context, any, ...keyopts.ImportOption) (*keystore.GenericKey, error) {
	panic("not implemented")
}

func (d *testDriver) ExportKey(context.Context, *keystore.GenericKey, ...keyopts.ExportOption) (any, error) {
	panic("not implemented")
}

func (d *testDriver) GetSigner(_ context.Context, key *keystore.GenericKey) (crypto.Signer, error) {
	id, err := key.ID()
	if err != nil {
		return nil, err
	}
	signer, ok := d.signers[string(id)]
	if !ok {
		return nil, fmt.Errorf("test driver: unknown key %s", id)
	}
	return signer, nil
}

var testDrv = &testDriver{signers: make(map[string]crypto.Signer)}

func init() {
	keystore.MustRegisterDriver(testDrv)
}

func generateTestKey(t *testing.T) *keystore.GenericKey {
	t.Helper()
	key, err := testDrv.GenerateKey(context.Background())
	require.NoError(t, err)
	return key
}

func TestGetDriver_NotFound(t *testing.T) {
	driver, ok := keystore.GetDriver("nonexistent_driver")
	assert.False(t, ok)
	assert.Nil(t, driver)
}

func TestOpenStore_InvalidPath(t *testing.T) {
	_, err := keystore.OpenStore("/nonexistent/path/to/store")
	assert.Error(t, err)
}

func TestGenericKey_ID(t *testing.T) {
	key := generateTestKey(t)

	keyID, err := key.ID()
	require.NoError(t, err)
	assert.True(t, keyID.IsValid())

	// Calling ID again should return the same value.
	keyID2, err := key.ID()
	require.NoError(t, err)
	assert.Equal(t, keyID, keyID2)
}

func TestGenericKey_String(t *testing.T) {
	key := generateTestKey(t)

	str := key.String()
	assert.NotEmpty(t, str)

	// String should be the key ID for valid keys.
	keyID, err := key.ID()
	require.NoError(t, err)
	assert.Equal(t, string(keyID), str)
}

func TestGenericKey_KeyType(t *testing.T) {
	key := generateTestKey(t)

	kt := key.KeyType()
	assert.Equal(t, keystore.KeyTypeEd25519, kt)
}

func TestGenericKey_GetSigner(t *testing.T) {
	ctx := context.Background()
	key := generateTestKey(t)

	signer, err := key.GetSigner(ctx)
	require.NoError(t, err)
	require.NotNil(t, signer)

	// Verify we can sign something with the returned signer.
	msg := []byte("hello world")
	sig, err := signer.Sign(rand.Reader, msg, crypto.Hash(0))
	require.NoError(t, err)

	pubKey, ok := signer.Public().(ed25519.PublicKey)
	require.True(t, ok, "expected ed25519.PublicKey")
	assert.True(t, ed25519.Verify(pubKey, msg, sig))
}

func TestGenericKey_GetSigner_BadDriver(t *testing.T) {
	ctx := context.Background()
	key := generateTestKey(t)

	// Clobber the driver name so it can't be found.
	key.Driver = "doesnotexist"
	_, err := key.GetSigner(ctx)
	assert.Error(t, err) //nolint:testifylint // assert is fine for error path checks
	assert.Contains(t, err.Error(), "doesnotexist")
}

func TestStore_AddGetUnlinkKey(t *testing.T) {
	ctx := context.Background()

	storeDir := t.TempDir()
	store, err := keystore.OpenStore(storeDir)
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck // test code

	key := generateTestKey(t)

	// Add the key.
	keyID, err := store.AddKey(ctx, key)
	require.NoError(t, err)
	assert.True(t, keyID.IsValid())

	// Get the key back.
	retrieved, err := store.GetKey(ctx, keyID)
	require.NoError(t, err)
	require.NotNil(t, retrieved)

	retrievedID, err := retrieved.ID()
	require.NoError(t, err)
	assert.Equal(t, keyID, retrievedID)
	assert.Equal(t, key.Driver, retrieved.Driver)
	assert.Equal(t, key.KeyType(), retrieved.KeyType())

	// The retrieved key should produce a working signer.
	signer, err := retrieved.GetSigner(ctx)
	require.NoError(t, err)
	msg := []byte("store test")
	sig, err := signer.Sign(rand.Reader, msg, crypto.Hash(0))
	require.NoError(t, err)

	pubKey, ok := signer.Public().(ed25519.PublicKey)
	require.True(t, ok, "expected ed25519.PublicKey")
	assert.True(t, ed25519.Verify(pubKey, msg, sig))

	// Unlink the key.
	err = store.UnlinkKey(ctx, keyID)
	require.NoError(t, err)

	// Getting the key after unlink should fail.
	_, err = store.GetKey(ctx, keyID)
	assert.ErrorIs(t, err, keystore.ErrNoSuchKey)
}

func TestStore_GetKey_NotFound(t *testing.T) {
	ctx := context.Background()

	storeDir := t.TempDir()
	store, err := keystore.OpenStore(storeDir)
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck // test code

	_, err = store.GetKey(ctx, keystore.KeyID("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"))
	assert.ErrorIs(t, err, keystore.ErrNoSuchKey)
}

func TestStore_GetKey_InvalidKeyID(t *testing.T) {
	ctx := context.Background()

	storeDir := t.TempDir()
	store, err := keystore.OpenStore(storeDir)
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck // test code

	_, err = store.GetKey(ctx, keystore.KeyID("invalid"))
	assert.Error(t, err)
}

func TestStore_UnlinkKey_NotFound(t *testing.T) {
	ctx := context.Background()

	storeDir := t.TempDir()
	store, err := keystore.OpenStore(storeDir)
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck // test code

	err = store.UnlinkKey(ctx, keystore.KeyID("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"))
	assert.ErrorIs(t, err, keystore.ErrNoSuchKey)
}

func TestStore_UnlinkKey_InvalidKeyID(t *testing.T) {
	ctx := context.Background()

	storeDir := t.TempDir()
	store, err := keystore.OpenStore(storeDir)
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck // test code

	err = store.UnlinkKey(ctx, keystore.KeyID("invalid"))
	assert.Error(t, err)
}

func TestStore_GetSigner(t *testing.T) {
	ctx := context.Background()

	storeDir := t.TempDir()
	store, err := keystore.OpenStore(storeDir)
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck // test code

	key := generateTestKey(t)

	keyID, err := store.AddKey(ctx, key)
	require.NoError(t, err)

	signer, err := store.GetSigner(ctx, keyID)
	require.NoError(t, err)
	require.NotNil(t, signer)

	// Verify the signer works.
	msg := []byte("store signer test")
	sig, err := signer.Sign(rand.Reader, msg, crypto.Hash(0))
	require.NoError(t, err)

	pubKey, ok := signer.Public().(ed25519.PublicKey)
	require.True(t, ok, "expected ed25519.PublicKey")
	assert.True(t, ed25519.Verify(pubKey, msg, sig))
}

func TestStore_GetSigner_NotFound(t *testing.T) {
	ctx := context.Background()

	storeDir := t.TempDir()
	store, err := keystore.OpenStore(storeDir)
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck // test code

	_, err = store.GetSigner(ctx, keystore.KeyID("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"))
	assert.ErrorIs(t, err, keystore.ErrNoSuchKey)
}

func TestStore_MultipleKeys(t *testing.T) {
	ctx := context.Background()

	storeDir := t.TempDir()
	store, err := keystore.OpenStore(storeDir)
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck // test code

	// Add several keys.
	var keyIDs []keystore.KeyID //nolint:prealloc // test code
	for range 5 {
		key := generateTestKey(t)

		keyID, err := store.AddKey(ctx, key)
		require.NoError(t, err)
		keyIDs = append(keyIDs, keyID)
	}

	// All keys should be retrievable.
	for _, keyID := range keyIDs {
		retrieved, err := store.GetKey(ctx, keyID)
		require.NoError(t, err)

		retrievedID, err := retrieved.ID()
		require.NoError(t, err)
		assert.Equal(t, keyID, retrievedID)
	}

	// Remove only one key.
	err = store.UnlinkKey(ctx, keyIDs[2])
	require.NoError(t, err)

	// The removed key should be gone.
	_, err = store.GetKey(ctx, keyIDs[2])
	require.ErrorIs(t, err, keystore.ErrNoSuchKey)

	// The rest should still work.
	for i, keyID := range keyIDs {
		if i == 2 {
			continue
		}
		_, err := store.GetKey(ctx, keyID)
		assert.NoError(t, err)
	}
}

func TestStore_GenerateKey(t *testing.T) {
	ctx := context.Background()

	storeDir := t.TempDir()
	store, err := keystore.OpenStore(storeDir)
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck // test code

	keyID, key, err := store.GenerateKey(ctx, testDriverName)
	require.NoError(t, err)
	assert.True(t, keyID.IsValid())
	require.NotNil(t, key)
	assert.Equal(t, testDriverName, key.Driver)
	assert.Equal(t, keystore.KeyTypeEd25519, key.KeyType())

	// The returned key ID should match the key's own ID.
	gotID, err := key.ID()
	require.NoError(t, err)
	assert.Equal(t, keyID, gotID)

	// The key should be retrievable from the store.
	retrieved, err := store.GetKey(ctx, keyID)
	require.NoError(t, err)
	retrievedID, err := retrieved.ID()
	require.NoError(t, err)
	assert.Equal(t, keyID, retrievedID)
	assert.Equal(t, key.Driver, retrieved.Driver)
	assert.Equal(t, key.KeyType(), retrieved.KeyType())

	// The generated key should produce a working signer.
	signer, err := key.GetSigner(ctx)
	require.NoError(t, err)
	msg := []byte("generate key test")
	sig, err := signer.Sign(rand.Reader, msg, crypto.Hash(0))
	require.NoError(t, err)

	pubKey, ok := signer.Public().(ed25519.PublicKey)
	require.True(t, ok, "expected ed25519.PublicKey")
	assert.True(t, ed25519.Verify(pubKey, msg, sig))
}

func TestStore_GenerateKey_UnknownDriver(t *testing.T) {
	ctx := context.Background()

	storeDir := t.TempDir()
	store, err := keystore.OpenStore(storeDir)
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck // test code

	keyID, key, err := store.GenerateKey(ctx, "nonexistent-driver")
	assert.Error(t, err) //nolint:testifylint // assert is fine for error path checks
	assert.Equal(t, keystore.BadKeyID, keyID)
	assert.Nil(t, key)
	assert.Contains(t, err.Error(), "nonexistent-driver")
}

func TestStore_GenerateKey_Multiple(t *testing.T) {
	ctx := context.Background()

	storeDir := t.TempDir()
	store, err := keystore.OpenStore(storeDir)
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck // test code

	// Generate several keys via GenerateKey.
	var keyIDs []keystore.KeyID //nolint:prealloc // test code
	for range 3 {
		keyID, _, err := store.GenerateKey(ctx, testDriverName)
		require.NoError(t, err)
		keyIDs = append(keyIDs, keyID)
	}

	// All keys should be distinct and retrievable.
	seen := make(map[keystore.KeyID]struct{})
	for _, keyID := range keyIDs {
		assert.NotContains(t, seen, keyID, "duplicate key ID generated")
		seen[keyID] = struct{}{}

		_, err := store.GetKey(ctx, keyID)
		assert.NoError(t, err)
	}
}

func TestStore_RotateKey(t *testing.T) {
	ctx := context.Background()

	storeDir := t.TempDir()
	store, err := keystore.OpenStore(storeDir)
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck // test code

	// Generate an initial key to rotate.
	oldKeyID, oldKey, err := store.GenerateKey(ctx, testDriverName)
	require.NoError(t, err)

	// Rotate the key.
	newKeyID, newKey, err := store.RotateKey(ctx, oldKeyID)
	require.NoError(t, err)
	assert.True(t, newKeyID.IsValid())
	require.NotNil(t, newKey)
	assert.Equal(t, testDriverName, newKey.Driver)
	assert.Equal(t, oldKey.KeyType(), newKey.KeyType())

	// The new key should have a different ID.
	assert.NotEqual(t, oldKeyID, newKeyID)

	// The returned key ID should match the key's own ID.
	gotID, err := newKey.ID()
	require.NoError(t, err)
	assert.Equal(t, newKeyID, gotID)

	// The new key should be retrievable from the store.
	retrieved, err := store.GetKey(ctx, newKeyID)
	require.NoError(t, err)
	retrievedID, err := retrieved.ID()
	require.NoError(t, err)
	assert.Equal(t, newKeyID, retrievedID)
	assert.Equal(t, newKey.Driver, retrieved.Driver)
	assert.Equal(t, newKey.KeyType(), retrieved.KeyType())

	// The old key should still exist in the store.
	_, err = store.GetKey(ctx, oldKeyID)
	require.NoError(t, err)

	// The rotated key should produce a working signer.
	signer, err := newKey.GetSigner(ctx)
	require.NoError(t, err)
	msg := []byte("rotate key test")
	sig, err := signer.Sign(rand.Reader, msg, crypto.Hash(0))
	require.NoError(t, err)

	pubKey, ok := signer.Public().(ed25519.PublicKey)
	require.True(t, ok, "expected ed25519.PublicKey")
	assert.True(t, ed25519.Verify(pubKey, msg, sig))
}

func TestStore_RotateKey_NotFound(t *testing.T) {
	ctx := context.Background()

	storeDir := t.TempDir()
	store, err := keystore.OpenStore(storeDir)
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck // test code

	keyID, key, err := store.RotateKey(ctx, keystore.KeyID("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"))
	assert.ErrorIs(t, err, keystore.ErrNoSuchKey) //nolint:testifylint // assert is fine for error path checks
	assert.Equal(t, keystore.BadKeyID, keyID)
	assert.Nil(t, key)
}

func TestStore_RotateKey_InvalidKeyID(t *testing.T) {
	ctx := context.Background()

	storeDir := t.TempDir()
	store, err := keystore.OpenStore(storeDir)
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck // test code

	keyID, key, err := store.RotateKey(ctx, keystore.KeyID("invalid"))
	assert.Error(t, err) //nolint:testifylint // assert is fine for error path checks
	assert.Equal(t, keystore.BadKeyID, keyID)
	assert.Nil(t, key)
}

func TestStore_RotateKey_BadDriver(t *testing.T) {
	ctx := context.Background()

	storeDir := t.TempDir()
	store, err := keystore.OpenStore(storeDir)
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck // test code

	// Add a key with a clobbered driver name.
	key := generateTestKey(t)
	keyID, err := store.AddKey(ctx, key)
	require.NoError(t, err)

	// Clobber the driver in the store by re-adding with a bad driver.
	// We can't modify the stored key directly, so instead we create a key
	// with a bad driver, add it, and try to rotate it.
	badKey := generateTestKey(t)
	badKey.Driver = "doesnotexist"
	badKeyID, err := store.AddKey(ctx, badKey)
	require.NoError(t, err)
	_ = keyID // keep linter happy

	rotatedID, rotatedKey, err := store.RotateKey(ctx, badKeyID)
	assert.Error(t, err) //nolint:testifylint // assert is fine for error path checks
	assert.Equal(t, keystore.BadKeyID, rotatedID)
	assert.Nil(t, rotatedKey)
	assert.Contains(t, err.Error(), "doesnotexist")
}

func TestStore_AddKey_Duplicate(t *testing.T) {
	ctx := context.Background()

	storeDir := t.TempDir()
	store, err := keystore.OpenStore(storeDir)
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck // test code

	key := generateTestKey(t)

	_, err = store.AddKey(ctx, key)
	require.NoError(t, err)

	// Adding the same key again should fail.
	_, err = store.AddKey(ctx, key)
	assert.ErrorIs(t, err, keystore.ErrKeyAlreadyExists)
}

func TestStoreFromFd(t *testing.T) {
	ctx := context.Background()

	storeDir := t.TempDir()

	dirFile, err := os.OpenFile(storeDir, unix.O_DIRECTORY, 0)
	require.NoError(t, err)
	defer dirFile.Close() //nolint:errcheck

	store, err := keystore.StoreFromFd(dirFile)
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck // test code

	key := generateTestKey(t)

	keyID, err := store.AddKey(ctx, key)
	require.NoError(t, err)

	retrieved, err := store.GetKey(ctx, keyID)
	require.NoError(t, err)

	retrievedID, err := retrieved.ID()
	require.NoError(t, err)
	assert.Equal(t, keyID, retrievedID)
}

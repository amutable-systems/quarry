//go:build insecure

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package keystore_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.amutable.dev/quarry/internal/keystore"
	_ "go.amutable.dev/quarry/internal/keystore/insecure"
)

func TestGetDriver_Insecure(t *testing.T) {
	driver, ok := keystore.GetDriver("insecure")
	assert.True(t, ok)
	assert.NotNil(t, driver)
	assert.Equal(t, "insecure", driver.Name())
}

func TestInsecure_Store_AddGetUnlinkKey(t *testing.T) {
	ctx := context.Background()

	storeDir := t.TempDir()
	store, err := keystore.OpenStore(storeDir)
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck // test code

	driver, ok := keystore.GetDriver("insecure")
	require.True(t, ok)

	key, err := driver.GenerateKey(ctx)
	require.NoError(t, err)

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

func TestInsecure_Store_GetSigner(t *testing.T) {
	ctx := context.Background()

	storeDir := t.TempDir()
	store, err := keystore.OpenStore(storeDir)
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck // test code

	driver, ok := keystore.GetDriver("insecure")
	require.True(t, ok)

	key, err := driver.GenerateKey(ctx)
	require.NoError(t, err)

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

func TestInsecure_Store_MultipleKeys(t *testing.T) {
	ctx := context.Background()

	storeDir := t.TempDir()
	store, err := keystore.OpenStore(storeDir)
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck // test code

	driver, ok := keystore.GetDriver("insecure")
	require.True(t, ok)

	// Add several keys.
	var keyIDs []keystore.KeyID //nolint:prealloc // test code
	for range 5 {
		key, err := driver.GenerateKey(ctx)
		require.NoError(t, err)

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
	assert.ErrorIs(t, err, keystore.ErrNoSuchKey) //nolint:testifylint // assert is fine for error path checks

	// The rest should still work.
	for i, keyID := range keyIDs {
		if i == 2 {
			continue
		}
		_, err := store.GetKey(ctx, keyID)
		assert.NoError(t, err)
	}
}

func TestInsecure_StoreFromFd(t *testing.T) {
	// This is tested implicitly through OpenStore usage, but let's exercise
	// StoreFromFd directly with an open directory.
	ctx := context.Background()

	storeDir := t.TempDir()

	dirFile, err := os.OpenFile(storeDir, unix.O_DIRECTORY, 0) //nolint:forbidigo // test code
	require.NoError(t, err)
	defer dirFile.Close() //nolint:errcheck

	store, err := keystore.StoreFromFd(dirFile)
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck // test code

	driver, ok := keystore.GetDriver("insecure")
	require.True(t, ok)

	key, err := driver.GenerateKey(ctx)
	require.NoError(t, err)

	keyID, err := store.AddKey(ctx, key)
	require.NoError(t, err)

	retrieved, err := store.GetKey(ctx, keyID)
	require.NoError(t, err)

	retrievedID, err := retrieved.ID()
	require.NoError(t, err)
	assert.Equal(t, keyID, retrievedID)
}

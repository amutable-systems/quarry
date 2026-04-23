// Copyright (C) 2026 Amutable GmbH

//go:build insecure

package tufext_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/keystore"
	_ "go.amutable.dev/quarry/internal/keystore/insecure"
	"go.amutable.dev/quarry/internal/tufext"
)

// openTestStore returns a fresh insecure-backed [keystore.Store] and an
// accompanying [context.Context]. The store is closed at test teardown.
func openTestStore(t *testing.T) (context.Context, *keystore.Store) {
	t.Helper()
	ctx := context.Background()
	store, err := keystore.OpenStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	return ctx, store
}

// generateInStore generates a fresh ed25519 key via the insecure driver,
// inserts it into the given store, and returns the key along with its
// stringified [keystore.KeyID].
func generateInStore(ctx context.Context, t *testing.T, store *keystore.Store) (*keystore.GenericKey, string) {
	t.Helper()
	_, key, err := store.GenerateKey(ctx, "insecure")
	require.NoError(t, err)
	id, err := key.ID()
	require.NoError(t, err)
	return key, string(id)
}

// ----- RootType ----------------------------------------------------------

func TestFillRoleKeys_Root_AllKeysPresent(t *testing.T) {
	ctx, store := openTestStore(t)

	rootKey, rootID := generateInStore(ctx, t, store)
	targetsKey, targetsID := generateInStore(ctx, t, store)

	root := tufmetadata.RootType{
		Keys: map[string]*tufmetadata.Key{
			rootID:    &rootKey.Public,
			targetsID: &targetsKey.Public,
		},
		Roles: map[string]*tufmetadata.Role{
			tufmetadata.ROOT:    {KeyIDs: []string{rootID}, Threshold: 1},
			tufmetadata.TARGETS: {KeyIDs: []string{targetsID}, Threshold: 1},
		},
	}

	require.NoError(t, tufext.FillRoleKeys(ctx, store, &root))

	// Both referenced keys remain, pointer identity preserved (no
	// unnecessary store round-trip).
	require.Len(t, root.Keys, 2)
	assert.Same(t, &rootKey.Public, root.Keys[rootID])
	assert.Same(t, &targetsKey.Public, root.Keys[targetsID])
}

func TestFillRoleKeys_Root_FillsMissingFromStore(t *testing.T) {
	ctx, store := openTestStore(t)

	rootKey, rootID := generateInStore(ctx, t, store)
	_, targetsID := generateInStore(ctx, t, store)

	// targets key is referenced but NOT pre-populated in the map.
	root := tufmetadata.RootType{
		Keys: map[string]*tufmetadata.Key{
			rootID: &rootKey.Public,
		},
		Roles: map[string]*tufmetadata.Role{
			tufmetadata.ROOT:    {KeyIDs: []string{rootID}, Threshold: 1},
			tufmetadata.TARGETS: {KeyIDs: []string{targetsID}, Threshold: 1},
		},
	}

	require.NoError(t, tufext.FillRoleKeys(ctx, store, &root))

	require.Len(t, root.Keys, 2)
	// rootKey was already there -- identity preserved.
	assert.Same(t, &rootKey.Public, root.Keys[rootID])
	// targetsKey was filled in from the store; fetching it from the key
	// round-trips to the same [keystore.KeyID].
	require.Contains(t, root.Keys, targetsID)
	gotTargetsID, err := root.Keys[targetsID].ID()
	require.NoError(t, err)
	assert.Equal(t, targetsID, gotTargetsID)
}

func TestFillRoleKeys_Root_FillsAllFromStore(t *testing.T) {
	ctx, store := openTestStore(t)

	_, rootID := generateInStore(ctx, t, store)
	_, targetsID := generateInStore(ctx, t, store)

	root := tufmetadata.RootType{
		// Start with an empty key map; every referenced keyID must come
		// from the store.
		Keys: map[string]*tufmetadata.Key{},
		Roles: map[string]*tufmetadata.Role{
			tufmetadata.ROOT:    {KeyIDs: []string{rootID}, Threshold: 1},
			tufmetadata.TARGETS: {KeyIDs: []string{targetsID}, Threshold: 1},
		},
	}

	require.NoError(t, tufext.FillRoleKeys(ctx, store, &root))

	require.Len(t, root.Keys, 2)
	assert.Contains(t, root.Keys, rootID)
	assert.Contains(t, root.Keys, targetsID)
}

func TestFillRoleKeys_Root_GCsUnreferencedKeys(t *testing.T) {
	ctx, store := openTestStore(t)

	rootKey, rootID := generateInStore(ctx, t, store)
	orphanKey, orphanID := generateInStore(ctx, t, store)

	// orphanID is present in the map but referenced by no role -- it must
	// be pruned, mirroring GCRoleKeys behavior.
	root := tufmetadata.RootType{
		Keys: map[string]*tufmetadata.Key{
			rootID:   &rootKey.Public,
			orphanID: &orphanKey.Public,
		},
		Roles: map[string]*tufmetadata.Role{
			tufmetadata.ROOT: {KeyIDs: []string{rootID}, Threshold: 1},
		},
	}

	require.NoError(t, tufext.FillRoleKeys(ctx, store, &root))

	require.Len(t, root.Keys, 1)
	assert.Contains(t, root.Keys, rootID)
	assert.NotContains(t, root.Keys, orphanID)
}

func TestFillRoleKeys_Root_SharedKeyAcrossRoles(t *testing.T) {
	ctx, store := openTestStore(t)

	_, sharedID := generateInStore(ctx, t, store)

	root := tufmetadata.RootType{
		Keys: map[string]*tufmetadata.Key{},
		Roles: map[string]*tufmetadata.Role{
			tufmetadata.ROOT:     {KeyIDs: []string{sharedID}, Threshold: 1},
			tufmetadata.TARGETS:  {KeyIDs: []string{sharedID}, Threshold: 1},
			tufmetadata.SNAPSHOT: {KeyIDs: []string{sharedID}, Threshold: 1},
		},
	}

	require.NoError(t, tufext.FillRoleKeys(ctx, store, &root))

	// A single deduplicated entry even though three roles reference it,
	// and the stored key round-trips to the same [keystore.KeyID].
	require.Len(t, root.Keys, 1)
	require.Contains(t, root.Keys, sharedID)
	gotID, err := root.Keys[sharedID].ID()
	require.NoError(t, err)
	assert.Equal(t, sharedID, gotID)
}

func TestFillRoleKeys_Root_MissingFromStore(t *testing.T) {
	ctx, store := openTestStore(t)

	missingID := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	root := tufmetadata.RootType{
		Keys: map[string]*tufmetadata.Key{},
		Roles: map[string]*tufmetadata.Role{
			tufmetadata.TARGETS: {KeyIDs: []string{missingID}, Threshold: 1},
		},
	}

	err := tufext.FillRoleKeys(ctx, store, &root)
	require.ErrorIs(t, err, keystore.ErrNoSuchKey)
	// Error message should pin down which role and keyID tripped it up.
	assert.Contains(t, err.Error(), missingID)
	assert.Contains(t, err.Error(), tufmetadata.TARGETS)
}

func TestFillRoleKeys_Root_InvalidKeyID(t *testing.T) {
	ctx, store := openTestStore(t)

	root := tufmetadata.RootType{
		Keys: map[string]*tufmetadata.Key{},
		Roles: map[string]*tufmetadata.Role{
			tufmetadata.ROOT: {KeyIDs: []string{"not-a-valid-keyid"}, Threshold: 1},
		},
	}

	err := tufext.FillRoleKeys(ctx, store, &root)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not-a-valid-keyid")
}

func TestFillRoleKeys_Root_EmptyRoles(t *testing.T) {
	ctx, store := openTestStore(t)

	// A RootType with no role assignments should be a no-op that also
	// purges any stray keys from the top-level key map.
	_, stray := generateInStore(ctx, t, store)
	root := tufmetadata.RootType{
		Keys: map[string]*tufmetadata.Key{
			stray: {},
		},
		Roles: map[string]*tufmetadata.Role{},
	}

	require.NoError(t, tufext.FillRoleKeys(ctx, store, &root))
	assert.Empty(t, root.Keys)
}

// ----- TargetsType -------------------------------------------------------

func TestFillRoleKeys_Targets_NilDelegations(t *testing.T) {
	ctx, store := openTestStore(t)

	targets := tufmetadata.TargetsType{
		Type:        tufmetadata.TARGETS,
		SpecVersion: tufmetadata.SPECIFICATION_VERSION,
		Version:     3,
		Targets:     map[string]*tufmetadata.TargetFiles{"a.bin": {Length: 1}},
	}

	require.NoError(t, tufext.FillRoleKeys(ctx, store, &targets))

	// No mutation -- delegations still nil, other fields untouched.
	assert.Nil(t, targets.Delegations)
	assert.Equal(t, int64(3), targets.Version)
	assert.Len(t, targets.Targets, 1)
}

func TestFillRoleKeys_Targets_SuccinctRolesUnsupported(t *testing.T) {
	ctx, store := openTestStore(t)

	key, keyID := generateInStore(ctx, t, store)
	targets := tufmetadata.TargetsType{
		Delegations: &tufmetadata.Delegations{
			Keys: map[string]*tufmetadata.Key{keyID: &key.Public},
			SuccinctRoles: &tufmetadata.SuccinctRoles{
				KeyIDs: []string{keyID}, Threshold: 1, BitLength: 4, NamePrefix: "bin",
			},
		},
	}

	err := tufext.FillRoleKeys(ctx, store, &targets)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "succinct roles")
	// Keys map untouched on error.
	assert.Same(t, &key.Public, targets.Delegations.Keys[keyID])
}

func TestFillRoleKeys_Targets_FillsFromStore(t *testing.T) {
	ctx, store := openTestStore(t)

	keptKey, keptID := generateInStore(ctx, t, store)
	_, missingID := generateInStore(ctx, t, store)

	targets := tufmetadata.TargetsType{
		Delegations: &tufmetadata.Delegations{
			Keys: map[string]*tufmetadata.Key{
				keptID: &keptKey.Public,
			},
			Roles: []tufmetadata.DelegatedRole{
				{Name: "alpha", KeyIDs: []string{keptID}, Threshold: 1},
				{Name: "beta", KeyIDs: []string{missingID}, Threshold: 1},
			},
		},
	}

	require.NoError(t, tufext.FillRoleKeys(ctx, store, &targets))

	require.Len(t, targets.Delegations.Keys, 2)
	assert.Same(t, &keptKey.Public, targets.Delegations.Keys[keptID])
	require.Contains(t, targets.Delegations.Keys, missingID)
	gotMissingID, err := targets.Delegations.Keys[missingID].ID()
	require.NoError(t, err)
	assert.Equal(t, missingID, gotMissingID)
}

func TestFillRoleKeys_Targets_MissingFromStore(t *testing.T) {
	ctx, store := openTestStore(t)

	missingID := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	targets := tufmetadata.TargetsType{
		Delegations: &tufmetadata.Delegations{
			Keys: map[string]*tufmetadata.Key{},
			Roles: []tufmetadata.DelegatedRole{
				{Name: "needs-a-key", KeyIDs: []string{missingID}, Threshold: 1},
			},
		},
	}

	err := tufext.FillRoleKeys(ctx, store, &targets)
	require.ErrorIs(t, err, keystore.ErrNoSuchKey)
	assert.Contains(t, err.Error(), missingID)
	assert.Contains(t, err.Error(), "needs-a-key")
}

func TestFillRoleKeys_Targets_GCsUnreferencedKeys(t *testing.T) {
	ctx, store := openTestStore(t)

	keptKey, keptID := generateInStore(ctx, t, store)
	orphanKey, orphanID := generateInStore(ctx, t, store)

	targets := tufmetadata.TargetsType{
		Delegations: &tufmetadata.Delegations{
			Keys: map[string]*tufmetadata.Key{
				keptID:   &keptKey.Public,
				orphanID: &orphanKey.Public,
			},
			Roles: []tufmetadata.DelegatedRole{
				{Name: "alpha", KeyIDs: []string{keptID}, Threshold: 1},
			},
		},
	}

	require.NoError(t, tufext.FillRoleKeys(ctx, store, &targets))

	require.Len(t, targets.Delegations.Keys, 1)
	assert.Same(t, &keptKey.Public, targets.Delegations.Keys[keptID])
	assert.NotContains(t, targets.Delegations.Keys, orphanID)
}

// When the store lookup errors for a reason other than the key being
// missing (here: the store has been closed), the error must surface
// distinctly and the caller's Keys map must be left untouched so a retry
// is safe.
func TestFillRoleKeys_Targets_StoreClosed(t *testing.T) {
	ctx := context.Background()
	store, err := keystore.OpenStore(t.TempDir())
	require.NoError(t, err)

	existingKey, existingID := generateInStore(ctx, t, store)
	_, missingID := generateInStore(ctx, t, store)

	targets := tufmetadata.TargetsType{
		Delegations: &tufmetadata.Delegations{
			Keys: map[string]*tufmetadata.Key{
				existingID: &existingKey.Public,
			},
			Roles: []tufmetadata.DelegatedRole{
				{Name: "alpha", KeyIDs: []string{existingID}, Threshold: 1},
				// `missingID` is valid but not in the local map; fetching
				// it from the (closed) store will fail.
				{Name: "beta", KeyIDs: []string{missingID}, Threshold: 1},
			},
		},
	}

	require.NoError(t, store.Close())

	err = tufext.FillRoleKeys(ctx, store, &targets)
	require.Error(t, err)
	require.NotErrorIs(t, err, keystore.ErrNoSuchKey,
		"closed-store errors must not masquerade as missing-key errors")

	// FillRoleKeys only assigns back to *keySlot after the fill loop
	// completes -- so on error the map is whatever the caller passed in.
	assert.Len(t, targets.Delegations.Keys, 1)
	assert.Same(t, &existingKey.Public, targets.Delegations.Keys[existingID])
}

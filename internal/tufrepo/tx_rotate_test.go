//go:build insecure

// Copyright (C) 2026 Amutable GmbH

package tufrepo_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/keystore"
	"go.amutable.dev/quarry/internal/tufrepo"
)

// ----- ReplaceKeys -------------------------------------------------------

func TestReplaceKeys_ReplacesCoreRoleKey(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	newKey := generateInsecureKey(ctx, t, bs.store)
	newKeyID, err := newKey.ID()
	require.NoError(t, err)

	op, err := tufrepo.ReplaceKeys(tufmetadata.TIMESTAMP,
		map[keystore.KeyID]*keystore.PublicKey{newKeyID: &newKey.Public},
		tufmetadata.Role{KeyIDs: []string{string(newKeyID)}, Threshold: 1},
	)
	require.NoError(t, err)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)
	require.NoError(t, tx.Apply(ctx, op))

	root, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{string(newKeyID)}, root.Signed.Roles[tufmetadata.TIMESTAMP].KeyIDs)
	// GCRoleKeys should have purged the old timestamp key since it's no
	// longer referenced by any role.
	oldID, err := bs.timestampKey.ID()
	require.NoError(t, err)
	assert.NotContains(t, root.Signed.Keys, string(oldID))
	assert.Contains(t, root.Signed.Keys, string(newKeyID))

	// A subsequent Sign should now produce a fresh timestamp signed with
	// the new key.
	_, err = tx.Sign(ctx, bs.store)
	require.NoError(t, err)

	ts, err := tx.TimestampRoleData(ctx)
	require.NoError(t, err)
	finalRoot, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	require.NoError(t, finalRoot.VerifyDelegate(tufmetadata.TIMESTAMP, ts))
}

func TestReplaceKeys_MissingKeyErrors(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	// Declare a keyID but do not include it in the keys map.
	op, err := tufrepo.ReplaceKeys(tufmetadata.TIMESTAMP,
		map[keystore.KeyID]*keystore.PublicKey{}, // empty
		tufmetadata.Role{KeyIDs: []string{"0000000000000000000000000000000000000000000000000000000000000000"}, Threshold: 1},
	)
	require.NoError(t, err)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	err = tx.Apply(ctx, op)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "public key not available")
}

func TestReplaceKeys_DelegatedRoleNotImplemented(t *testing.T) {
	_, err := tufrepo.ReplaceKeys("my-delegation",
		map[keystore.KeyID]*keystore.PublicKey{},
		tufmetadata.Role{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delegated role key replacement is not implemented")
}

// ----- RotateRoleKeys ----------------------------------------------------

func TestRotateRoleKeys_RotatesCoreRoleKeys(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	oldID, err := bs.timestampKey.ID()
	require.NoError(t, err)

	op, err := tufrepo.RotateRoleKeys(tufmetadata.TIMESTAMP, bs.store)
	require.NoError(t, err)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)
	require.NoError(t, tx.Apply(ctx, op))

	root, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	newKeyIDs := root.Signed.Roles[tufmetadata.TIMESTAMP].KeyIDs
	require.Len(t, newKeyIDs, 1)
	assert.NotEqual(t, string(oldID), newKeyIDs[0], "timestamp key should have been rotated to a new id")

	// The new key must now be in both the store and the root key map.
	assert.Contains(t, root.Signed.Keys, newKeyIDs[0])
	_, err = bs.store.GetKey(ctx, keystore.KeyID(newKeyIDs[0]))
	require.NoError(t, err)

	// The old key should have been GC'd from root.Signed.Keys since no
	// other role references it. Note: ReplaceKeys explicitly unlinks; this
	// method does not unlink the old key from the store (by design -- the
	// caller is responsible).
	assert.NotContains(t, root.Signed.Keys, string(oldID))
}

// rotateRoleKeys passes IsCoreRole at the API boundary but can still fail
// internally if a core role entry has been stripped from the root between
// TxnStart and the rotation call.
func TestRotateRoleKeys_UnknownRole(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	op, err := tufrepo.RotateRoleKeys(tufmetadata.TIMESTAMP, bs.store)
	require.NoError(t, err)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	require.NoError(t, tx.Apply(ctx, tufrepo.NewTxnOp("drop-timestamp-role",
		func(ctx context.Context, tx *tufrepo.Transaction) error {
			root, err := tx.RootRoleData(ctx)
			if err != nil {
				return err
			}
			delete(root.Signed.Roles, tufmetadata.TIMESTAMP)
			return tx.UpdateRoleData(tufmetadata.ROOT, root)
		})))

	err = tx.Apply(ctx, op)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown role")
}

func TestRotateRoleKeys_DelegatedRoleNotImplemented(t *testing.T) {
	bs := bootstrapRepo(t)
	_, err := tufrepo.RotateRoleKeys("some-delegation", bs.store)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delegated role key rotation is not implemented")
}

// When a key referenced by a core role is no longer in the keystore,
// rotateRoleKeys falls back to generating a brand new key instead of
// rotating the missing one.
func TestRotateRoleKeys_GeneratesWhenOldKeyMissing(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	oldID, err := bs.timestampKey.ID()
	require.NoError(t, err)
	require.NoError(t, bs.store.UnlinkKey(ctx, oldID))

	op, err := tufrepo.RotateRoleKeys(tufmetadata.TIMESTAMP, bs.store)
	require.NoError(t, err)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)
	require.NoError(t, tx.Apply(ctx, op))

	root, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	newKeyIDs := root.Signed.Roles[tufmetadata.TIMESTAMP].KeyIDs
	require.Len(t, newKeyIDs, 1)
	assert.NotEqual(t, string(oldID), newKeyIDs[0])
	_, err = bs.store.GetKey(ctx, keystore.KeyID(newKeyIDs[0]))
	assert.NoError(t, err)
}

// Rotating multiple timestamp keys (higher threshold) should produce exactly
// one fresh key per old keyID.
func TestRotateRoleKeys_MultipleKeys(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	// Upgrade TIMESTAMP's role to use two keys with threshold 2.
	extraKey := generateInsecureKey(ctx, t, bs.store)
	extraKeyID, err := extraKey.ID()
	require.NoError(t, err)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)
	require.NoError(t, tx.Apply(ctx, tufrepo.NewTxnOp("add-timestamp-key",
		func(ctx context.Context, tx *tufrepo.Transaction) error {
			root, err := tx.RootRoleData(ctx)
			if err != nil {
				return err
			}
			role := root.Signed.Roles[tufmetadata.TIMESTAMP]
			role.KeyIDs = append(role.KeyIDs, string(extraKeyID))
			role.Threshold = 2
			root.Signed.Keys[string(extraKeyID)] = &extraKey.Public
			return tx.UpdateRoleData(tufmetadata.ROOT, root)
		})))

	oldIDs := append([]string(nil), mustRootRoleKeyIDs(ctx, t, tx, tufmetadata.TIMESTAMP)...)
	require.Len(t, oldIDs, 2)

	rotateOp, err := tufrepo.RotateRoleKeys(tufmetadata.TIMESTAMP, bs.store)
	require.NoError(t, err)
	require.NoError(t, tx.Apply(ctx, rotateOp))

	newIDs := mustRootRoleKeyIDs(ctx, t, tx, tufmetadata.TIMESTAMP)
	require.Len(t, newIDs, 2)
	for _, id := range newIDs {
		assert.NotContains(t, oldIDs, id, "rotation produced a stale key id")
		_, err := bs.store.GetKey(ctx, keystore.KeyID(id))
		require.NoError(t, err, "rotated key should be in the store")
	}

	// Threshold must be preserved across rotation.
	root, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, root.Signed.Roles[tufmetadata.TIMESTAMP].Threshold)
}

// RotateRoleKeys accepts variadic `...any` options but only routes
// [keyopts.RotateOption] and [keyopts.GenerateOption] values. Any other type
// must surface as an "unsupported option type" error at Apply time, with no
// side-effects on the keystore.
func TestRotateRoleKeys_UnsupportedOption(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	keysBefore, err := countKeystoreEntries(bs.storeDir)
	require.NoError(t, err)

	op, err := tufrepo.RotateRoleKeys(tufmetadata.TIMESTAMP, bs.store, "not-an-option")
	require.NoError(t, err)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	err = tx.Apply(ctx, op)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported option type")

	// Option routing must happen before any key generation.
	keysAfter, err := countKeystoreEntries(bs.storeDir)
	require.NoError(t, err)
	assert.Equal(t, keysBefore, keysAfter, "unsupported-option failure must not generate keys")
}

// If rotateRoleKeys generates new keys but a later step (here:
// [tufext.GCRoleKeys]) fails, the deferred cleanup must unlink those new
// keys from the store so they don't accumulate. We force GC to fail by
// pre-injecting a dangling keyID into a different role before rotation.
func TestRotateRoleKeys_CleansUpGeneratedKeysOnError(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	keysBefore, err := countKeystoreEntries(bs.storeDir)
	require.NoError(t, err)

	op, err := tufrepo.RotateRoleKeys(tufmetadata.TIMESTAMP, bs.store)
	require.NoError(t, err)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	// Inject a dangling keyID into another role so [tufext.GCRoleKeys] in
	// rotateRoleKeys trips up after the new keys have been generated.
	require.NoError(t, tx.Apply(ctx, tufrepo.NewTxnOp("corrupt-root-keys",
		func(ctx context.Context, tx *tufrepo.Transaction) error {
			root, err := tx.RootRoleData(ctx)
			if err != nil {
				return err
			}
			dangling := "0000000000000000000000000000000000000000000000000000000000000000"
			root.Signed.Roles[tufmetadata.SNAPSHOT].KeyIDs = append(
				root.Signed.Roles[tufmetadata.SNAPSHOT].KeyIDs, dangling,
			)
			return tx.UpdateRoleData(tufmetadata.ROOT, root)
		})))

	err = tx.Apply(ctx, op)
	require.Error(t, err)

	keysAfter, err := countKeystoreEntries(bs.storeDir)
	require.NoError(t, err)
	assert.Equal(t, keysBefore, keysAfter,
		"generated keys must be unlinked when rotation fails")

	// Cardinality-preservation alone isn't enough: a buggy defer could
	// unlink one of the bootstrap keys instead of the newly-generated one
	// and still pass. Verify every bootstrap key is still retrievable.
	for _, key := range []*keystore.GenericKey{bs.rootKey, bs.targetsKey, bs.snapshotKey, bs.timestampKey} {
		id, err := key.ID()
		require.NoError(t, err)
		_, err = bs.store.GetKey(ctx, id)
		assert.NoErrorf(t, err, "bootstrap key %s must survive rotation rollback", id)
	}
}

// Rotating keys on an already-failed transaction should surface the root cause.
func TestRotateRoleKeys_FailedTransaction(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	// Poison the transaction.
	boom := errors.New("poison")
	_ = tx.Apply(ctx, tufrepo.NewTxnOp("poison",
		func(context.Context, *tufrepo.Transaction) error { return boom }))

	op, err := tufrepo.RotateRoleKeys(tufmetadata.TIMESTAMP, bs.store)
	require.NoError(t, err)

	err = tx.Apply(ctx, op)
	require.ErrorIs(t, err, boom)
}

// ----- end-to-end: rotate + sign + commit --------------------------------

func TestRotateRoleKeys_EndToEnd_CommitsValidTimestamp(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	op, err := tufrepo.RotateRoleKeys(tufmetadata.TIMESTAMP, bs.store)
	require.NoError(t, err)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)
	require.NoError(t, tx.Apply(ctx, op))

	_, err = tx.Sign(ctx, bs.store)
	require.NoError(t, err)

	_, err = bs.repo.TxnCommit(ctx, tx)
	require.NoError(t, err)

	// Re-open the repo -- the live state must verify with go-tuf's
	// VerifyDelegate on each top-level role.
	tx2, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	root, err := tx2.RootRoleData(ctx)
	require.NoError(t, err)
	assert.Greater(t, root.Signed.Version, int64(1))

	ts, err := tx2.TimestampRoleData(ctx)
	require.NoError(t, err)
	require.NoError(t, root.VerifyDelegate(tufmetadata.TIMESTAMP, ts))

	snap, err := tx2.SnapshotRoleData(ctx)
	require.NoError(t, err)
	require.NoError(t, root.VerifyDelegate(tufmetadata.SNAPSHOT, snap))

	targets, err := tx2.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	require.NoError(t, root.VerifyDelegate(tufmetadata.TARGETS, targets))
}

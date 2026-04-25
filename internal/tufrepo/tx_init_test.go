//go:build insecure

// Copyright (C) 2026 Amutable GmbH

package tufrepo_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/tufext"
	"go.amutable.dev/quarry/internal/tufrepo"
	storeopts "go.amutable.dev/quarry/internal/tufrepo/opts"
)

// readBlob returns the full body of a blob, surfacing a read error ahead of
// a close error so the caller sees the root cause.
func readBlob(ctx context.Context, t *testing.T, repo *tufrepo.Repository, filename string) []byte {
	t.Helper()
	rdr, _, err := repo.GetBlob(ctx, filename)
	require.NoError(t, err)
	body, readErr := io.ReadAll(rdr)
	closeErr := rdr.Close()
	require.NoError(t, readErr)
	require.NoError(t, closeErr)
	return body
}

// TestInitTxn_PreSignedRoot_EmptyRepo is the hardhat-style happy path: the
// caller pre-signs the initial root via RootBuilder and InitTxn commits it
// to an empty repo.
func TestInitTxn_PreSignedRoot_EmptyRepo(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)
	store, _ := newTestKeystore(t)

	rootKey := generateInsecureKey(ctx, t, store)
	targetsKey := generateInsecureKey(ctx, t, store)
	snapshotKey := generateInsecureKey(ctx, t, store)
	timestampKey := generateInsecureKey(ctx, t, store)

	builder := tufext.NewRootBuilder()
	_, err := builder.AddRole(tufmetadata.ROOT, 1, rootKey.Public)
	require.NoError(t, err)
	_, err = builder.AddRole(tufmetadata.TARGETS, 1, targetsKey.Public)
	require.NoError(t, err)
	_, err = builder.AddRole(tufmetadata.SNAPSHOT, 1, snapshotKey.Public)
	require.NoError(t, err)
	_, err = builder.AddRole(tufmetadata.TIMESTAMP, 1, timestampKey.Public)
	require.NoError(t, err)

	signedRoot, builderNewKeys, err := builder.Sign(ctx, store)
	require.NoError(t, err)
	require.Empty(t, builderNewKeys,
		"RootBuilder must not autogenerate keys when all roles are pre-configured")
	// Exact count, not just non-empty: guards the later equality check from
	// passing vacuously on two empty slices.
	require.Len(t, signedRoot.Signatures, 1)

	// Clone so any in-place mutation by Sign is detectable.
	preSignedSigs := slices.Clone(signedRoot.Signatures)

	tx := tufrepo.InitTxn(signedRoot)
	signNewKeys, err := tx.Sign(ctx, store)
	require.NoError(t, err)
	assert.Empty(t, signNewKeys,
		"Sign must not autogenerate any keys for a fully-keyed InitTxn")

	postRoot, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	assert.Equal(t, preSignedSigs, postRoot.Signatures,
		"pre-signed root signatures must be preserved through Sign")
	assert.Equal(t, int64(1), postRoot.Signed.Version)

	// Capture versioned filenames for the blob-existence check below.
	txTargets, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	txSnapshot, err := tx.SnapshotRoleData(ctx)
	require.NoError(t, err)
	txTimestamp, err := tx.TimestampRoleData(ctx)
	require.NoError(t, err)

	committedTs, err := repo.TxnCommit(ctx, tx)
	require.NoError(t, err)
	require.NotNil(t, committedTs)
	assert.Greater(t, committedTs.Signed.Version, int64(1),
		"timestamp version must be bumped above the fresh-metadata default")

	// All four top-level roles must land as versioned blobs (the
	// markDirty-all-four + versioned-loop contract).
	expectedBlobs := []string{
		fmt.Sprintf("%d.%s.json", int64(1), tufmetadata.ROOT),
		fmt.Sprintf("%d.%s.json", txTargets.Signed.Version, tufmetadata.TARGETS),
		fmt.Sprintf("%d.%s.json", txSnapshot.Signed.Version, tufmetadata.SNAPSHOT),
		fmt.Sprintf("%d.%s.json", txTimestamp.Signed.Version, tufmetadata.TIMESTAMP),
		tufmetadata.TIMESTAMP + ".json",
	}
	for _, blob := range expectedBlobs {
		rdr, _, err := repo.GetBlob(ctx, blob)
		require.NoErrorf(t, err, "blob %s must exist after TxnCommit", blob)
		require.NoError(t, rdr.Close())
	}

	// TxnStart verifies the full delegation chain on the populated repo.
	tx2, err := repo.TxnStart(ctx)
	require.NoError(t, err)
	root, err := tx2.RootRoleData(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), root.Signed.Version)
}

// TestInitTxn_OpenCodedRoot_EmptyRepo hands InitTxn an unsigned hand-rolled
// root; Sign must produce the root signatures from keys in the store.
func TestInitTxn_OpenCodedRoot_EmptyRepo(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)
	store, _ := newTestKeystore(t)

	rootKey := generateInsecureKey(ctx, t, store)
	targetsKey := generateInsecureKey(ctx, t, store)
	snapshotKey := generateInsecureKey(ctx, t, store)
	timestampKey := generateInsecureKey(ctx, t, store)

	rootMeta := tufmetadata.Root(time.Now().UTC().Add(tufrepo.DefaultRootExpiry))
	require.NoError(t, rootMeta.Signed.AddKey(&rootKey.Public, tufmetadata.ROOT))
	require.NoError(t, rootMeta.Signed.AddKey(&targetsKey.Public, tufmetadata.TARGETS))
	require.NoError(t, rootMeta.Signed.AddKey(&snapshotKey.Public, tufmetadata.SNAPSHOT))
	require.NoError(t, rootMeta.Signed.AddKey(&timestampKey.Public, tufmetadata.TIMESTAMP))
	require.Empty(t, rootMeta.Signatures, "sanity: starting state must be unsigned")

	tx := tufrepo.InitTxn(rootMeta)
	signNewKeys, err := tx.Sign(ctx, store)
	require.NoError(t, err)
	assert.Empty(t, signNewKeys,
		"Sign must not autogenerate any keys for a fully-keyed InitTxn")

	// Sign signed with the caller's root key -- no rotation during InitTxn.
	postRoot, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	require.Len(t, postRoot.Signatures, 1)
	rootKeyID, err := rootKey.ID()
	require.NoError(t, err)
	assert.Equal(t, string(rootKeyID), postRoot.Signatures[0].KeyID)
	assert.Equal(t, int64(1), postRoot.Signed.Version)

	_, err = repo.TxnCommit(ctx, tx)
	require.NoError(t, err)

	// TxnStart re-verifies Sign's new root signature via the full chain.
	_, err = repo.TxnStart(ctx)
	require.NoError(t, err)
}

// TestInitTxn_FailsOnExistingRepo: InitTxn's NoClobber guards reject a
// commit against a repo that already has content.
func TestInitTxn_FailsOnExistingRepo(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	// Byte snapshot so we can verify the failed commit left it untouched.
	preTsBytes := readBlob(ctx, t, bs.repo, tufmetadata.TIMESTAMP+".json")

	newStore, _ := newTestKeystore(t)
	rootKey := generateInsecureKey(ctx, t, newStore)
	targetsKey := generateInsecureKey(ctx, t, newStore)
	snapshotKey := generateInsecureKey(ctx, t, newStore)
	timestampKey := generateInsecureKey(ctx, t, newStore)

	builder := tufext.NewRootBuilder()
	_, err := builder.AddRole(tufmetadata.ROOT, 1, rootKey.Public)
	require.NoError(t, err)
	_, err = builder.AddRole(tufmetadata.TARGETS, 1, targetsKey.Public)
	require.NoError(t, err)
	_, err = builder.AddRole(tufmetadata.SNAPSHOT, 1, snapshotKey.Public)
	require.NoError(t, err)
	_, err = builder.AddRole(tufmetadata.TIMESTAMP, 1, timestampKey.Public)
	require.NoError(t, err)
	signedRoot, _, err := builder.Sign(ctx, newStore)
	require.NoError(t, err)

	tx := tufrepo.InitTxn(signedRoot)
	_, err = tx.Sign(ctx, newStore)
	require.NoError(t, err)

	_, err = bs.repo.TxnCommit(ctx, tx)
	require.Error(t, err)
	// Only 1.root.json and timestamp.json can collide (other roles use
	// {timeVer}.json). Whichever fires first surfaces as ErrETagMismatch;
	// only the timestamp-swap path also wraps ErrClobberedTransaction.
	assert.ErrorIs(t, err, storeopts.ErrETagMismatch) //nolint:testifylint // assert is fine for error path checks

	postTsBytes := readBlob(ctx, t, bs.repo, tufmetadata.TIMESTAMP+".json")
	assert.Equal(t, preTsBytes, postTsBytes,
		"existing timestamp.json must not have been overwritten")
}

// TestInitTxn_FailsWhenOnlyTimestampExists exercises the atomic-swap
// ClobberIfMatches("") guard specifically: with only timestamp.json
// pre-existing, all versioned writes succeed, so the failure must land at
// the swap step -- the only path that wraps as ErrClobberedTransaction.
func TestInitTxn_FailsWhenOnlyTimestampExists(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)
	store, _ := newTestKeystore(t)

	// Opaque bytes -- the guard is a pure ETag check.
	preTsBytes := []byte("pre-existing-timestamp-blob")
	_, err := repo.PutBlob(ctx, tufmetadata.TIMESTAMP+".json", bytes.NewReader(preTsBytes))
	require.NoError(t, err)

	rootKey := generateInsecureKey(ctx, t, store)
	targetsKey := generateInsecureKey(ctx, t, store)
	snapshotKey := generateInsecureKey(ctx, t, store)
	timestampKey := generateInsecureKey(ctx, t, store)

	builder := tufext.NewRootBuilder()
	_, err = builder.AddRole(tufmetadata.ROOT, 1, rootKey.Public)
	require.NoError(t, err)
	_, err = builder.AddRole(tufmetadata.TARGETS, 1, targetsKey.Public)
	require.NoError(t, err)
	_, err = builder.AddRole(tufmetadata.SNAPSHOT, 1, snapshotKey.Public)
	require.NoError(t, err)
	_, err = builder.AddRole(tufmetadata.TIMESTAMP, 1, timestampKey.Public)
	require.NoError(t, err)
	signedRoot, _, err := builder.Sign(ctx, store)
	require.NoError(t, err)

	tx := tufrepo.InitTxn(signedRoot)
	_, err = tx.Sign(ctx, store)
	require.NoError(t, err)

	// Pre-staged filenames must be unlinked by the cleanup defer.
	txTargets, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	txSnapshot, err := tx.SnapshotRoleData(ctx)
	require.NoError(t, err)
	txTimestamp, err := tx.TimestampRoleData(ctx)
	require.NoError(t, err)
	wouldBeOrphans := []string{
		fmt.Sprintf("%d.%s.json", int64(1), tufmetadata.ROOT),
		fmt.Sprintf("%d.%s.json", txTargets.Signed.Version, tufmetadata.TARGETS),
		fmt.Sprintf("%d.%s.json", txSnapshot.Signed.Version, tufmetadata.SNAPSHOT),
		fmt.Sprintf("%d.%s.json", txTimestamp.Signed.Version, tufmetadata.TIMESTAMP),
	}

	_, err = repo.TxnCommit(ctx, tx)
	require.Error(t, err)
	require.ErrorIs(t, err, tufrepo.ErrClobberedTransaction)
	require.ErrorIs(t, err, storeopts.ErrETagMismatch)

	for _, blob := range wouldBeOrphans {
		_, _, err := repo.GetBlob(ctx, blob)
		require.ErrorIsf(t, err, fs.ErrNotExist, "blob %s should have been cleaned up", blob)
	}

	postTsBytes := readBlob(ctx, t, repo, tufmetadata.TIMESTAMP+".json")
	assert.Equal(t, preTsBytes, postTsBytes,
		"pre-existing timestamp.json must not have been overwritten")
}

// TestInitTxn_Commit_RejectsNonOneVersion pins TxnCommit's Version != 1
// gate. The Zero subtest covers the most plausible caller bug.
func TestInitTxn_Commit_RejectsNonOneVersion(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version int64
	}{
		{name: "Zero", version: 0},
		{name: "Two", version: 2},
		{name: "Large", version: 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			repo := newTestRepo(t)
			store, _ := newTestKeystore(t)

			rootKey := generateInsecureKey(ctx, t, store)
			targetsKey := generateInsecureKey(ctx, t, store)
			snapshotKey := generateInsecureKey(ctx, t, store)
			timestampKey := generateInsecureKey(ctx, t, store)

			builder := tufext.NewRootBuilder()
			builder.RootType().Version = tc.version
			require.Equal(t, tc.version, builder.RootType().Version,
				"sanity: RootBuilder must not normalise the caller's version")
			_, err := builder.AddRole(tufmetadata.ROOT, 1, rootKey.Public)
			require.NoError(t, err)
			_, err = builder.AddRole(tufmetadata.TARGETS, 1, targetsKey.Public)
			require.NoError(t, err)
			_, err = builder.AddRole(tufmetadata.SNAPSHOT, 1, snapshotKey.Public)
			require.NoError(t, err)
			_, err = builder.AddRole(tufmetadata.TIMESTAMP, 1, timestampKey.Public)
			require.NoError(t, err)
			signedRoot, _, err := builder.Sign(ctx, store)
			require.NoError(t, err)
			require.Equal(t, tc.version, signedRoot.Signed.Version)

			// The version guard fires before any upload, so tx.Sign would
			// only couple this test to Sign's own validation rules.
			tx := tufrepo.InitTxn(signedRoot)
			_, err = repo.TxnCommit(ctx, tx)
			require.ErrorIs(t, err, tufrepo.ErrInvalidTransactionState)
			assert.Contains(t, err.Error(), "version must be 1")
		})
	}
}

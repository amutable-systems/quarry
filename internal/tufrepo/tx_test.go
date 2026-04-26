//go:build insecure

// Copyright (C) 2026 Amutable GmbH

package tufrepo_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

// ----- TxnStart ----------------------------------------------------------

func TestTxnStart_EmptyRepo(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	_, err := repo.TxnStart(ctx)
	require.Error(t, err)
}

func TestTxnStart_Success(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx)

	// Top-level role data should be accessible.
	root, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), root.Signed.Version)

	ts, err := tx.TimestampRoleData(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), ts.Signed.Version)

	snap, err := tx.SnapshotRoleData(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), snap.Signed.Version)

	targets, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	assert.Equal(t, int64(1), targets.Signed.Version)

	// RefTime should be at-or-after bootstrap's initialRefTime.
	assert.False(t, tx.RefTime.Before(bs.initialRefTime),
		"RefTime %v should be >= bootstrap time %v", tx.RefTime, bs.initialRefTime)
}

// TestTxnStart_TimestampEmptyMeta_AcceptedAsPartialInit verifies that a
// timestamp.json with an empty Meta is treated as partial-init repo state:
// TxnStart succeeds, no snapshot is loaded, and the targets map is empty.
func TestTxnStart_TimestampEmptyMeta_AcceptedAsPartialInit(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	// Overwrite timestamp.json with one whose Meta is empty.
	ts := tufext.DefaultTimestamp(time.Now().Add(time.Hour))
	ts.Signed.Meta = map[string]*tufmetadata.MetaFiles{}
	signMeta(ctx, t, ts, bs.timestampKey)

	_, err := bs.repo.PutBlob(ctx, "timestamp.json", bytes.NewReader(mustEncode(t, ts)),
		storeopts.Clobber)
	require.NoError(t, err)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	snap, err := tx.SnapshotRoleData(ctx)
	require.NoError(t, err)
	assert.Nil(t, snap, "no snapshot should be loaded for empty-Meta timestamp")
	_, err = tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.ErrorIs(t, err, fs.ErrNotExist,
		"no targets should be loaded for empty-Meta timestamp")
}

// TestTxnStart_TimestampHasNonSnapshotMetaEntry covers the case where
// Meta has a single entry but it is not snapshot.json -- this must be
// rejected (it is not the partial-init state).
func TestTxnStart_TimestampHasNonSnapshotMetaEntry(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	ts := tufext.DefaultTimestamp(time.Now().Add(time.Hour))
	ts.Signed.Meta = map[string]*tufmetadata.MetaFiles{
		"foo.json": {Version: 1},
	}
	signMeta(ctx, t, ts, bs.timestampKey)

	_, err := bs.repo.PutBlob(ctx, "timestamp.json", bytes.NewReader(mustEncode(t, ts)),
		storeopts.Clobber)
	require.NoError(t, err)

	_, err = bs.repo.TxnStart(ctx)
	require.ErrorIs(t, err, tufrepo.ErrInvalidRepoState)
	assert.Contains(t, err.Error(), "roles other than snapshot")
}

func TestTxnStart_TimestampHasExtraMetaEntry(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	ts := currentTimestamp(ctx, t, bs.repo)
	// Add an unexpected extra link -- tx should reject this.
	ts.Signed.Meta["extra.json"] = &tufmetadata.MetaFiles{Version: 1}
	signMeta(ctx, t, ts, bs.timestampKey)

	_, err := bs.repo.PutBlob(ctx, "timestamp.json", bytes.NewReader(mustEncode(t, ts)),
		storeopts.Clobber)
	require.NoError(t, err)

	_, err = bs.repo.TxnStart(ctx)
	require.ErrorIs(t, err, tufrepo.ErrInvalidRepoState)
	assert.Contains(t, err.Error(), "roles other than snapshot")
}

func TestTxnStart_SnapshotMetapathMissingJSONSuffix(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	// Rewrite 1.snapshot.json so that its Meta uses a bare role name without
	// ".json" -- TxnStart should reject this explicitly.
	snap := tufext.DefaultSnapshot(time.Now().Add(time.Hour))
	snap.Signed.Version = 1
	snap.Signed.Meta = map[string]*tufmetadata.MetaFiles{
		tufmetadata.TARGETS: {Version: 1},
	}
	signMeta(ctx, t, snap, bs.snapshotKey)
	_, _, err := bs.repo.PutVersionedFile(ctx, tufmetadata.SNAPSHOT, snap, storeopts.Clobber)
	require.NoError(t, err)

	_, err = bs.repo.TxnStart(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), ".json suffix")
}

func TestTxnStart_SnapshotReferencesMissingTargets(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	// Point the snapshot at a non-existent target file version.
	snap := tufext.DefaultSnapshot(time.Now().Add(time.Hour))
	snap.Signed.Version = 1
	snap.Signed.Meta = map[string]*tufmetadata.MetaFiles{
		tufmetadata.TARGETS + ".json": {Version: 999},
	}
	signMeta(ctx, t, snap, bs.snapshotKey)
	_, _, err := bs.repo.PutVersionedFile(ctx, tufmetadata.SNAPSHOT, snap, storeopts.Clobber)
	require.NoError(t, err)

	// Timestamp must also be re-pointed at the rewritten snapshot.
	ts := currentTimestamp(ctx, t, bs.repo)
	hash, err := tufrepo.HashMetaFile(ctx, snap)
	require.NoError(t, err)
	ts.Signed.Meta = map[string]*tufmetadata.MetaFiles{tufmetadata.SNAPSHOT + ".json": hash}
	signMeta(ctx, t, ts, bs.timestampKey)
	_, err = bs.repo.PutBlob(ctx, "timestamp.json", bytes.NewReader(mustEncode(t, ts)),
		storeopts.Clobber)
	require.NoError(t, err)

	_, err = bs.repo.TxnStart(ctx)
	require.ErrorIs(t, err, fs.ErrNotExist)
}

func TestTxnStart_CorruptSnapshotJSON(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	_, err := bs.repo.PutBlob(ctx, "1.snapshot.json", bytes.NewReader([]byte("not json")),
		storeopts.Clobber)
	require.NoError(t, err)

	_, err = bs.repo.TxnStart(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse snapshot")
}

func TestTxnStart_SnapshotWrongType(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	// Store a timestamp payload as 1.snapshot.json.
	ts := tufext.DefaultTimestamp(time.Now().Add(time.Hour))
	_, err := bs.repo.PutBlob(ctx, "1.snapshot.json", bytes.NewReader(mustEncode(t, ts)),
		storeopts.Clobber)
	require.NoError(t, err)

	_, err = bs.repo.TxnStart(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid snapshot blob")
}

func TestTxnStart_CorruptRoot(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	_, err := bs.repo.PutBlob(ctx, "1.root.json", bytes.NewReader([]byte("not json")),
		storeopts.Clobber)
	require.NoError(t, err)

	_, err = bs.repo.TxnStart(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse latest root")
}

// TxnStart must call CheckMetadataType on every delegated target file it
// loads, not just on the top-level snapshot.
func TestTxnStart_DelegatedTargetWrongType(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t, withDelegation("bad-delegate"))

	// Overwrite 1.bad-delegate.json with a root payload instead of targets.
	root := tufext.DefaultRoot(time.Now().Add(time.Hour))
	_, err := bs.repo.PutBlob(ctx, "1.bad-delegate.json", bytes.NewReader(mustEncode(t, root)),
		storeopts.Clobber)
	require.NoError(t, err)

	_, err = bs.repo.TxnStart(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid bad-delegate blob")
}

// ----- Role data accessors ------------------------------------------------

func TestTransaction_RoleData_ReturnsDeepCopy(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	// Mutating the returned root should not leak back into the transaction.
	root, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	root.Signed.Version = 99999
	root.Signed.Roles[tufmetadata.ROOT].KeyIDs = nil

	root2, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), root2.Signed.Version)
	assert.NotEmpty(t, root2.Signed.Roles[tufmetadata.ROOT].KeyIDs)
}

func TestTransaction_RoleData_Dispatches(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	rootAny, err := tx.RoleData(ctx, tufmetadata.ROOT)
	require.NoError(t, err)
	_, ok := rootAny.(*tufext.SignedRoot)
	assert.True(t, ok, "expected *Metadata[RootType], got %T", rootAny)

	tsAny, err := tx.RoleData(ctx, tufmetadata.TIMESTAMP)
	require.NoError(t, err)
	_, ok = tsAny.(*tufext.SignedTimestamp)
	assert.True(t, ok)

	snapAny, err := tx.RoleData(ctx, tufmetadata.SNAPSHOT)
	require.NoError(t, err)
	_, ok = snapAny.(*tufext.SignedSnapshot)
	assert.True(t, ok)

	targetsAny, err := tx.RoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	_, ok = targetsAny.(*tufext.SignedTargets)
	assert.True(t, ok)
}

func TestTransaction_TargetsRoleData_UnknownRole(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	_, err = tx.TargetsRoleData(ctx, "never-existed")
	require.ErrorIs(t, err, fs.ErrNotExist)

	// Read-only getters must not poison the transaction on lookup failure.
	err = tx.Apply(ctx, tufrepo.NewTxnOp("noop", func(context.Context, *tufrepo.Transaction) error {
		return nil
	}))
	require.NoError(t, err, "TargetsRoleData ErrNotExist must not invalidate the transaction")
}

func TestTransaction_RootRoleData_PrefersNewRoot(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	orig, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	orig.Signed.Version = 12345
	require.NoError(t, tx.UpdateRoleData(tufmetadata.ROOT, orig))

	next, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(12345), next.Signed.Version)
}

// ----- UpdateRoleData input types ----------------------------------------

func TestTransaction_UpdateRoleData_AcceptsAllInputShapes(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	baseline, err := tx.RootRoleData(ctx)
	require.NoError(t, err)

	for _, tc := range []struct {
		name    string
		version int64
		build   func(*tufext.SignedRoot) any
	}{
		{
			name:    "MetadataPointer",
			version: 11,
			build: func(r *tufext.SignedRoot) any {
				r.Signed.Version = 11
				return r
			},
		},
		{
			name:    "MetadataValue",
			version: 12,
			build: func(r *tufext.SignedRoot) any {
				r.Signed.Version = 12
				return *r
			},
		},
		{
			name:    "Bytes",
			version: 13,
			build: func(r *tufext.SignedRoot) any {
				r.Signed.Version = 13
				return mustEncode(t, r)
			},
		},
		{
			name:    "RawMessage",
			version: 14,
			build: func(r *tufext.SignedRoot) any {
				r.Signed.Version = 14
				return json.RawMessage(mustEncode(t, r))
			},
		},
		{
			name:    "Reader",
			version: 15,
			build: func(r *tufext.SignedRoot) any {
				r.Signed.Version = 15
				return bytes.NewReader(mustEncode(t, r))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Every sub-test starts from a fresh clone of the baseline.
			clone := decodeJSON[tufmetadata.RootType](t, mustEncode(t, baseline))
			require.NoError(t, tx.UpdateRoleData(tufmetadata.ROOT, tc.build(clone)))

			got, err := tx.RootRoleData(ctx)
			require.NoError(t, err)
			assert.Equal(t, tc.version, got.Signed.Version)
		})
	}
}

func TestTransaction_UpdateRoleData_UnsupportedType(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	err = tx.UpdateRoleData(tufmetadata.ROOT, "not a metadata struct")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported data type")
}

func TestTransaction_UpdateRoleData_CorruptBytes(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	err = tx.UpdateRoleData(tufmetadata.ROOT, []byte("not-json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode JSON")
}

func TestTransaction_UpdateRoleData_ReaderError(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	boom := errors.New("reader boom")
	err = tx.UpdateRoleData(tufmetadata.ROOT, errReader{err: boom})
	require.ErrorIs(t, err, boom)
}

// TestTransaction_UpdateRoleData_MismatchedRole is a table of
// role-payload mismatches -- every combination must surface as
// [tufrepo.ErrMismatchedRole] so callers can branch on it cleanly.
//
// The payloads are encoded to bytes so they go through parseRoleData's JSON
// path (where the *Signed.Type field is what establishes role identity) --
// passing a typed *Metadata struct would short-circuit in the Go type
// switch before CheckMetadataType ever ran.
func TestTransaction_UpdateRoleData_MismatchedRole(t *testing.T) {
	// Pre-encode one payload for every role so every sub-test can pick a
	// payload whose _type does not match the target role.
	encoded := map[string][]byte{
		tufmetadata.ROOT:      mustEncode(t, tufext.DefaultRoot(time.Now().Add(time.Hour))),
		tufmetadata.TARGETS:   mustEncode(t, tufext.DefaultTargets(time.Now().Add(time.Hour))),
		tufmetadata.SNAPSHOT:  mustEncode(t, tufext.DefaultSnapshot(time.Now().Add(time.Hour))),
		tufmetadata.TIMESTAMP: mustEncode(t, tufext.DefaultTimestamp(time.Now().Add(time.Hour))),
	}

	for _, tc := range []struct {
		role    string
		payload string // key into encoded -- must differ from role
	}{
		{tufmetadata.ROOT, tufmetadata.TIMESTAMP},
		{tufmetadata.TARGETS, tufmetadata.ROOT},
		{tufmetadata.SNAPSHOT, tufmetadata.TARGETS},
		{tufmetadata.TIMESTAMP, tufmetadata.SNAPSHOT},
	} {
		t.Run(tc.role+"_with_"+tc.payload, func(t *testing.T) {
			ctx := context.Background()
			bs := bootstrapRepo(t)
			tx, err := bs.repo.TxnStart(ctx)
			require.NoError(t, err)

			err = tx.UpdateRoleData(tc.role, encoded[tc.payload])
			require.ErrorIs(t, err, tufrepo.ErrMismatchedRole)
			assert.Contains(t, err.Error(), "_type")
		})
	}
}

// TestTransaction_UpdateRoleData_DelegatedRoleName ensures that passing a
// role name which is not a core role creates/updates the delegated targets
// entry.
func TestTransaction_UpdateRoleData_DelegatedRoleName(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t, withDelegation("mydeleg"))

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	data, err := tx.TargetsRoleData(ctx, "mydeleg")
	require.NoError(t, err)
	data.Signed.Version = 77
	require.NoError(t, tx.UpdateRoleData("mydeleg", data))

	got, err := tx.TargetsRoleData(ctx, "mydeleg")
	require.NoError(t, err)
	assert.Equal(t, int64(77), got.Signed.Version)
}

// ----- ClearRole ----------------------------------------------------------

func TestTransaction_ClearRole_RejectsCoreRoles(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	for _, role := range tufmetadata.TOP_LEVEL_ROLE_NAMES {
		t.Run(role, func(t *testing.T) {
			err := tx.ClearRole(ctx, role)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "top-level role")
		})
	}
}

func TestTransaction_ClearRole_RemovesDelegatedRole(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t, withDelegation("tbd"))

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	// Role is initially present.
	_, err = tx.TargetsRoleData(ctx, "tbd")
	require.NoError(t, err)

	require.NoError(t, tx.ClearRole(ctx, "tbd"))

	_, err = tx.TargetsRoleData(ctx, "tbd")
	require.ErrorIs(t, err, fs.ErrNotExist)
}

// Regression test for the ClearRole-after-UpdateRoleData bug: clearing a role
// that was also modified in the same transaction must not leave the role in
// the dirty set, or bumpRevisions will crash looking up its now-missing data.
func TestTransaction_ClearRole_AfterUpdateDoesNotBreakSign(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t, withDelegation("will-be-cleared"))

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	// Modify, then clear the same delegated role in one transaction.
	data, err := tx.TargetsRoleData(ctx, "will-be-cleared")
	require.NoError(t, err)
	data.Signed.Version = 42
	require.NoError(t, tx.UpdateRoleData("will-be-cleared", data))

	require.NoError(t, tx.ClearRole(ctx, "will-be-cleared"))

	_, err = tx.Sign(ctx, bs.store)
	require.NoError(t, err)
}

// ----- Roles / DefinedRoles iterators ------------------------------------

func TestTransaction_Roles(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t, withDelegation("a"), withDelegation("b"))

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	var got []string
	for role, err := range tx.Roles(ctx) {
		require.NoError(t, err)
		got = append(got, role)
	}

	// Top-level roles come first, in spec order.
	topLevel := len(tufmetadata.TOP_LEVEL_ROLE_NAMES)
	require.GreaterOrEqual(t, len(got), topLevel)
	assert.Equal(t, tufmetadata.TOP_LEVEL_ROLE_NAMES[:], got[:topLevel])

	// Delegated roles appear exactly once afterwards.
	delegated := got[topLevel:]
	slices.Sort(delegated)
	assert.Equal(t, []string{"a", "b"}, delegated)
}

func TestTransaction_Roles_BreakStopsIteration(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	var got []string
	for role, err := range tx.Roles(ctx) {
		require.NoError(t, err)
		got = append(got, role)
		if len(got) == 2 {
			break
		}
	}
	assert.Len(t, got, 2)
}

func TestTransaction_DefinedRoles(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t, withDelegation("delegA"))

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	// Add another delegation declared only in targets but with no
	// corresponding metafile. DefinedRoles should still include it.
	targets, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	extraKey := generateInsecureKey(ctx, t, bs.store)
	extraKeyID := mustKeyIDs(t, extraKey)[0]
	targets.Signed.Delegations.Keys[extraKeyID] = &extraKey.Public
	targets.Signed.Delegations.Roles = append(targets.Signed.Delegations.Roles, tufmetadata.DelegatedRole{
		Name:      "phantom",
		KeyIDs:    []string{extraKeyID},
		Threshold: 1,
	})
	require.NoError(t, tx.UpdateRoleData(tufmetadata.TARGETS, targets))

	var got []string
	for role, err := range tx.DefinedRoles(ctx) {
		require.NoError(t, err)
		got = append(got, role)
	}
	slices.Sort(got)
	assert.Equal(t, []string{
		"delegA", "phantom",
		tufmetadata.ROOT, tufmetadata.SNAPSHOT, tufmetadata.TARGETS, tufmetadata.TIMESTAMP,
	}, got)
}

// ----- Apply / transaction failure --------------------------------------

func TestTransaction_Apply_RunsOpsInOrder(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	var seen []string
	op := func(name string) tufrepo.TxnOp {
		return tufrepo.NewTxnOp(name, func(_ context.Context, _ *tufrepo.Transaction) error {
			seen = append(seen, name)
			return nil
		})
	}

	require.NoError(t, tx.Apply(ctx, op("first"), op("second"), op("third")))
	assert.Equal(t, []string{"first", "second", "third"}, seen)
}

func TestTransaction_Apply_StopsOnFirstError(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	boom := errors.New("boom")
	var ranAfterFailure bool
	err = tx.Apply(ctx,
		tufrepo.NewTxnOp("fail", func(context.Context, *tufrepo.Transaction) error { return boom }),
		tufrepo.NewTxnOp("should-not-run", func(context.Context, *tufrepo.Transaction) error {
			ranAfterFailure = true
			return nil
		}),
	)
	require.ErrorIs(t, err, boom)
	assert.Contains(t, err.Error(), `"fail"`)
	assert.False(t, ranAfterFailure, "ops after a failing op must not run")
}

func TestTransaction_Apply_ContextCancelled(t *testing.T) {
	bs := bootstrapRepo(t)

	ctx := context.Background()
	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	cctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = tx.Apply(cctx, tufrepo.NewTxnOp("no-op", func(context.Context, *tufrepo.Transaction) error {
		t.Fatal("op should not run under a cancelled ctx")
		return nil
	}))
	require.ErrorIs(t, err, context.Canceled)
}

// TestTransaction_Apply_NoOps applies zero TxnOps -- must succeed and
// neither mutate the transaction state nor invalidate it.
func TestTransaction_Apply_NoOps(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	require.NoError(t, tx.Apply(ctx))

	// Transaction must still be usable.
	_, err = tx.RootRoleData(ctx)
	require.NoError(t, err)
}

// TestTransaction_Apply_CancelledBetweenOps covers the per-iteration
// ctx.Done() check. The first op runs; then the context is cancelled; the
// second op must not run.
func TestTransaction_Apply_CancelledBetweenOps(t *testing.T) {
	bs := bootstrapRepo(t)
	parent := context.Background()
	tx, err := bs.repo.TxnStart(parent)
	require.NoError(t, err)

	cctx, cancel := context.WithCancel(parent)

	var firstRan, secondRan bool
	err = tx.Apply(cctx,
		tufrepo.NewTxnOp("first", func(context.Context, *tufrepo.Transaction) error {
			firstRan = true
			cancel()
			return nil
		}),
		tufrepo.NewTxnOp("second", func(context.Context, *tufrepo.Transaction) error {
			secondRan = true
			return nil
		}),
	)
	require.ErrorIs(t, err, context.Canceled)
	assert.True(t, firstRan, "first op should have run before cancellation")
	assert.False(t, secondRan, "second op must be skipped after cancellation")
}

// A transaction that has seen one failure must refuse to do further
// externally-visible work (Apply, Sign, TxnCommit) with the original
// failure preserved as the root cause. Read-only getters and
// internal-only mutators (UpdateRoleData, ClearRole, BumpExpiry, ...)
// are intentionally exempt: they don't have external side effects, and
// any state they leave behind is gated downstream by Apply/Sign/Commit.
func TestTransaction_InvalidatedAfterFailure(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	boom := errors.New("poison")
	err = tx.Apply(ctx, tufrepo.NewTxnOp("poison", func(context.Context, *tufrepo.Transaction) error {
		return boom
	}))
	require.ErrorIs(t, err, boom)

	// Read-only getters keep working: the post-failure state is whatever
	// was there at the moment the op returned an error.
	_, err = tx.RootRoleData(ctx)
	require.NoError(t, err)
	_, err = tx.TimestampRoleData(ctx)
	require.NoError(t, err)
	_, err = tx.SnapshotRoleData(ctx)
	require.NoError(t, err)
	_, err = tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)

	// Externally-visible methods (Apply runs user code, Sign produces
	// signed blobs, TxnCommit hits the store) all refuse to operate.
	err = tx.Apply(ctx, tufrepo.NewTxnOp("noop", func(context.Context, *tufrepo.Transaction) error {
		return nil
	}))
	require.ErrorIs(t, err, boom)
	_, err = tx.Sign(ctx, bs.store)
	require.ErrorIs(t, err, boom)
	_, err = bs.repo.TxnCommit(ctx, tx)
	require.ErrorIs(t, err, boom)
}

// ----- TxnCommit ---------------------------------------------------------

func TestTxnCommit_HappyPath(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	// Modify targets -- add a fake target file.
	require.NoError(t, tx.Apply(ctx, addTargetOp("t/example.bin", 42)))

	_, err = tx.Sign(ctx, bs.store)
	require.NoError(t, err)

	committedTs, err := bs.repo.TxnCommit(ctx, tx)
	require.NoError(t, err)
	require.NotNil(t, committedTs)
	assert.Greater(t, committedTs.Signed.Version, int64(1),
		"timestamp version must be bumped above bootstrap value")

	// A fresh TxnStart should see the new state.
	tx2, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)
	targets, err := tx2.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	require.Contains(t, targets.Signed.Targets, "t/example.bin")
	assert.Equal(t, int64(42), targets.Signed.Targets["t/example.bin"].Length)
}

// TxnCommit must reject a racing timestamp write and fully roll back the
// versioned blobs it pre-staged, so the repo is not left with orphan
// metadata.
func TestTxnCommit_ClobberRollsBackVersionedBlobs(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)
	require.NoError(t, tx.Apply(ctx, addTargetOp("t/example.bin", 1)))
	_, err = tx.Sign(ctx, bs.store)
	require.NoError(t, err)

	// Capture the exact versioned filenames the commit will try to upload.
	// Anything dirty becomes {version}.{role}.json.
	orphanRoles := []string{tufmetadata.TARGETS, tufmetadata.SNAPSHOT, tufmetadata.TIMESTAMP}
	wouldBeOrphans := make([]string, 0, len(orphanRoles))
	for _, role := range orphanRoles {
		data, err := tx.RoleData(ctx, role)
		require.NoError(t, err)
		version := tufrepo.SignedVersion(t, data)
		wouldBeOrphans = append(wouldBeOrphans, fmt.Sprintf("%d.%s.json", version, role))
	}

	// Simulate a racing writer that clobbers timestamp.json after Sign but
	// before our commit -- this will fail the atomic timestamp swap.
	_, err = bs.repo.PutBlob(ctx, "timestamp.json",
		bytes.NewReader([]byte("racing-writer")), storeopts.Clobber)
	require.NoError(t, err)

	_, err = bs.repo.TxnCommit(ctx, tx)
	require.ErrorIs(t, err, tufrepo.ErrClobberedTransaction)
	require.ErrorIs(t, err, storeopts.ErrETagMismatch)

	// Every blob that was pre-staged for the commit must have been cleaned up.
	for _, name := range wouldBeOrphans {
		_, _, err := bs.repo.GetBlob(ctx, name)
		require.ErrorIsf(t, err, fs.ErrNotExist,
			"blob %s should have been cleaned up", name)
	}

	// The racing writer's bytes must still be live at timestamp.json -- the
	// commit's atomic swap must not have overwritten them past the failed
	// ETag check.
	rdr, _, err := bs.repo.GetBlob(ctx, "timestamp.json")
	require.NoError(t, err)
	body, err := io.ReadAll(rdr)
	require.NoError(t, err)
	require.NoError(t, rdr.Close())
	assert.Equal(t, []byte("racing-writer"), body,
		"timestamp.json must still contain the racing writer's payload")
}

// A second TxnCommit on the same transaction fails cleanly -- the versioned
// blobs cannot be re-uploaded (NoClobber) and the timestamp ETag has changed.
// Importantly, the cleanup defer must not delete the blobs committed by the
// first (successful) commit.
func TestTxnCommit_Twice_DoesNotDestroyFirstCommit(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	require.NoError(t, tx.Apply(ctx, addTargetOp("t/file", 1)))
	_, err = tx.Sign(ctx, bs.store)
	require.NoError(t, err)

	firstTs, err := bs.repo.TxnCommit(ctx, tx)
	require.NoError(t, err)

	// Second commit must fail.
	_, err = bs.repo.TxnCommit(ctx, tx)
	require.Error(t, err)

	// But the first commit's live state must still be intact.
	liveTs := currentTimestamp(ctx, t, bs.repo)
	assert.Equal(t, firstTs.Signed.Version, liveTs.Signed.Version)
	// The snapshot link survived intact: same version and hashes after re-fetch.
	require.Contains(t, liveTs.Signed.Meta, tufmetadata.SNAPSHOT+".json")
	liveSnap := liveTs.Signed.Meta[tufmetadata.SNAPSHOT+".json"]
	firstSnap := firstTs.Signed.Meta[tufmetadata.SNAPSHOT+".json"]
	assert.Equal(t, firstSnap.Version, liveSnap.Version)
	assert.Equal(t, firstSnap.Hashes, liveSnap.Hashes)
}

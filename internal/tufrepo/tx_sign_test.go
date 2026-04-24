// Copyright (C) 2026 Amutable GmbH

//go:build insecure

package tufrepo_test

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/tufext"
	"go.amutable.dev/quarry/internal/tufrepo"
)

// Sign on a pristine, unmodified transaction is a no-op.
func TestSign_NoDirty(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	newKeys, err := tx.Sign(ctx, bs.store)
	require.NoError(t, err)
	assert.Empty(t, newKeys)

	// None of the versions should have changed.
	root, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), root.Signed.Version)

	ts, err := tx.TimestampRoleData(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), ts.Signed.Version)

	snap, err := tx.SnapshotRoleData(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), snap.Signed.Version)
}

// Modifying the top-level targets role should cascade into snapshot and
// timestamp version bumps, and all three should have fresh valid signatures.
func TestSign_TargetsChangeCascadesThroughSnapshotAndTimestamp(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)
	require.NoError(t, tx.Apply(ctx, addTargetOp("x/y", 9)))

	newKeys, err := tx.Sign(ctx, bs.store)
	require.NoError(t, err)
	assert.Empty(t, newKeys, "no keys should be rotated when only targets change")

	targets, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	assert.Greater(t, targets.Signed.Version, int64(1), "targets version bumped")

	snap, err := tx.SnapshotRoleData(ctx)
	require.NoError(t, err)
	assert.Greater(t, snap.Signed.Version, int64(1), "snapshot version bumped")
	// Snapshot's meta must reference the newly bumped targets version.
	targetsMeta, ok := snap.Signed.Meta[tufmetadata.TARGETS+".json"]
	require.True(t, ok)
	assert.Equal(t, targets.Signed.Version, targetsMeta.Version)

	ts, err := tx.TimestampRoleData(ctx)
	require.NoError(t, err)
	assert.Greater(t, ts.Signed.Version, int64(1), "timestamp version bumped")
	// Timestamp's meta must reference the newly bumped snapshot version.
	snapMeta, ok := ts.Signed.Meta[tufmetadata.SNAPSHOT+".json"]
	require.True(t, ok)
	assert.Equal(t, snap.Signed.Version, snapMeta.Version)

	// Every role should have fresh valid signatures that go-tuf accepts.
	rootMeta, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	assertRootDelegates(ctx, t, tx, tufmetadata.ROOT, rootMeta)
	assertRootDelegates(ctx, t, tx, tufmetadata.TARGETS, targets)
	assertRootDelegates(ctx, t, tx, tufmetadata.SNAPSHOT, snap)
	assertRootDelegates(ctx, t, tx, tufmetadata.TIMESTAMP, ts)
}

// Sign must be idempotent: calling it a second time with no further changes
// should not mutate versions, expiries, or signatures.
func TestSign_Idempotent(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)
	require.NoError(t, tx.Apply(ctx, addTargetOp("a/b", 3)))

	_, err = tx.Sign(ctx, bs.store)
	require.NoError(t, err)

	// Snapshot the post-Sign state.
	rootAfter1, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	tsAfter1, err := tx.TimestampRoleData(ctx)
	require.NoError(t, err)
	snapAfter1, err := tx.SnapshotRoleData(ctx)
	require.NoError(t, err)
	targetsAfter1, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)

	_, err = tx.Sign(ctx, bs.store)
	require.NoError(t, err)

	// Second Sign must not touch anything.
	rootAfter2, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	tsAfter2, err := tx.TimestampRoleData(ctx)
	require.NoError(t, err)
	snapAfter2, err := tx.SnapshotRoleData(ctx)
	require.NoError(t, err)
	targetsAfter2, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)

	assert.Equal(t, rootAfter1.Signed.Version, rootAfter2.Signed.Version)
	assert.Equal(t, rootAfter1.Signatures, rootAfter2.Signatures)
	assert.Equal(t, tsAfter1.Signed.Version, tsAfter2.Signed.Version)
	assert.Equal(t, tsAfter1.Signatures, tsAfter2.Signatures)
	assert.Equal(t, snapAfter1.Signed.Version, snapAfter2.Signed.Version)
	assert.Equal(t, snapAfter1.Signatures, snapAfter2.Signatures)
	assert.Equal(t, targetsAfter1.Signed.Version, targetsAfter2.Signed.Version)
	assert.Equal(t, targetsAfter1.Signatures, targetsAfter2.Signatures)
}

// When the root role is dirtied (but not pre-signed), Sign must rotate the
// timestamp key per TUF spec PR #316 -- the new root binds the new timestamp
// key.
func TestSign_DirtyRootRotatesTimestampKey(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	oldRoot, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	oldTimestampKeyIDs := append([]string(nil), oldRoot.Signed.Roles[tufmetadata.TIMESTAMP].KeyIDs...)

	// Dirty the root with an unrelated tweak (bump its expiry by a day).
	// Signatures from the existing key are now stale, so Sign's "is this
	// already signed?" check will return false and we'll take the rotation
	// path.
	oldRoot.Signed.Expires = oldRoot.Signed.Expires.Add(24 * time.Hour)
	oldRoot.Signatures = nil
	require.NoError(t, tx.UpdateRoleData(tufmetadata.ROOT, oldRoot))

	newKeys, err := tx.Sign(ctx, bs.store)
	require.NoError(t, err)
	assert.NotEmpty(t, newKeys, "timestamp key should have been rotated")

	newRoot, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	newTimestampKeyIDs := newRoot.Signed.Roles[tufmetadata.TIMESTAMP].KeyIDs
	assert.NotEqual(t, oldTimestampKeyIDs, newTimestampKeyIDs,
		"timestamp role should reference new key ids after rotation")

	// The returned newKeys should match the new timestamp keyIDs.
	wantIDs := make([]string, len(newKeys))
	for i, id := range newKeys {
		wantIDs[i] = string(id)
	}
	assert.ElementsMatch(t, newTimestampKeyIDs, wantIDs)

	// The new timestamp is signed by the new key -- root's view of it verifies.
	ts, err := tx.TimestampRoleData(ctx)
	require.NoError(t, err)
	assertRootDelegates(ctx, t, tx, tufmetadata.TIMESTAMP, ts)
}

// A pre-signed root (where all of the root's quorums already verify) must
// NOT trigger the rotation of the timestamp key -- the user explicitly asked
// for the new root shape, and we trust their signing.
func TestSign_PreSignedRootSkipsTimestampRotation(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	// Pre-sign a new root (just bump version & re-sign with the existing
	// root key; expiries/keys are unchanged).
	oldRoot, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	oldTimestampKeyIDs := append([]string(nil), oldRoot.Signed.Roles[tufmetadata.TIMESTAMP].KeyIDs...)

	oldRoot.Signed.Version = 2
	oldRoot.Signatures = nil
	_, err = tufext.SignRole(ctx, oldRoot, bs.rootKey)
	require.NoError(t, err)

	require.NoError(t, tx.UpdateRoleData(tufmetadata.ROOT, oldRoot))

	newKeys, err := tx.Sign(ctx, bs.store)
	require.NoError(t, err)
	assert.Empty(t, newKeys, "pre-signed root must not trigger key rotation")

	// Timestamp role's key IDs in root must be unchanged.
	newRoot, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	assert.Equal(t, oldTimestampKeyIDs, newRoot.Signed.Roles[tufmetadata.TIMESTAMP].KeyIDs)
}

// Sign must fail cleanly when the quorum cannot be met because the signing
// key has been unlinked from the keystore.
func TestSign_FailsWhenThresholdCannotBeMet(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	targetsID, err := bs.targetsKey.ID()
	require.NoError(t, err)
	require.NoError(t, bs.store.UnlinkKey(ctx, targetsID))

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	// Force the targets role to need re-signing.
	require.NoError(t, tx.Apply(ctx, addTargetOp("unsignable", 1)))

	_, err = tx.Sign(ctx, bs.store)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "of required")
}

// signRoleWith's terminal fallback (tx_sign.go: "...it must've been signed
// by a different key store or mechanism.") re-appends the original signature
// untouched. Reaching it requires a signature whose keyID is neither in the
// role's quorum nor in the local keystore, on a role that Sign is actually
// about to re-sign (i.e. not short-circuited by checkRoleSignatures).
func TestSign_PreservesForeignSignaturesOnReSignedRole(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	// Force the targets role to be re-signed by adding a target and attach
	// a foreign-keyID signature on top. The foreign keyID is a valid-looking
	// ed25519 id but neither in the quorum (root only knows bs.targetsKey)
	// nor in the keystore -- so signRoleWith must take the fallback
	// re-insert path.
	foreignKeyID := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	foreignSig := tufmetadata.Signature{
		KeyID:     foreignKeyID,
		Signature: []byte("foreign-signature-from-some-other-keystore"),
	}
	require.NoError(t, tx.Apply(ctx, addTargetOp("t/x", 1)))
	require.NoError(t, tx.Apply(ctx, tufrepo.NewTxnOp("inject-foreign-sig",
		func(ctx context.Context, tx *tufrepo.Transaction) error {
			targets, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
			if err != nil {
				return err
			}
			targets.Signatures = append(targets.Signatures, foreignSig)
			return tx.UpdateRoleData(tufmetadata.TARGETS, targets)
		})))

	_, err = tx.Sign(ctx, bs.store)
	require.NoError(t, err)

	signedTargets, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)

	// The foreign signature must have survived alongside a fresh signature
	// from the actual targets quorum key.
	var sawForeign, sawQuorum bool
	quorumID, err := bs.targetsKey.ID()
	require.NoError(t, err)
	for _, s := range signedTargets.Signatures {
		if s.KeyID == foreignKeyID {
			sawForeign = true
			assert.Equal(t, []byte(foreignSig.Signature), []byte(s.Signature),
				"foreign signature body must be preserved verbatim")
		}
		if s.KeyID == string(quorumID) {
			sawQuorum = true
		}
	}
	assert.True(t, sawForeign, "foreign signature was dropped by signRoleWith")
	assert.True(t, sawQuorum, "fresh quorum signature was not produced by signRoleWith")
	assertRootDelegates(ctx, t, tx, tufmetadata.TARGETS, signedTargets)
}

// A role with N keys and threshold M < N should only receive M signatures
// after Sign -- the "break once threshold met" early-exit in signRoleWith
// must kick in.
func TestSign_StopsAfterThresholdMet(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	extraKey := generateInsecureKey(ctx, t, bs.store)
	extraKeyID, err := extraKey.ID()
	require.NoError(t, err)
	origTimestampID, err := bs.timestampKey.ID()
	require.NoError(t, err)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	// Pre-sign a new root with a 2-key TIMESTAMP role. Pre-signing (by the
	// existing root key) prevents Sign from taking the "dirty root → rotate
	// timestamp keys" branch, so the quorum seen by signRoleWith keeps both
	// keys we just added.
	root, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	role := root.Signed.Roles[tufmetadata.TIMESTAMP]
	role.KeyIDs = append(role.KeyIDs, string(extraKeyID))
	role.Threshold = 1 // explicit -- the whole point is threshold < len(keys)
	root.Signed.Keys[string(extraKeyID)] = &extraKey.Public
	root.Signed.Version = 2
	root.Signatures = nil
	_, err = tufext.SignRole(ctx, root, bs.rootKey)
	require.NoError(t, err)
	require.NoError(t, tx.UpdateRoleData(tufmetadata.ROOT, root))

	// Strip the existing timestamp signature so signRoleWith's first loop
	// has nothing to reuse; threshold is only reached via the second loop,
	// which must break after signing with exactly one key.
	ts, err := tx.TimestampRoleData(ctx)
	require.NoError(t, err)
	ts.Signatures = nil
	require.NoError(t, tx.UpdateRoleData(tufmetadata.TIMESTAMP, ts))

	// Force the re-sign cascade (targets → snapshot → timestamp).
	require.NoError(t, tx.Apply(ctx, addTargetOp("t/x", 1)))

	_, err = tx.Sign(ctx, bs.store)
	require.NoError(t, err)

	signedTs, err := tx.TimestampRoleData(ctx)
	require.NoError(t, err)
	require.Len(t, signedTs.Signatures, 1)
	// Map iteration order in signRoleWith's second loop is nondeterministic,
	// so accept either quorum key -- just not anything else.
	assert.Contains(t,
		[]string{string(origTimestampID), string(extraKeyID)},
		signedTs.Signatures[0].KeyID,
		"lone signature must come from one of the declared TIMESTAMP keys")
	assertRootDelegates(ctx, t, tx, tufmetadata.TIMESTAMP, signedTs)
}

// A pre-existing signature whose keyID is in the quorum but which fails
// verification (e.g. garbled bytes) must be dropped and replaced with a
// fresh signature from the same key (available in the store), rather than
// re-appended as-is.
func TestSign_DropsInvalidSignatureFromKnownQuorumKey(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	targetsID, err := bs.targetsKey.ID()
	require.NoError(t, err)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	// Mutate targets (forces re-sign), AND inject a garbled pre-existing
	// signature claiming to be from targetsKey. The garbled sig won't
	// verify, so signRoleWith should drop it and re-sign cleanly.
	require.NoError(t, tx.Apply(ctx, tufrepo.NewTxnOp("inject-garbled-sig",
		func(ctx context.Context, tx *tufrepo.Transaction) error {
			targets, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
			if err != nil {
				return err
			}
			targets.Signed.Targets = map[string]*tufmetadata.TargetFiles{
				"x/y": {Length: 1, Hashes: tufmetadata.Hashes{"sha256": []byte("thirty-two-bytes-padding-padding")}},
			}
			targets.Signatures = []tufmetadata.Signature{
				{KeyID: string(targetsID), Signature: []byte("garbled")},
			}
			return tx.UpdateRoleData(tufmetadata.TARGETS, targets)
		})))

	_, err = tx.Sign(ctx, bs.store)
	require.NoError(t, err)

	targets, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	require.Len(t, targets.Signatures, 1, "garbled sig must be replaced, not duplicated")
	assert.Equal(t, string(targetsID), targets.Signatures[0].KeyID)
	assert.NotEqual(t, []byte("garbled"), []byte(targets.Signatures[0].Signature))
	assertRootDelegates(ctx, t, tx, tufmetadata.TARGETS, targets)
}

// findRoleDelegators must error on a role that appears in no delegator.
// Hitting this through the public API means adding an orphan delegated
// target role (present in tx.targets but unreferenced by main targets).
func TestSign_NoDelegatorForOrphanedRole(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	orphan := tufmetadata.Targets(time.Now().Add(time.Hour))
	require.NoError(t, tx.UpdateRoleData("orphan-role", orphan))

	_, err = tx.Sign(ctx, bs.store)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not find any delegators for role orphan-role")
}

// BumpExpiry must persist a non-nil new expiry for every role type the
// metaExpiry switch covers -- the four core roles plus delegated targets.
// The closure must also see the live expiry for that role as oldExpiry.
func TestBumpExpiry_WritesNewExpiryForAllRoles(t *testing.T) {
	for _, roleName := range []string{
		tufmetadata.ROOT, tufmetadata.TIMESTAMP, tufmetadata.SNAPSHOT,
		tufmetadata.TARGETS, "my-delegation",
	} {
		t.Run(roleName, func(t *testing.T) {
			ctx := context.Background()
			bs := bootstrapRepo(t, withDelegation("my-delegation"))

			tx, err := bs.repo.TxnStart(ctx)
			require.NoError(t, err)

			origData, err := tx.RoleData(ctx, roleName)
			require.NoError(t, err)
			origExpires := tufrepo.SignedExpires(t, origData)
			newExpires := origExpires.Add(99 * time.Hour)

			var seenOld time.Time
			err = tx.BumpExpiry(ctx, roleName, func(oldExpiry time.Time, _ any) (*time.Time, error) {
				seenOld = oldExpiry
				return &newExpires, nil
			})
			require.NoError(t, err)
			assert.True(t, seenOld.Equal(origExpires),
				"closure should see live expiry %v, got %v", origExpires, seenOld)

			got, err := tx.RoleData(ctx, roleName)
			require.NoError(t, err)
			assert.True(t, newExpires.Equal(tufrepo.SignedExpires(t, got)),
				"role expiry should be %v, got %v", newExpires, tufrepo.SignedExpires(t, got))
		})
	}
}

// A nil return from the closure must leave the role untouched -- expiry
// unchanged, and nothing marked dirty (observed via a follow-up Sign that
// produces no version bump).
func TestBumpExpiry_NilReturnLeavesRoleUnchanged(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	origData, err := tx.RoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	origExpires := tufrepo.SignedExpires(t, origData)
	origVersion := tufrepo.SignedVersion(t, origData)

	err = tx.BumpExpiry(ctx, tufmetadata.TARGETS, func(time.Time, any) (*time.Time, error) {
		return nil, nil //nolint:nilnil // nil indicates no change needed
	})
	require.NoError(t, err)

	after, err := tx.RoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	assert.True(t, origExpires.Equal(tufrepo.SignedExpires(t, after)),
		"expiry must not change when closure returns nil")

	_, err = tx.Sign(ctx, bs.store)
	require.NoError(t, err)
	afterSign, err := tx.RoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	assert.Equal(t, origVersion, tufrepo.SignedVersion(t, afterSign),
		"targets version must not bump when BumpExpiry was a no-op")
}

// An error returned from the closure must propagate verbatim and invalidate
// the transaction.
func TestBumpExpiry_ClosureErrorInvalidatesTransaction(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	boom := errors.New("boom")
	err = tx.BumpExpiry(ctx, tufmetadata.TARGETS, func(time.Time, any) (*time.Time, error) {
		return nil, boom
	})
	require.ErrorIs(t, err, boom)

	_, err = tx.RootRoleData(ctx)
	require.ErrorIs(t, err, boom)
}

// An unknown role name falls through RoleData to TargetsRoleData, which must
// surface fs.ErrNotExist before the closure ever runs.
func TestBumpExpiry_UnknownRoleError(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	err = tx.BumpExpiry(ctx, "never-existed", func(time.Time, any) (*time.Time, error) {
		t.Fatal("closure must not run when the role cannot be fetched")
		return nil, nil //nolint:nilnil // unreachable, closure must not run
	})
	require.ErrorIs(t, err, fs.ErrNotExist)
}

// A pre-invalidated transaction must reject BumpExpiry outright, without
// invoking the closure.
func TestBumpExpiry_RejectsInvalidatedTransaction(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	boom := errors.New("poison")
	err = tx.Apply(ctx, tufrepo.NewTxnOp("poison", func(context.Context, *tufrepo.Transaction) error {
		return boom
	}))
	require.ErrorIs(t, err, boom)

	err = tx.BumpExpiry(ctx, tufmetadata.TARGETS, func(time.Time, any) (*time.Time, error) {
		t.Fatal("closure must not run on a failed transaction")
		return nil, nil //nolint:nilnil // unreachable, closure must not run
	})
	require.ErrorIs(t, err, boom)
}

// Per the doc comment, when the closure returns a non-nil expiry, any other
// modifications the closure made to the role data must also be committed.
// A follow-up Sign must also re-sign the role -- BumpExpiry has to dirty the
// role for bumpExpiries's caller contract to hold.
func TestBumpExpiry_CommitsClosureMutationsWithNewExpiry(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	origData, err := tx.RoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	origVersion := tufrepo.SignedVersion(t, origData)
	newExpires := tufrepo.SignedExpires(t, origData).Add(42 * time.Hour)

	err = tx.BumpExpiry(ctx, tufmetadata.TARGETS, func(_ time.Time, roleData any) (*time.Time, error) {
		targets := roleData.(*tufmetadata.Metadata[tufmetadata.TargetsType]) //nolint:forcetypeassert // tx.RoleData guarantees this type for TARGETS
		if targets.Signed.Targets == nil {
			targets.Signed.Targets = map[string]*tufmetadata.TargetFiles{}
		}
		targets.Signed.Targets["foo/bar"] = &tufmetadata.TargetFiles{
			Length: 7,
			Hashes: tufmetadata.Hashes{"sha256": bytes.Repeat([]byte{0xCD}, 32)},
		}
		return &newExpires, nil
	})
	require.NoError(t, err)

	got, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	require.Contains(t, got.Signed.Targets, "foo/bar")
	assert.Equal(t, int64(7), got.Signed.Targets["foo/bar"].Length)
	assert.True(t, newExpires.Equal(got.Signed.Expires))

	// Sign must process the dirtied role -- version bumps and the new
	// signatures verify against root.
	_, err = tx.Sign(ctx, bs.store)
	require.NoError(t, err)
	signed, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	assert.Greater(t, signed.Signed.Version, origVersion,
		"targets version must bump after Sign since BumpExpiry dirtied the role")
	assertRootDelegates(ctx, t, tx, tufmetadata.TARGETS, signed)
}

// A nil expiryFn must drive the default per-role expiry via tx.expiry's
// dispatch -- each core role gets its own default, and delegated targets
// fall through to DefaultTargetsExpiry.
func TestBumpExpiry_NilClosureAppliesDefaultForAllRoles(t *testing.T) {
	for _, tc := range []struct {
		roleName string
		want     time.Duration
	}{
		{tufmetadata.ROOT, tufrepo.DefaultRootExpiry},
		{tufmetadata.TIMESTAMP, tufrepo.DefaultTimestampExpiry},
		{tufmetadata.SNAPSHOT, tufrepo.DefaultSnapshotExpiry},
		{tufmetadata.TARGETS, tufrepo.DefaultTargetsExpiry},
		{"my-delegation", tufrepo.DefaultTargetsExpiry},
	} {
		t.Run(tc.roleName, func(t *testing.T) {
			ctx := context.Background()
			bs := bootstrapRepo(t, withDelegation("my-delegation"))

			tx, err := bs.repo.TxnStart(ctx)
			require.NoError(t, err)

			require.NoError(t, tx.BumpExpiry(ctx, tc.roleName, nil))

			got, err := tx.RoleData(ctx, tc.roleName)
			require.NoError(t, err)
			want := tx.RefTime.Add(tc.want)
			assert.True(t, want.Equal(tufrepo.SignedExpires(t, got)),
				"expiry should be RefTime + %v = %v, got %v",
				tc.want, want, tufrepo.SignedExpires(t, got))
		})
	}
}

// The "unconditional" half of the nil-closure contract: even when the current
// expiry is farther in the future than RefTime + default, nil still clobbers
// it. The internal bumpExpiries closure guards against shortening; this path
// intentionally does not.
func TestBumpExpiry_NilClosureOverwritesFutureExpiry(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	// Strictly farther than RefTime+default so nil must shorten, independent
	// of what DefaultTargetsExpiry happens to be set to today.
	farFuture := tx.RefTime.Add(2 * tufrepo.DefaultTargetsExpiry)
	err = tx.BumpExpiry(ctx, tufmetadata.TARGETS, func(time.Time, any) (*time.Time, error) {
		return &farFuture, nil
	})
	require.NoError(t, err)

	require.NoError(t, tx.BumpExpiry(ctx, tufmetadata.TARGETS, nil))

	got, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	want := tx.RefTime.Add(tufrepo.DefaultTargetsExpiry)
	assert.True(t, want.Equal(got.Signed.Expires),
		"nil closure should overwrite far-future %v with %v, got %v",
		farFuture, want, got.Signed.Expires)
}

// The mirror case: a nil return discards every modification the closure made
// to the role data, not just the expiry.
func TestBumpExpiry_DiscardsClosureMutationsOnNilReturn(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	err = tx.BumpExpiry(ctx, tufmetadata.TARGETS, func(_ time.Time, roleData any) (*time.Time, error) {
		targets := roleData.(*tufmetadata.Metadata[tufmetadata.TargetsType]) //nolint:forcetypeassert // tx.RoleData guarantees this type for TARGETS
		targets.Signed.Targets = map[string]*tufmetadata.TargetFiles{
			"ghost": {Length: 1},
		}
		return nil, nil //nolint:nilnil // nil indicates no change needed
	})
	require.NoError(t, err)

	got, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	assert.NotContains(t, got.Signed.Targets, "ghost")
}

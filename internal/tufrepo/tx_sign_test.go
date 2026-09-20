//go:build insecure

// Copyright (C) 2026 Amutable GmbH

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

// TestSign_RejectsInvalidatedTransaction pins the explicit tx.valid()
// guard at the top of Sign: a poisoned transaction must surface the
// poison verbatim before any of the signing-flow side effects run. We
// stage the same dirty-root setup as TestSign_DirtyRootRotatesTimestampKey
// (which would otherwise drive bumpRevisions, rotateRoleKeys, and
// signRole into mutating tx.newRoot) and then poison the tx -- Sign
// must short-circuit, leaving the root byte-identical to its
// post-UpdateRoleData state.
func TestSign_RejectsInvalidatedTransaction(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	// Dirty-root setup that would otherwise trigger version bump,
	// timestamp-key rotation, and re-signing of the root inside Sign.
	oldRoot, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	oldRoot.Signed.Expires = oldRoot.Signed.Expires.Add(24 * time.Hour)
	oldRoot.Signatures = nil
	require.NoError(t, tx.UpdateRoleData(tufmetadata.ROOT, oldRoot))

	// Snapshot of the root the moment Sign sees it; on a refused Sign
	// every field below must be unchanged.
	preSign, err := tx.RootRoleData(ctx)
	require.NoError(t, err)

	boom := errors.New("poison")
	err = tx.Apply(ctx, tufrepo.NewTxnOp("poison", func(context.Context, *tufrepo.Transaction) error {
		return boom
	}))
	require.ErrorIs(t, err, boom)

	newKeys, err := tx.Sign(ctx, bs.store)
	require.ErrorIs(t, err, boom, "Sign must surface the poison verbatim")
	assert.Nil(t, newKeys, "Sign must return no key IDs when refusing")

	// If Sign had let bumpRevisions / rotateRoleKeys / signRole run, the
	// version, timestamp KeyIDs, and signatures would all differ here.
	postSign, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	assert.Equal(t, preSign, postSign,
		"Sign must not mutate the root when refusing an invalidated transaction")
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

	orphan := tufext.DefaultTargets(time.Now().Add(time.Hour))
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

// An error returned from the closure must propagate verbatim. BumpExpiry
// is intentionally one of the methods that does not poison the tx on
// closure error -- the user can retry, or do something else.
func TestBumpExpiry_ClosureErrorPropagatesVerbatim(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	boom := errors.New("boom")
	err = tx.BumpExpiry(ctx, tufmetadata.TARGETS, func(time.Time, any) (*time.Time, error) {
		return nil, boom
	})
	require.ErrorIs(t, err, boom)

	// Tx must remain usable -- a noop Apply must not surface the boom.
	err = tx.Apply(ctx, tufrepo.NewTxnOp("noop", func(context.Context, *tufrepo.Transaction) error {
		return nil
	}))
	require.NoError(t, err, "BumpExpiry closure error must not poison the transaction")

	// And a fresh BumpExpiry call must run normally.
	var ran bool
	err = tx.BumpExpiry(ctx, tufmetadata.TARGETS, func(time.Time, any) (*time.Time, error) {
		ran = true
		return nil, nil //nolint:nilnil // nil indicates no change needed
	})
	require.NoError(t, err)
	assert.True(t, ran, "follow-up BumpExpiry closure must run")
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
		targets := roleData.(*tufext.SignedTargets) //nolint:forcetypeassert // tx.RoleData guarantees this type for TARGETS
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

// A nil expiryFn must drive the default per-role expiry via tx.ExpiresAfter's
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
		targets := roleData.(*tufext.SignedTargets) //nolint:forcetypeassert // tx.RoleData guarantees this type for TARGETS
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

// ----- SetExpiresAfter -----------------------------------------------------

// ExpiresAfter is the read side of SetExpiresAfter: it reports the package
// default for every role kind on a fresh transaction (including roles the
// transaction has never heard of), then tracks per-role overrides and the ""
// form.
func TestExpiresAfter_TracksSetExpireAfter(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t, withDelegation("my-delegation"))

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	defaults := map[string]time.Duration{
		tufmetadata.ROOT:      tufrepo.DefaultRootExpiry,
		tufmetadata.TIMESTAMP: tufrepo.DefaultTimestampExpiry,
		tufmetadata.SNAPSHOT:  tufrepo.DefaultSnapshotExpiry,
		tufmetadata.TARGETS:   tufrepo.DefaultTargetsExpiry,
		"my-delegation":       tufrepo.DefaultTargetsExpiry,
		"not-in-transaction":  tufrepo.DefaultTargetsExpiry,
	}
	for roleName, want := range defaults {
		assert.Equal(t, want, tx.ExpiresAfter(roleName), "default expiry for %s", roleName)
	}

	const override = 99 * time.Hour
	require.NoError(t, tx.SetExpiresAfter(tufmetadata.SNAPSHOT, override))
	assert.Equal(t, override, tx.ExpiresAfter(tufmetadata.SNAPSHOT))
	assert.Equal(t, tufrepo.DefaultTimestampExpiry, tx.ExpiresAfter(tufmetadata.TIMESTAMP),
		"override must not leak to other roles")

	const all = 5 * time.Hour
	require.NoError(t, tx.SetExpiresAfter("", all))
	for roleName := range defaults {
		assert.Equal(t, all, tx.ExpiresAfter(roleName), "expiry for %s after the all-roles form", roleName)
	}
}

// SetExpiresAfter feeds tx.ExpiresAfter, so a nil-closure BumpExpiry is the
// most direct probe of a role's currently-configured expiry. A per-role
// override must only move the named role -- a sibling keeps its own default.
func TestSetExpiresAfter_OverridesOnlyNamedRole(t *testing.T) {
	const override = 99 * time.Hour
	for _, tc := range []struct {
		roleName, sibling string
		siblingWant       time.Duration
	}{
		{tufmetadata.ROOT, tufmetadata.TIMESTAMP, tufrepo.DefaultTimestampExpiry},
		{tufmetadata.TIMESTAMP, tufmetadata.SNAPSHOT, tufrepo.DefaultSnapshotExpiry},
		{tufmetadata.SNAPSHOT, tufmetadata.TARGETS, tufrepo.DefaultTargetsExpiry},
		{tufmetadata.TARGETS, "my-delegation", tufrepo.DefaultTargetsExpiry},
		{"my-delegation", tufmetadata.TARGETS, tufrepo.DefaultTargetsExpiry},
	} {
		t.Run(tc.roleName, func(t *testing.T) {
			ctx := context.Background()
			bs := bootstrapRepo(t, withDelegation("my-delegation"))

			tx, err := bs.repo.TxnStart(ctx)
			require.NoError(t, err)
			require.NoError(t, tx.SetExpiresAfter(tc.roleName, override))

			require.NoError(t, tx.BumpExpiry(ctx, tc.roleName, nil))
			got, err := tx.RoleData(ctx, tc.roleName)
			require.NoError(t, err)
			want := tx.RefTime.Add(override)
			assert.True(t, want.Equal(tufrepo.SignedExpires(t, got)),
				"%s expiry should be RefTime + %v = %v, got %v",
				tc.roleName, override, want, tufrepo.SignedExpires(t, got))

			require.NoError(t, tx.BumpExpiry(ctx, tc.sibling, nil))
			gotSibling, err := tx.RoleData(ctx, tc.sibling)
			require.NoError(t, err)
			wantSibling := tx.RefTime.Add(tc.siblingWant)
			assert.True(t, wantSibling.Equal(tufrepo.SignedExpires(t, gotSibling)),
				"%s expiry should keep its default RefTime + %v = %v, got %v",
				tc.sibling, tc.siblingWant, wantSibling, tufrepo.SignedExpires(t, gotSibling))
		})
	}
}

// The "" form is the only way to reach delegated roles a caller cannot
// enumerate, so it must wipe every per-role override (core and delegated
// alike) and make all roles fall through to the new fallback.
func TestSetExpiresAfter_AllRolesClearsEveryOverride(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t, withDelegation("my-delegation"))

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)
	require.NoError(t, tx.SetExpiresAfter(tufmetadata.SNAPSHOT, 5*time.Hour))
	require.NoError(t, tx.SetExpiresAfter("my-delegation", 7*time.Hour))

	const all = 99 * time.Hour
	require.NoError(t, tx.SetExpiresAfter("", all))

	want := tx.RefTime.Add(all)
	for _, roleName := range []string{
		tufmetadata.ROOT, tufmetadata.TIMESTAMP, tufmetadata.SNAPSHOT,
		tufmetadata.TARGETS, "my-delegation",
	} {
		require.NoError(t, tx.BumpExpiry(ctx, roleName, nil))
		got, err := tx.RoleData(ctx, roleName)
		require.NoError(t, err)
		assert.True(t, want.Equal(tufrepo.SignedExpires(t, got)),
			"%s expiry should be RefTime + %v = %v, got %v",
			roleName, all, want, tufrepo.SignedExpires(t, got))
	}
}

// A per-role override set after the "" form layers on top of the new
// fallback rather than being discarded by it.
func TestSetExpiresAfter_RoleOverrideAfterAllRoles(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t, withDelegation("my-delegation"))

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	const all, tsOnly = 99 * time.Hour, 3 * time.Hour
	require.NoError(t, tx.SetExpiresAfter("", all))
	require.NoError(t, tx.SetExpiresAfter(tufmetadata.TIMESTAMP, tsOnly))

	for roleName, after := range map[string]time.Duration{
		tufmetadata.TIMESTAMP: tsOnly,
		tufmetadata.SNAPSHOT:  all,
		"my-delegation":       all,
	} {
		require.NoError(t, tx.BumpExpiry(ctx, roleName, nil))
		got, err := tx.RoleData(ctx, roleName)
		require.NoError(t, err)
		want := tx.RefTime.Add(after)
		assert.True(t, want.Equal(tufrepo.SignedExpires(t, got)),
			"%s expiry should be RefTime + %v = %v, got %v",
			roleName, after, want, tufrepo.SignedExpires(t, got))
	}
}

// Non-positive durations would produce metadata that is expired the moment
// it is signed, so SetExpiresAfter must reject them -- and must do so before
// touching any state, so that a rejected "" call does not wipe overrides
// that were already configured.
func TestSetExpiresAfter_RejectsNonPositive(t *testing.T) {
	for _, after := range []time.Duration{0, -time.Hour} {
		t.Run(after.String(), func(t *testing.T) {
			ctx := context.Background()
			bs := bootstrapRepo(t, withDelegation("my-delegation"))

			tx, err := bs.repo.TxnStart(ctx)
			require.NoError(t, err)

			const override = 99 * time.Hour
			require.NoError(t, tx.SetExpiresAfter("my-delegation", override))

			for _, roleName := range []string{tufmetadata.SNAPSHOT, "my-delegation", ""} {
				require.Error(t, tx.SetExpiresAfter(roleName, after))
			}

			// The delegated override survives and snapshot keeps its default.
			require.NoError(t, tx.BumpExpiry(ctx, "my-delegation", nil))
			got, err := tx.RoleData(ctx, "my-delegation")
			require.NoError(t, err)
			want := tx.RefTime.Add(override)
			assert.True(t, want.Equal(tufrepo.SignedExpires(t, got)),
				"delegated override should survive rejected calls: want %v, got %v",
				want, tufrepo.SignedExpires(t, got))

			require.NoError(t, tx.BumpExpiry(ctx, tufmetadata.SNAPSHOT, nil))
			gotSnap, err := tx.RoleData(ctx, tufmetadata.SNAPSHOT)
			require.NoError(t, err)
			wantSnap := tx.RefTime.Add(tufrepo.DefaultSnapshotExpiry)
			assert.True(t, wantSnap.Equal(tufrepo.SignedExpires(t, gotSnap)),
				"snapshot should keep its default: want %v, got %v",
				wantSnap, tufrepo.SignedExpires(t, gotSnap))
		})
	}
}

// Sign's bumpExpiries path must honour a per-role override when it re-signs
// a dirty role, while the snapshot/timestamp cascade keeps using their own
// (untouched) defaults -- the override must not leak across roles.
func TestSign_SetExpiresAfterAppliesToDirtyRole(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t, withDelegation("a"))

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	// Longer than the bootstrap expiry so the no-shortening guard in
	// bumpExpiries cannot mask the override.
	override := 3 * tufrepo.DefaultTargetsExpiry
	require.NoError(t, tx.SetExpiresAfter(tufmetadata.TARGETS, override))
	require.NoError(t, tx.Apply(ctx, addTargetOp("foo/bar", 1)))

	origDelegated, err := tx.TargetsRoleData(ctx, "a")
	require.NoError(t, err)

	_, err = tx.Sign(ctx, bs.store)
	require.NoError(t, err)

	afterTargets, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	wantTargets := tx.RefTime.Add(override)
	assert.True(t, wantTargets.Equal(afterTargets.Signed.Expires),
		"targets expiry should be RefTime + %v = %v, got %v",
		override, wantTargets, afterTargets.Signed.Expires)

	afterSnap, err := tx.SnapshotRoleData(ctx)
	require.NoError(t, err)
	wantSnap := tx.RefTime.Add(tufrepo.DefaultSnapshotExpiry)
	assert.True(t, wantSnap.Equal(afterSnap.Signed.Expires),
		"snapshot should keep its default expiry %v, got %v",
		wantSnap, afterSnap.Signed.Expires)

	afterTs, err := tx.TimestampRoleData(ctx)
	require.NoError(t, err)
	wantTs := tx.RefTime.Add(tufrepo.DefaultTimestampExpiry)
	assert.True(t, wantTs.Equal(afterTs.Signed.Expires),
		"timestamp should keep its default expiry %v, got %v",
		wantTs, afterTs.Signed.Expires)

	// Neither dirty nor inside the refresh window: untouched.
	afterDelegated, err := tx.TargetsRoleData(ctx, "a")
	require.NoError(t, err)
	assert.True(t, origDelegated.Signed.Expires.Equal(afterDelegated.Signed.Expires))
	assert.Equal(t, origDelegated.Signatures, afterDelegated.Signatures)
}

// The updateSnapshot/updateTimestamp cascade must honour overrides for those
// two roles. Unlike bumpExpiries this path has no no-shortening guard, so a
// shorter-than-default override is applied verbatim -- which is what
// `hardhat repoctl snapshot --expire-after` relies on.
func TestSign_SetExpiresAfterAppliesToSnapshotAndTimestampCascade(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	const snapAfter, tsAfter = 2 * time.Hour, time.Hour
	require.NoError(t, tx.SetExpiresAfter(tufmetadata.SNAPSHOT, snapAfter))
	require.NoError(t, tx.SetExpiresAfter(tufmetadata.TIMESTAMP, tsAfter))

	origSnap, err := tx.SnapshotRoleData(ctx)
	require.NoError(t, err)

	require.NoError(t, tx.Apply(ctx, addTargetOp("foo/bar", 1)))
	_, err = tx.Sign(ctx, bs.store)
	require.NoError(t, err)

	afterSnap, err := tx.SnapshotRoleData(ctx)
	require.NoError(t, err)
	wantSnap := tx.RefTime.Add(snapAfter)
	assert.True(t, wantSnap.Equal(afterSnap.Signed.Expires),
		"snapshot expiry should be RefTime + %v = %v, got %v",
		snapAfter, wantSnap, afterSnap.Signed.Expires)
	assert.True(t, afterSnap.Signed.Expires.Before(origSnap.Signed.Expires),
		"sanity: the override must actually have shortened the snapshot expiry")
	assertRootDelegates(ctx, t, tx, tufmetadata.SNAPSHOT, afterSnap)

	afterTs, err := tx.TimestampRoleData(ctx)
	require.NoError(t, err)
	wantTs := tx.RefTime.Add(tsAfter)
	assert.True(t, wantTs.Equal(afterTs.Signed.Expires),
		"timestamp expiry should be RefTime + %v = %v, got %v",
		tsAfter, wantTs, afterTs.Signed.Expires)
	assertRootDelegates(ctx, t, tx, tufmetadata.TIMESTAMP, afterTs)
}

// bumpExpiries keeps its no-shortening guard even under an override: a dirty
// targets role whose configured expiry would land before its current one is
// re-signed with the current expiry left alone.
func TestSign_SetExpiresAfterCannotShortenViaBumpExpiries(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)
	require.NoError(t, tx.SetExpiresAfter(tufmetadata.TARGETS, time.Hour))

	origTargets, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)

	require.NoError(t, tx.Apply(ctx, addTargetOp("foo/bar", 1)))
	_, err = tx.Sign(ctx, bs.store)
	require.NoError(t, err)

	afterTargets, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	assert.Greater(t, afterTargets.Signed.Version, origTargets.Signed.Version,
		"targets was dirty and must still be re-signed")
	assert.True(t, origTargets.Signed.Expires.Equal(afterTargets.Signed.Expires),
		"targets expiry must not be shortened: want %v, got %v",
		origTargets.Signed.Expires, afterTargets.Signed.Expires)
}

// The "" form must reach delegated roles through Sign itself, not only via
// BumpExpiry. With a refresh window wide enough to auto-refresh every
// non-root role, all of them must land on RefTime + the shared expiry.
func TestSign_SetExpiresAfterAllRolesAppliesToAutoRefresh(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t, withDelegation("a"))

	withRefreshWindow(t, 2*tufrepo.DefaultTargetsExpiry)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	all := 3 * tufrepo.DefaultTargetsExpiry
	require.NoError(t, tx.SetExpiresAfter("", all))

	origRoot, err := tx.RootRoleData(ctx)
	require.NoError(t, err)

	_, err = tx.Sign(ctx, bs.store)
	require.NoError(t, err)

	want := tx.RefTime.Add(all)
	for _, roleName := range []string{
		tufmetadata.TIMESTAMP, tufmetadata.SNAPSHOT, tufmetadata.TARGETS, "a",
	} {
		got, err := tx.RoleData(ctx, roleName)
		require.NoError(t, err)
		assert.True(t, want.Equal(tufrepo.SignedExpires(t, got)),
			"%s expiry should be RefTime + %v = %v, got %v",
			roleName, all, want, tufrepo.SignedExpires(t, got))
	}

	// Root is two years out and so outside even this window: untouched.
	afterRoot, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	assert.True(t, origRoot.Signed.Expires.Equal(afterRoot.Signed.Expires))
	assert.Equal(t, origRoot.Signatures, afterRoot.Signatures)
}

// ----- bumpExpiries auto-refresh ---------------------------------------

// Snapshot/timestamp assertions here are correctness checks, not isolation
// pins -- they would also move via the updateSnapshot/updateTimestamp
// cascade. See TestSign_AutoRefreshTimestampOnly_NoCascade for isolation.
func TestSign_AutoRefreshesSoonToExpireRoles(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t, withDelegation("a"))

	withRefreshWindow(t, 2*tufrepo.DefaultTargetsExpiry)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	origRoot, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	origTargets, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	origDelegated, err := tx.TargetsRoleData(ctx, "a")
	require.NoError(t, err)
	origSnap, err := tx.SnapshotRoleData(ctx)
	require.NoError(t, err)
	origTs, err := tx.TimestampRoleData(ctx)
	require.NoError(t, err)

	newKeys, err := tx.Sign(ctx, bs.store)
	require.NoError(t, err)
	assert.Empty(t, newKeys)

	afterTargets, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	assert.Greater(t, afterTargets.Signed.Version, origTargets.Signed.Version)
	assert.True(t, afterTargets.Signed.Expires.After(origTargets.Signed.Expires))
	assertRootDelegates(ctx, t, tx, tufmetadata.TARGETS, afterTargets)

	afterDelegated, err := tx.TargetsRoleData(ctx, "a")
	require.NoError(t, err)
	assert.Greater(t, afterDelegated.Signed.Version, origDelegated.Signed.Version)
	assert.True(t, afterDelegated.Signed.Expires.After(origDelegated.Signed.Expires))
	require.NoError(t, afterTargets.VerifyDelegate("a", afterDelegated))

	afterSnap, err := tx.SnapshotRoleData(ctx)
	require.NoError(t, err)
	assert.Greater(t, afterSnap.Signed.Version, origSnap.Signed.Version)
	assert.True(t, afterSnap.Signed.Expires.After(origSnap.Signed.Expires))
	assertRootDelegates(ctx, t, tx, tufmetadata.SNAPSHOT, afterSnap)

	afterTs, err := tx.TimestampRoleData(ctx)
	require.NoError(t, err)
	assert.Greater(t, afterTs.Signed.Version, origTs.Signed.Version)
	assert.True(t, afterTs.Signed.Expires.After(origTs.Signed.Expires))
	assertRootDelegates(ctx, t, tx, tufmetadata.TIMESTAMP, afterTs)

	afterRoot, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	assert.Equal(t, origRoot.Signed.Version, afterRoot.Signed.Version)
	assert.True(t, origRoot.Signed.Expires.Equal(afterRoot.Signed.Expires))
	assert.Equal(t, origRoot.Signatures, afterRoot.Signatures)
}

// Window covers timestamp (~30h) but excludes the ~174h targets/snapshot/
// delegated roles, so the cascade through updateSnapshot/updateTimestamp
// does not fire and timestamp must move solely via bumpExpiries.
func TestSign_AutoRefreshTimestampOnly_NoCascade(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t, withDelegation("a"))

	withRefreshWindow(t, tufrepo.DefaultTimestampExpiry+12*time.Hour)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	origTargets, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	origDelegated, err := tx.TargetsRoleData(ctx, "a")
	require.NoError(t, err)
	origSnap, err := tx.SnapshotRoleData(ctx)
	require.NoError(t, err)
	origTs, err := tx.TimestampRoleData(ctx)
	require.NoError(t, err)

	_, err = tx.Sign(ctx, bs.store)
	require.NoError(t, err)

	afterTs, err := tx.TimestampRoleData(ctx)
	require.NoError(t, err)
	assert.Greater(t, afterTs.Signed.Version, origTs.Signed.Version)
	assert.True(t, afterTs.Signed.Expires.After(origTs.Signed.Expires))
	assertRootDelegates(ctx, t, tx, tufmetadata.TIMESTAMP, afterTs)

	afterTargets, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	assert.Equal(t, origTargets.Signed.Version, afterTargets.Signed.Version)
	assert.Equal(t, origTargets.Signatures, afterTargets.Signatures)

	afterDelegated, err := tx.TargetsRoleData(ctx, "a")
	require.NoError(t, err)
	assert.Equal(t, origDelegated.Signed.Version, afterDelegated.Signed.Version)
	assert.Equal(t, origDelegated.Signatures, afterDelegated.Signatures)

	afterSnap, err := tx.SnapshotRoleData(ctx)
	require.NoError(t, err)
	assert.Equal(t, origSnap.Signed.Version, afterSnap.Signed.Version)
	assert.Equal(t, origSnap.Signatures, afterSnap.Signatures)
}

// Roles just outside the window must not be touched.
func TestSign_NoAutoRefreshOutsideWindow(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t, withDelegation("a"))

	withRefreshWindow(t, tufrepo.DefaultTargetsExpiry-1*time.Hour)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	origTargets, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	origDelegated, err := tx.TargetsRoleData(ctx, "a")
	require.NoError(t, err)
	origSnap, err := tx.SnapshotRoleData(ctx)
	require.NoError(t, err)

	_, err = tx.Sign(ctx, bs.store)
	require.NoError(t, err)

	afterTargets, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	assert.Equal(t, origTargets.Signed.Version, afterTargets.Signed.Version)
	assert.Equal(t, origTargets.Signatures, afterTargets.Signatures)

	afterDelegated, err := tx.TargetsRoleData(ctx, "a")
	require.NoError(t, err)
	assert.Equal(t, origDelegated.Signed.Version, afterDelegated.Signed.Version)
	assert.Equal(t, origDelegated.Signatures, afterDelegated.Signatures)

	afterSnap, err := tx.SnapshotRoleData(ctx)
	require.NoError(t, err)
	assert.Equal(t, origSnap.Signed.Version, afterSnap.Signed.Version)
	assert.Equal(t, origSnap.Signatures, afterSnap.Signatures)
}

// `oldExpiry.Sub(tx.RefTime) <= window` includes negative durations, so an
// already-expired role auto-refreshes even under the default 6h window.
func TestSign_AutoRefreshFiresOnAlreadyExpiredRole(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t, withDelegation("a"))

	rewriteDelegatedExpiry(ctx, t, bs, "a", time.Now().Add(-1*time.Hour).UTC())

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	origDelegated, err := tx.TargetsRoleData(ctx, "a")
	require.NoError(t, err)
	require.True(t, origDelegated.Signed.Expires.Before(tx.RefTime))

	_, err = tx.Sign(ctx, bs.store)
	require.NoError(t, err)

	afterDelegated, err := tx.TargetsRoleData(ctx, "a")
	require.NoError(t, err)
	assert.True(t, afterDelegated.Signed.Expires.After(tx.RefTime))
	assert.Greater(t, afterDelegated.Signed.Version, origDelegated.Signed.Version)
	afterTargets, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	require.NoError(t, afterTargets.VerifyDelegate("a", afterDelegated))
}

// canSignRole gates auto-refresh per role: the unsignable role stays put,
// in-window peers still refresh.
func TestSign_AutoRefreshSkippedWhenSigningKeyMissing(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t, withDelegation("a"))

	delegatedID, err := bs.delegatedKeys["a"].ID()
	require.NoError(t, err)
	require.NoError(t, bs.store.UnlinkKey(ctx, delegatedID))

	withRefreshWindow(t, 2*tufrepo.DefaultTargetsExpiry)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	origDelegated, err := tx.TargetsRoleData(ctx, "a")
	require.NoError(t, err)
	origTargets, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)

	_, err = tx.Sign(ctx, bs.store)
	require.NoError(t, err)

	afterDelegated, err := tx.TargetsRoleData(ctx, "a")
	require.NoError(t, err)
	assert.Equal(t, origDelegated.Signed.Version, afterDelegated.Signed.Version)
	assert.True(t, origDelegated.Signed.Expires.Equal(afterDelegated.Signed.Expires))
	assert.Equal(t, origDelegated.Signatures, afterDelegated.Signatures)

	// Other in-window roles still refresh -- skip is per-role, not whole-pass.
	afterTargets, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	assert.Greater(t, afterTargets.Signed.Version, origTargets.Signed.Version)
}

// canSignRole is bypassed on the dirty path: a dirty role with a missing key
// still triggers Sign to attempt (and fail at) signRole.
func TestSign_DirtyRoleBypassesKeyAvailabilityCheck(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	targetsID, err := bs.targetsKey.ID()
	require.NoError(t, err)
	require.NoError(t, bs.store.UnlinkKey(ctx, targetsID))

	withRefreshWindow(t, 2*tufrepo.DefaultTargetsExpiry)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)
	require.NoError(t, tx.Apply(ctx, addTargetOp("dirty/me", 1)))

	_, err = tx.Sign(ctx, bs.store)
	require.Error(t, err)
}

// Pins the no-shortening guard at tx_sign.go:586-588.
func TestSign_DoesNotShortenFarFutureExpiry(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	farFuture := tx.RefTime.Add(2 * tufrepo.DefaultTargetsExpiry)
	require.NoError(t, tx.BumpExpiry(ctx, tufmetadata.TARGETS,
		func(time.Time, any) (*time.Time, error) { return &farFuture, nil }))

	_, err = tx.Sign(ctx, bs.store)
	require.NoError(t, err)

	got, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
	require.NoError(t, err)
	assert.True(t, farFuture.Equal(got.Signed.Expires))
}

// Auto-refreshing root falls into the existing isDirty(ROOT) branch and
// rotates the timestamp keys -- the in-tree comment in tx_sign.go marks this
// as deliberate-for-now.
func TestSign_AutoRefreshOfRootRotatesTimestampKey(t *testing.T) {
	ctx := context.Background()
	bs := bootstrapRepo(t)

	withRefreshWindow(t, 3*tufrepo.DefaultRootExpiry)

	tx, err := bs.repo.TxnStart(ctx)
	require.NoError(t, err)

	origRoot, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	origTimestampKeyIDs := append([]string(nil), origRoot.Signed.Roles[tufmetadata.TIMESTAMP].KeyIDs...)

	newKeys, err := tx.Sign(ctx, bs.store)
	require.NoError(t, err)
	assert.NotEmpty(t, newKeys)

	afterRoot, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	assert.Greater(t, afterRoot.Signed.Version, origRoot.Signed.Version)
	newTimestampKeyIDs := afterRoot.Signed.Roles[tufmetadata.TIMESTAMP].KeyIDs
	assert.NotEqual(t, origTimestampKeyIDs, newTimestampKeyIDs)

	wantIDs := make([]string, len(newKeys))
	for i, id := range newKeys {
		wantIDs[i] = string(id)
	}
	assert.ElementsMatch(t, newTimestampKeyIDs, wantIDs)

	assertRootDelegates(ctx, t, tx, tufmetadata.ROOT, afterRoot)
	afterTs, err := tx.TimestampRoleData(ctx)
	require.NoError(t, err)
	assertRootDelegates(ctx, t, tx, tufmetadata.TIMESTAMP, afterTs)
}

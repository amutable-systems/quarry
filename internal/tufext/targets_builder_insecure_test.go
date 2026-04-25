//go:build insecure

// Copyright (C) 2026 Amutable GmbH

package tufext_test

import (
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/keystore"
	_ "go.amutable.dev/quarry/internal/keystore/insecure"
	"go.amutable.dev/quarry/internal/tufext"
)

// fixedRefTime is an arbitrary historical reference point used by tests that
// want a stable Version/Expires.
var fixedRefTime = time.Date(2020, 1, 1, 12, 0, 0, 0, time.UTC)

func TestTargetsBuilder_SignWith_Basic(t *testing.T) {
	ctx, store := openTestStore(t)
	key, keyID := generateInStore(ctx, t, store)

	builder := tufext.NewTargetsBuilder()
	_, err := builder.AddTargetFile("foo.txt", 5, digest.SHA256.FromBytes([]byte("hello")))
	require.NoError(t, err)

	meta, err := builder.SignWith(ctx, store, key)
	require.NoError(t, err)
	require.NotNil(t, meta)

	// Signed by the provided key -- verify via go-tuf's VerifyDelegate.
	require.Len(t, meta.Signatures, 1)
	assert.Equal(t, keyID, meta.Signatures[0].KeyID)
	verifyTUFSignature(t, tufmetadata.TARGETS, key, meta)
}

func TestTargetsBuilder_SignWith_VersionAndExpiry(t *testing.T) {
	// When Version/Expires are left at their zero values, SignWith fills them
	// from RefTime and ExpireAfter. When the caller has explicitly set either
	// field via TargetsType(), SignWith leaves that value alone.
	ctx, store := openTestStore(t)
	key, _ := generateInStore(ctx, t, store)

	expireAfter := 48 * time.Hour

	t.Run("Defaulted", func(t *testing.T) {
		builder := tufext.NewTargetsBuilder()
		builder.RefTime = fixedRefTime
		builder.ExpireAfter = expireAfter

		meta, err := builder.SignWith(ctx, store, key)
		require.NoError(t, err)

		assert.Equal(t, fixedRefTime.UnixMilli(), meta.Signed.Version)
		assert.True(t, meta.Signed.Expires.Equal(fixedRefTime.Add(expireAfter)),
			"Expires should be RefTime.Add(ExpireAfter); got %v", meta.Signed.Expires)
	})

	t.Run("ExplicitPreserved", func(t *testing.T) {
		builder := tufext.NewTargetsBuilder()
		builder.RefTime = fixedRefTime
		builder.ExpireAfter = expireAfter

		explicitVersion := int64(42)
		explicitExpires := fixedRefTime.Add(10 * 365 * 24 * time.Hour)
		inner := builder.TargetsType()
		inner.Version = explicitVersion
		inner.Expires = explicitExpires

		meta, err := builder.SignWith(ctx, store, key)
		require.NoError(t, err)

		assert.Equal(t, explicitVersion, meta.Signed.Version)
		assert.True(t, meta.Signed.Expires.Equal(explicitExpires),
			"Expires should match the explicitly set value; got %v", meta.Signed.Expires)
	})
}

func TestTargetsBuilder_SignWith_MultipleKeys(t *testing.T) {
	ctx, store := openTestStore(t)
	k1, id1 := generateInStore(ctx, t, store)
	k2, id2 := generateInStore(ctx, t, store)

	builder := tufext.NewTargetsBuilder()
	meta, err := builder.SignWith(ctx, store, k1, k2)
	require.NoError(t, err)

	require.Len(t, meta.Signatures, 2)
	// Signatures are appended in call order.
	assert.Equal(t, id1, meta.Signatures[0].KeyID)
	assert.Equal(t, id2, meta.Signatures[1].KeyID)

	verifyTUFSignature(t, tufmetadata.TARGETS, k1, meta)
	verifyTUFSignature(t, tufmetadata.TARGETS, k2, meta)
}

func TestTargetsBuilder_SignWith_NoKeys(t *testing.T) {
	ctx, store := openTestStore(t)

	builder := tufext.NewTargetsBuilder()
	builder.RefTime = fixedRefTime
	meta, err := builder.SignWith(ctx, store)
	require.NoError(t, err)
	require.NotNil(t, meta)

	assert.Empty(t, meta.Signatures)
	// Core fields are still populated from the builder state.
	assert.Equal(t, tufmetadata.TARGETS, meta.Signed.Type)
	assert.Equal(t, fixedRefTime.UnixMilli(), meta.Signed.Version)
	assert.True(t, meta.Signed.Expires.Equal(fixedRefTime.Add(builder.ExpireAfter)))
}

func TestTargetsBuilder_SignWith_IndependentOfBuilder(t *testing.T) {
	// SignWith deep-copies the inner payload, so mutations to the returned
	// Metadata must not bleed back into the builder and vice versa. Cover both
	// Targets and Delegations in both directions.
	ctx, store := openTestStore(t)
	signingKey, _ := generateInStore(ctx, t, store)
	delegKey, _ := generateInStore(ctx, t, store)

	builder := tufext.NewTargetsBuilder()
	_, err := builder.AddTargetFile("a.bin", 1, digest.SHA256.FromBytes([]byte("a")))
	require.NoError(t, err)
	role, err := builder.AddDelegation("delegated", 1, delegKey.Public)
	require.NoError(t, err)
	role.Paths = []string{"delegated/*"}

	meta, err := builder.SignWith(ctx, store, signingKey)
	require.NoError(t, err)
	require.Len(t, meta.Signed.Targets, 1)
	require.NotNil(t, meta.Signed.Delegations)
	require.Len(t, meta.Signed.Delegations.Roles, 1)

	// (1) Mutations to the returned metadata do not bleed into the builder:
	// add a target, rewrite the delegated role's Paths, and append a new
	// delegated role entirely.
	meta.Signed.Targets["b.bin"] = &tufmetadata.TargetFiles{Length: 2}
	meta.Signed.Delegations.Roles[0].Paths = []string{"modified/*"}
	meta.Signed.Delegations.Roles = append(meta.Signed.Delegations.Roles, tufmetadata.DelegatedRole{
		Name: "extra", KeyIDs: []string{}, Threshold: 1,
	})

	inner := builder.TargetsType()
	assert.Len(t, inner.Targets, 1)
	assert.NotContains(t, inner.Targets, "b.bin")
	require.Len(t, inner.Delegations.Roles, 1)
	assert.Equal(t, []string{"delegated/*"}, inner.Delegations.Roles[0].Paths)

	// (2) Mutations to the builder do not bleed into the already-signed
	// metadata: add a new target and a new delegation.
	_, err = builder.AddTargetFile("c.bin", 3, digest.SHA256.FromBytes([]byte("c")))
	require.NoError(t, err)
	newDelegKey, _ := generateInStore(ctx, t, store)
	_, err = builder.AddDelegation("new-role", 1, newDelegKey.Public)
	require.NoError(t, err)

	assert.NotContains(t, meta.Signed.Targets, "c.bin")
	for _, r := range meta.Signed.Delegations.Roles {
		assert.NotEqual(t, "new-role", r.Name)
	}
}

func TestTargetsBuilder_SignWith_SequentialSigns(t *testing.T) {
	// SignWith can be called repeatedly on the same builder: each result
	// reflects the builder's state at that moment, and earlier results are not
	// mutated by later builder changes. Also serves as a regression guard that
	// the Delegations.Roles slice doesn't grow spuriously across signs (e.g.
	// if TargetsType appended to the existing slice rather than rebuilding
	// it).
	ctx, store := openTestStore(t)
	key, _ := generateInStore(ctx, t, store)
	delegKey, delegID := generateInStore(ctx, t, store)

	builder := tufext.NewTargetsBuilder()
	_, err := builder.AddTargetFile("a.bin", 1, digest.SHA256.FromBytes([]byte("a")))
	require.NoError(t, err)
	_, err = builder.AddDelegation("alpha", 1, delegKey.Public)
	require.NoError(t, err)

	first, err := builder.SignWith(ctx, store, key)
	require.NoError(t, err)
	require.Len(t, first.Signed.Targets, 1)
	require.Len(t, first.Signed.Delegations.Roles, 1)

	_, err = builder.AddTargetFile("b.bin", 2, digest.SHA256.FromBytes([]byte("b")))
	require.NoError(t, err)

	second, err := builder.SignWith(ctx, store, key)
	require.NoError(t, err)

	// Second sign sees the new file; first sign is unchanged.
	assert.Len(t, second.Signed.Targets, 2)
	assert.Len(t, first.Signed.Targets, 1)
	assert.NotContains(t, first.Signed.Targets, "b.bin")

	// Delegations.Roles is still exactly one entry on both results.
	require.Len(t, second.Signed.Delegations.Roles, 1)
	assert.Equal(t, "alpha", second.Signed.Delegations.Roles[0].Name)
	assert.Equal(t, []string{delegID}, second.Signed.Delegations.Roles[0].KeyIDs)

	verifyTUFSignature(t, tufmetadata.TARGETS, key, first)
	verifyTUFSignature(t, tufmetadata.TARGETS, key, second)
}

func TestTargetsBuilder_SignWith_WithDelegations(t *testing.T) {
	// A signed targets with a delegated role: the delegation, its
	// KeyIDs/Paths, and the delegated key are all present in the signed
	// payload and the signature verifies.
	ctx, store := openTestStore(t)
	signingKey, _ := generateInStore(ctx, t, store)
	delegKey, delegID := generateInStore(ctx, t, store)

	builder := tufext.NewTargetsBuilder()
	role, err := builder.AddDelegation("delegated", 1, delegKey.Public)
	require.NoError(t, err)
	role.Paths = []string{"delegated/*"}

	meta, err := builder.SignWith(ctx, store, signingKey)
	require.NoError(t, err)

	require.NotNil(t, meta.Signed.Delegations)
	require.Len(t, meta.Signed.Delegations.Roles, 1)
	signed := meta.Signed.Delegations.Roles[0]
	assert.Equal(t, "delegated", signed.Name)
	assert.Equal(t, []string{delegID}, signed.KeyIDs)
	assert.Equal(t, []string{"delegated/*"}, signed.Paths)
	assert.Equal(t, 1, signed.Threshold)

	require.Len(t, meta.Signed.Delegations.Keys, 1)
	require.Contains(t, meta.Signed.Delegations.Keys, delegID)

	verifyTUFSignature(t, tufmetadata.TARGETS, signingKey, meta)
}

func TestTargetsBuilder_SignWith_FillsKeysFromStore(t *testing.T) {
	// A caller that constructs a delegated role via TargetsType() without
	// pre-populating Delegations.Keys relies on SignWith's implicit
	// FillRoleKeys step to pull the referenced key from the store.
	ctx, store := openTestStore(t)
	signingKey, _ := generateInStore(ctx, t, store)
	_, delegID := generateInStore(ctx, t, store)

	builder := tufext.NewTargetsBuilder()
	inner := builder.TargetsType()
	inner.Delegations = &tufmetadata.Delegations{
		Keys: map[string]*tufmetadata.Key{},
		Roles: []tufmetadata.DelegatedRole{
			{Name: "delegated", KeyIDs: []string{delegID}, Threshold: 1},
		},
	}

	meta, err := builder.SignWith(ctx, store, signingKey)
	require.NoError(t, err)

	require.NotNil(t, meta.Signed.Delegations)
	require.Len(t, meta.Signed.Delegations.Keys, 1)
	require.Contains(t, meta.Signed.Delegations.Keys, delegID)
	gotID, err := meta.Signed.Delegations.Keys[delegID].ID()
	require.NoError(t, err)
	assert.Equal(t, delegID, gotID)
}

func TestTargetsBuilder_SignWith_GCsUnreferencedKeys(t *testing.T) {
	// SignWith's FillRoleKeys pass also prunes keys in the top-level
	// Keys map that no delegated role references.
	ctx, store := openTestStore(t)
	signingKey, _ := generateInStore(ctx, t, store)
	refKey, refID := generateInStore(ctx, t, store)
	orphanKey, orphanID := generateInStore(ctx, t, store)

	builder := tufext.NewTargetsBuilder()
	inner := builder.TargetsType()
	inner.Delegations = &tufmetadata.Delegations{
		Keys: map[string]*tufmetadata.Key{
			refID:    &refKey.Public,
			orphanID: &orphanKey.Public,
		},
		Roles: []tufmetadata.DelegatedRole{
			{Name: "delegated", KeyIDs: []string{refID}, Threshold: 1},
		},
	}

	meta, err := builder.SignWith(ctx, store, signingKey)
	require.NoError(t, err)

	require.Len(t, meta.Signed.Delegations.Keys, 1)
	assert.Contains(t, meta.Signed.Delegations.Keys, refID)
	assert.NotContains(t, meta.Signed.Delegations.Keys, orphanID)
}

func TestTargetsBuilder_SignWith_MissingKeyInStore(t *testing.T) {
	// If a delegated role references a keyID that is neither in the
	// Delegations.Keys map nor in the store, SignWith surfaces
	// ErrNoSuchKey from its implicit FillRoleKeys pass.
	ctx, store := openTestStore(t)
	signingKey, _ := generateInStore(ctx, t, store)

	builder := tufext.NewTargetsBuilder()
	inner := builder.TargetsType()
	missingID := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	inner.Delegations = &tufmetadata.Delegations{
		Keys: map[string]*tufmetadata.Key{},
		Roles: []tufmetadata.DelegatedRole{
			{Name: "missing", KeyIDs: []string{missingID}, Threshold: 1},
		},
	}

	meta, err := builder.SignWith(ctx, store, signingKey)
	require.Error(t, err)
	assert.Nil(t, meta)
	assert.ErrorIs(t, err, keystore.ErrNoSuchKey)
}

func TestTargetsBuilder_SignWith_BadKey(t *testing.T) {
	// A signing key with an unknown driver causes SignRole to fail, and
	// SignWith returns the error without producing a partial Metadata.
	ctx, store := openTestStore(t)
	key, _ := generateInStore(ctx, t, store)
	key.Driver = "nonexistent"

	builder := tufext.NewTargetsBuilder()
	meta, err := builder.SignWith(ctx, store, key)
	require.Error(t, err)
	assert.Nil(t, meta)
}

// Copyright (C) 2026 Amutable GmbH

package tufext_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/keystore"
	"go.amutable.dev/quarry/internal/tufext"
	"go.amutable.dev/quarry/internal/tufrepo"
)

func TestNewRootBuilder(t *testing.T) {
	before := time.Now().UTC()
	builder := tufext.NewRootBuilder()
	after := time.Now().UTC()

	inner := builder.RootType()
	require.NotNil(t, inner)

	assert.Equal(t, tufmetadata.ROOT, inner.Type)
	assert.Equal(t, tufmetadata.SPECIFICATION_VERSION, inner.SpecVersion)
	assert.Equal(t, int64(1), inner.Version)
	assert.True(t, inner.ConsistentSnapshot)

	// Expires defaults to the zero time and is filled in by Sign.
	assert.True(t, inner.Expires.IsZero())

	// Keys and Roles are pre-initialised by DefaultRoot.
	assert.NotNil(t, inner.Keys)
	assert.Empty(t, inner.Keys)
	assert.NotNil(t, inner.Roles)
	assert.Empty(t, inner.Roles)

	assert.Equal(t, time.UTC, builder.RefTime.Location())
	assert.True(t, !builder.RefTime.Before(before) && !builder.RefTime.After(after),
		"RefTime %v should be between %v and %v", builder.RefTime, before, after)
	assert.Equal(t, tufrepo.DefaultRootExpiry, builder.ExpireAfter)
	assert.Equal(t, keystore.DefaultDriver, builder.GenerateKeyDriver)
}

func TestRootBuilder_AddRole(t *testing.T) {
	for _, tc := range []struct {
		name      string
		roleName  string
		threshold int
		numKeys   int
	}{
		{name: "SingleKey", roleName: tufmetadata.ROOT, threshold: 1, numKeys: 1},
		{name: "MultipleKeys", roleName: tufmetadata.TARGETS, threshold: 2, numKeys: 3},
		{name: "ThresholdEqualsKeys", roleName: tufmetadata.SNAPSHOT, threshold: 3, numKeys: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			builder := tufext.NewRootBuilder()
			keys := make([]keystore.PublicKey, 0, tc.numKeys)
			keyIDs := make([]string, 0, tc.numKeys)
			for i := 0; i < tc.numKeys; i++ {
				k := generateTestPublicKey(t)
				keys = append(keys, k)
				keyIDs = append(keyIDs, keyIDOf(t, k))
			}

			role, err := builder.AddRole(tc.roleName, tc.threshold, keys...)
			require.NoError(t, err)
			require.NotNil(t, role)

			assert.Equal(t, tc.threshold, role.Threshold)
			// KeyIDs preserve variadic-argument order.
			assert.Equal(t, keyIDs, role.KeyIDs)

			inner := builder.RootType()
			require.Len(t, inner.Roles, 1)
			assert.Same(t, role, inner.Roles[tc.roleName])
			assert.Len(t, inner.Keys, tc.numKeys)
			for _, id := range keyIDs {
				assert.Contains(t, inner.Keys, id)
			}
		})
	}
}

func TestRootBuilder_AddRole_InvalidThreshold(t *testing.T) {
	// AddRole rejects thresholds that are non-positive or that exceed the
	// number of provided keys -- a role configured this way could never be
	// satisfied on verification.
	for _, tc := range []struct {
		name      string
		threshold int
		numKeys   int
	}{
		{name: "ZeroThreshold", threshold: 0, numKeys: 1},
		{name: "NegativeThreshold", threshold: -1, numKeys: 1},
		{name: "ThresholdExceedsKeys", threshold: 2, numKeys: 1},
		{name: "EmptyKeys", threshold: 1, numKeys: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			builder := tufext.NewRootBuilder()
			keys := make([]keystore.PublicKey, 0, tc.numKeys)
			for i := 0; i < tc.numKeys; i++ {
				keys = append(keys, generateTestPublicKey(t))
			}

			role, err := builder.AddRole(tufmetadata.ROOT, tc.threshold, keys...)
			require.Error(t, err)
			assert.Nil(t, role)
			assert.ErrorContains(t, err, "threshold") //nolint:testifylint // preferable for error-path tests

			// Nothing was added to the builder.
			inner := builder.RootType()
			assert.Empty(t, inner.Roles)
			assert.Empty(t, inner.Keys)
		})
	}
}

func TestRootBuilder_AddRole_ReplacesExisting(t *testing.T) {
	// A second AddRole with the same role name replaces the first -- the new
	// role definition sticks. The top-level key map is not pruned here (that
	// happens in Sign via FillRoleKeys).
	builder := tufext.NewRootBuilder()
	k1 := generateTestPublicKey(t)
	k2 := generateTestPublicKey(t)

	first, err := builder.AddRole(tufmetadata.ROOT, 1, k1)
	require.NoError(t, err)
	second, err := builder.AddRole(tufmetadata.ROOT, 1, k2)
	require.NoError(t, err)

	assert.NotSame(t, first, second)

	inner := builder.RootType()
	require.Len(t, inner.Roles, 1)
	assert.Same(t, second, inner.Roles[tufmetadata.ROOT])
	assert.Equal(t, []string{keyIDOf(t, k2)}, inner.Roles[tufmetadata.ROOT].KeyIDs)
}

func TestRootBuilder_AddRole_SharedKeyAcrossRoles(t *testing.T) {
	// A key referenced by multiple roles is deduplicated in the top-level
	// Keys map but remains referenced by each role's KeyIDs slice.
	builder := tufext.NewRootBuilder()
	shared := generateTestPublicKey(t)
	other := generateTestPublicKey(t)
	sharedID := keyIDOf(t, shared)
	otherID := keyIDOf(t, other)

	_, err := builder.AddRole(tufmetadata.ROOT, 1, shared, other)
	require.NoError(t, err)
	_, err = builder.AddRole(tufmetadata.TARGETS, 1, shared)
	require.NoError(t, err)

	inner := builder.RootType()
	assert.Len(t, inner.Keys, 2)
	assert.Contains(t, inner.Keys, sharedID)
	assert.Contains(t, inner.Keys, otherID)

	assert.Equal(t, []string{sharedID, otherID}, inner.Roles[tufmetadata.ROOT].KeyIDs)
	assert.Equal(t, []string{sharedID}, inner.Roles[tufmetadata.TARGETS].KeyIDs)
}

func TestRootBuilder_AddRole_CallerMutationAfterAddDoesNotLeak(t *testing.T) {
	// AddRole takes keys by value, so mutating a key the caller passed in
	// after the call must not change what was stored.
	builder := tufext.NewRootBuilder()
	key := generateTestPublicKey(t)
	origID := keyIDOf(t, key)

	_, err := builder.AddRole(tufmetadata.ROOT, 1, key)
	require.NoError(t, err)

	key.Scheme = "mangled"

	inner := builder.RootType()
	stored, ok := inner.Keys[origID]
	require.True(t, ok)
	assert.Equal(t, tufmetadata.KeySchemeEd25519, stored.Scheme)
}

func TestRootBuilder_RootType_StablePointer(t *testing.T) {
	builder := tufext.NewRootBuilder()

	inner := builder.RootType()
	require.NotNil(t, inner)

	// Repeated calls return a pointer to the same inner state so that
	// "arbitrary modification" per the docstring is persistent.
	assert.Same(t, inner, builder.RootType())
}

func TestRootBuilder_RootType_ReflectsMutations(t *testing.T) {
	// Mutating the role pointer returned by AddRole is reflected in the next
	// RootType() view because that pointer lives in the same Roles map.
	builder := tufext.NewRootBuilder()
	k := generateTestPublicKey(t)

	role, err := builder.AddRole(tufmetadata.ROOT, 1, k)
	require.NoError(t, err)

	role.Threshold = 2

	inner := builder.RootType()
	assert.Equal(t, 2, inner.Roles[tufmetadata.ROOT].Threshold)
}

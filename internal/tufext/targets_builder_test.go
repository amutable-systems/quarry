// Copyright (C) 2026 Amutable GmbH

package tufext_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/keystore"
	"go.amutable.dev/quarry/internal/tufext"
	"go.amutable.dev/quarry/internal/tufrepo"
)

// generateTestPublicKey returns a fresh ed25519-backed [keystore.PublicKey]
// suitable for [TargetsBuilder.AddDelegation]. Each call produces a distinct
// public key so [keystore.PublicKey.ID] yields distinct IDs.
func generateTestPublicKey(t *testing.T) keystore.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	tufKey, err := tufmetadata.KeyFromPublicKey(pub)
	require.NoError(t, err)
	return *tufKey
}

// keyIDOf returns the stringified [keystore.KeyID] for the given key.
func keyIDOf(t *testing.T, key keystore.PublicKey) string {
	t.Helper()
	id, err := key.ID()
	require.NoError(t, err)
	return id
}

func TestNewTargetsBuilder(t *testing.T) {
	before := time.Now().UTC()
	builder := tufext.NewTargetsBuilder()
	after := time.Now().UTC()

	inner := builder.TargetsType()
	require.NotNil(t, inner)

	assert.Equal(t, tufmetadata.TARGETS, inner.Type)
	assert.Equal(t, tufmetadata.SPECIFICATION_VERSION, inner.SpecVersion)

	// Targets map is initialised (non-nil, empty) so AddTargetFile can write
	// into it without a nil-map panic.
	assert.NotNil(t, inner.Targets)
	assert.Empty(t, inner.Targets)

	assert.Nil(t, inner.Delegations)

	assert.Equal(t, time.UTC, builder.RefTime.Location())
	assert.True(t, !builder.RefTime.Before(before) && !builder.RefTime.After(after),
		"RefTime %v should be between %v and %v", builder.RefTime, before, after)
	assert.Equal(t, tufrepo.DefaultTargetsExpiry, builder.ExpireAfter)
}

func TestTargetsBuilder_AddTargetFile(t *testing.T) {
	for _, tc := range []struct {
		name   string
		size   int64
		hashes []digest.Digest
	}{
		{
			name:   "SingleHash",
			size:   5,
			hashes: []digest.Digest{digest.SHA256.FromBytes([]byte("hello"))},
		},
		{
			name: "MultipleHashes",
			size: 5,
			hashes: []digest.Digest{
				digest.SHA256.FromBytes([]byte("hello")),
				digest.SHA512.FromBytes([]byte("hello")),
			},
		},
		{
			name: "NoHashes",
			size: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			builder := tufext.NewTargetsBuilder()

			meta, err := builder.AddTargetFile("foo.bin", tc.size, tc.hashes...)
			require.NoError(t, err)
			require.NotNil(t, meta)

			assert.Equal(t, tc.size, meta.Length)
			require.Len(t, meta.Hashes, len(tc.hashes))
			for _, h := range tc.hashes {
				expected, err := hex.DecodeString(h.Encoded())
				require.NoError(t, err)
				assert.EqualValues(t, expected, meta.Hashes[string(h.Algorithm())])
			}

			// Returned pointer is the same pointer stored in the Targets
			// map -- this is the contract that lets callers configure the
			// entry via the returned reference.
			assert.Same(t, meta, builder.TargetsType().Targets["foo.bin"])
		})
	}
}

func TestTargetsBuilder_AddTargetFile_MultipleFiles(t *testing.T) {
	builder := tufext.NewTargetsBuilder()
	h := digest.SHA256.FromBytes([]byte("data"))

	metaA, err := builder.AddTargetFile("a.bin", 1, h)
	require.NoError(t, err)
	metaB, err := builder.AddTargetFile("b.bin", 2, h)
	require.NoError(t, err)

	targets := builder.TargetsType().Targets
	require.Len(t, targets, 2)
	assert.Same(t, metaA, targets["a.bin"])
	assert.Same(t, metaB, targets["b.bin"])
	assert.Equal(t, int64(1), targets["a.bin"].Length)
	assert.Equal(t, int64(2), targets["b.bin"].Length)
}

func TestTargetsBuilder_AddTargetFile_OverwriteSameFile(t *testing.T) {
	// A second AddTargetFile with the same filename replaces rather than
	// merges -- only the newest entry sticks.
	builder := tufext.NewTargetsBuilder()
	h1 := digest.SHA256.FromBytes([]byte("v1"))
	h2 := digest.SHA256.FromBytes([]byte("v2"))

	_, err := builder.AddTargetFile("foo.txt", 10, h1)
	require.NoError(t, err)
	meta2, err := builder.AddTargetFile("foo.txt", 20, h2)
	require.NoError(t, err)

	targets := builder.TargetsType().Targets
	require.Len(t, targets, 1)
	assert.Same(t, meta2, targets["foo.txt"])
	assert.Equal(t, int64(20), targets["foo.txt"].Length)

	expected, err := hex.DecodeString(h2.Encoded())
	require.NoError(t, err)
	assert.EqualValues(t, expected, targets["foo.txt"].Hashes["sha256"])
}

func TestTargetsBuilder_AddTargetFile_InvalidHash(t *testing.T) {
	// digest.Digest is a string type with no validation until you call
	// Validate/Parse, so a malformed digest can reach AddTargetFile.
	// AddTargetFile runs Validate up front, so any malformed digest (wrong
	// length, unknown algorithm, non-hex encoding, missing separator) is
	// rejected before it lands in the Targets map.
	builder := tufext.NewTargetsBuilder()
	bad := digest.Digest("sha256:not-hex!!")

	meta, err := builder.AddTargetFile("bad.bin", 1, bad)
	require.Error(t, err)
	assert.Nil(t, meta)
	assert.ErrorContains(t, err, "is invalid") //nolint:testifylint // preferable for error-path tests

	// File is not added to the map.
	assert.NotContains(t, builder.TargetsType().Targets, "bad.bin")
}

func TestTargetsBuilder_AddTargetFile_ModifyReturnedPointer(t *testing.T) {
	// The documented contract is that callers can configure the target entry
	// by modifying the returned reference. Setting Custom here must be visible
	// through the builder's TargetsType view.
	builder := tufext.NewTargetsBuilder()
	h := digest.SHA256.FromBytes([]byte("hello"))

	meta, err := builder.AddTargetFile("foo.txt", 5, h)
	require.NoError(t, err)

	raw := json.RawMessage(`{"custom":"value"}`)
	meta.Custom = &raw

	got := builder.TargetsType().Targets["foo.txt"]
	require.NotNil(t, got)
	require.NotNil(t, got.Custom)
	assert.Equal(t, raw, *got.Custom)
}

func TestTargetsBuilder_AddDelegation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		roleName  string
		threshold int
		numKeys   int
	}{
		{name: "SingleKey", roleName: "alpha", threshold: 1, numKeys: 1},
		{name: "MultipleKeys", roleName: "multi", threshold: 2, numKeys: 3},
		{name: "ThresholdEqualsKeys", roleName: "tight", threshold: 3, numKeys: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			builder := tufext.NewTargetsBuilder()
			keys := make([]keystore.PublicKey, 0, tc.numKeys)
			keyIDs := make([]string, 0, tc.numKeys)
			for i := 0; i < tc.numKeys; i++ {
				k := generateTestPublicKey(t)
				keys = append(keys, k)
				keyIDs = append(keyIDs, keyIDOf(t, k))
			}

			role, err := builder.AddDelegation(tc.roleName, tc.threshold, keys...)
			require.NoError(t, err)
			require.NotNil(t, role)

			assert.Equal(t, tc.roleName, role.Name)
			assert.Equal(t, tc.threshold, role.Threshold)
			// KeyIDs preserve variadic-argument order.
			assert.Equal(t, keyIDs, role.KeyIDs)

			inner := builder.TargetsType()
			require.NotNil(t, inner.Delegations)
			assert.Len(t, inner.Delegations.Keys, tc.numKeys)
			for _, id := range keyIDs {
				assert.Contains(t, inner.Delegations.Keys, id)
			}
			require.Len(t, inner.Delegations.Roles, 1)
			assert.Equal(t, tc.roleName, inner.Delegations.Roles[0].Name)
			assert.Equal(t, keyIDs, inner.Delegations.Roles[0].KeyIDs)
			assert.Equal(t, tc.threshold, inner.Delegations.Roles[0].Threshold)
		})
	}
}

func TestTargetsBuilder_AddDelegation_InvalidThreshold(t *testing.T) {
	// AddDelegation rejects thresholds that are non-positive or that exceed
	// the number of provided keys -- such a role could never be satisfied.
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
			builder := tufext.NewTargetsBuilder()
			keys := make([]keystore.PublicKey, 0, tc.numKeys)
			for i := 0; i < tc.numKeys; i++ {
				keys = append(keys, generateTestPublicKey(t))
			}

			role, err := builder.AddDelegation("bad", tc.threshold, keys...)
			require.Error(t, err)
			assert.Nil(t, role)
			assert.ErrorContains(t, err, "threshold") //nolint:testifylint // preferable for error-path tests

			// Nothing was added to Delegations.
			inner := builder.TargetsType()
			if inner.Delegations != nil {
				assert.Empty(t, inner.Delegations.Roles)
			}
		})
	}
}

func TestTargetsBuilder_AddDelegation_MultipleRoles(t *testing.T) {
	builder := tufext.NewTargetsBuilder()
	k1 := generateTestPublicKey(t)
	k2 := generateTestPublicKey(t)

	_, err := builder.AddDelegation("alpha", 1, k1)
	require.NoError(t, err)
	_, err = builder.AddDelegation("beta", 1, k2)
	require.NoError(t, err)

	inner := builder.TargetsType()
	require.Len(t, inner.Delegations.Roles, 2)
	assert.Len(t, inner.Delegations.Keys, 2)
	assert.Equal(t, "alpha", inner.Delegations.Roles[0].Name)
	assert.Equal(t, "beta", inner.Delegations.Roles[1].Name)
}

func TestTargetsBuilder_AddDelegation_SharedKeyAcrossRoles(t *testing.T) {
	// A key referenced by multiple roles is deduplicated in the top-level Keys
	// map but remains referenced by each role's KeyIDs slice.
	builder := tufext.NewTargetsBuilder()
	shared := generateTestPublicKey(t)
	other := generateTestPublicKey(t)
	sharedID := keyIDOf(t, shared)
	otherID := keyIDOf(t, other)

	_, err := builder.AddDelegation("alpha", 1, shared, other)
	require.NoError(t, err)
	_, err = builder.AddDelegation("beta", 1, shared)
	require.NoError(t, err)

	inner := builder.TargetsType()
	assert.Len(t, inner.Delegations.Keys, 2)
	assert.Contains(t, inner.Delegations.Keys, sharedID)
	assert.Contains(t, inner.Delegations.Keys, otherID)

	require.Len(t, inner.Delegations.Roles, 2)
	assert.Equal(t, []string{sharedID, otherID}, inner.Delegations.Roles[0].KeyIDs)
	assert.Equal(t, []string{sharedID}, inner.Delegations.Roles[1].KeyIDs)
}

func TestTargetsBuilder_AddDelegation_SuccinctRolesUnsupported(t *testing.T) {
	// AddDelegation refuses to work once SuccinctRoles are configured,
	// mirroring the same restriction in GCRoleKeys/FillRoleKeys.
	builder := tufext.NewTargetsBuilder()
	inner := builder.TargetsType()
	inner.Delegations = &tufmetadata.Delegations{
		SuccinctRoles: &tufmetadata.SuccinctRoles{
			KeyIDs: []string{}, Threshold: 1, BitLength: 4, NamePrefix: "bin",
		},
	}

	key := generateTestPublicKey(t)
	role, err := builder.AddDelegation("alpha", 1, key)
	require.Error(t, err)
	assert.Nil(t, role)
	assert.ErrorContains(t, err, "succinct roles") //nolint:testifylint // preferable for error-path tests

	assert.Empty(t, inner.Delegations.Roles)
	assert.Empty(t, inner.Delegations.Keys)
}

func TestTargetsBuilder_AddDelegation_InsertionOrderPreserved(t *testing.T) {
	// The Roles slice orders entries by insertion. This matters because TUF
	// delegation resolution is order-sensitive: the first matching role wins.
	// Use deliberately unsorted names to catch accidental sorting.
	builder := tufext.NewTargetsBuilder()
	names := []string{"charlie", "alpha", "bravo"}
	for _, n := range names {
		_, err := builder.AddDelegation(n, 1, generateTestPublicKey(t))
		require.NoError(t, err)
	}

	inner := builder.TargetsType()
	require.Len(t, inner.Delegations.Roles, len(names))
	for i, n := range names {
		assert.Equal(t, n, inner.Delegations.Roles[i].Name)
	}
}

// Make sure that AddDelegation will not cause previous pointers to reference
// old slices and thus make changes unobservable.
func TestTargetsBuilder_AddDelegation_PointerStableAcrossCalls(t *testing.T) {
	builder := tufext.NewTargetsBuilder()
	firstKey := generateTestPublicKey(t)
	firstID := keyIDOf(t, firstKey)

	firstRole, err := builder.AddDelegation("alpha", 1, firstKey)
	require.NoError(t, err)

	// 64 is well above Go's initial slice capacity for the append pattern used
	// by AddDelegation, so the backing array is guaranteed to have reallocated
	// at least once by the time the loop exits.
	const extraAppends = 64
	for i := 0; i < extraAppends; i++ {
		_, err := builder.AddDelegation(fmt.Sprintf("role%d", i), 1, generateTestPublicKey(t))
		require.NoError(t, err)
	}

	firstRole.Paths = []string{"alpha/*"}
	firstRole.Terminating = true

	inner := builder.TargetsType()
	require.Len(t, inner.Delegations.Roles, extraAppends+1)
	assert.Equal(t, "alpha", inner.Delegations.Roles[0].Name)
	assert.Equal(t, []string{firstID}, inner.Delegations.Roles[0].KeyIDs)
	assert.Equal(t, []string{"alpha/*"}, inner.Delegations.Roles[0].Paths)
	assert.True(t, inner.Delegations.Roles[0].Terminating)
}

func TestTargetsBuilder_AddDelegation_CallerMutationAfterAddDoesNotLeak(t *testing.T) {
	// AddDelegation takes keys by value, so mutating a key the caller passed
	// in after the call must not change what was stored.
	builder := tufext.NewTargetsBuilder()
	key := generateTestPublicKey(t)
	origID := keyIDOf(t, key)

	_, err := builder.AddDelegation("alpha", 1, key)
	require.NoError(t, err)

	key.Scheme = "mangled"

	inner := builder.TargetsType()
	stored, ok := inner.Delegations.Keys[origID]
	require.True(t, ok)
	assert.Equal(t, tufmetadata.KeySchemeEd25519, stored.Scheme)
}

func TestTargetsBuilder_TargetsType_NoDelegations(t *testing.T) {
	builder := tufext.NewTargetsBuilder()

	inner := builder.TargetsType()
	require.NotNil(t, inner)
	assert.Nil(t, inner.Delegations)

	// Repeated calls return a pointer to the same inner state so that
	// "arbitrary modification" per the docstring is persistent.
	assert.Same(t, inner, builder.TargetsType())
}

func TestTargetsBuilder_TargetsType_ReflectsPointerMutations(t *testing.T) {
	// Mutating a role through the pointer returned by AddDelegation is
	// reflected in the next TargetsType() view because TargetsType()
	// regenerates Delegations.Roles from the stored pointers.
	builder := tufext.NewTargetsBuilder()
	k := generateTestPublicKey(t)

	role, err := builder.AddDelegation("alpha", 1, k)
	require.NoError(t, err)

	role.Paths = []string{"alpha/*"}
	role.Terminating = true
	role.PathHashPrefixes = []string{"ff"}

	inner := builder.TargetsType()
	require.Len(t, inner.Delegations.Roles, 1)
	assert.Equal(t, []string{"alpha/*"}, inner.Delegations.Roles[0].Paths)
	assert.True(t, inner.Delegations.Roles[0].Terminating)
	assert.Equal(t, []string{"ff"}, inner.Delegations.Roles[0].PathHashPrefixes)
}

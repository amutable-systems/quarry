// Copyright (C) 2026 Amutable GmbH

package tufext_test

import (
	"maps"
	"slices"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/tufext"
)

// stubKey returns a fresh [tufmetadata.Key] for tests. The contents are
// irrelevant to [tufext.GCRoleKeys] -- each call returns a distinct pointer so
// tests can verify identity is preserved across the GC operation.
func stubKey() *tufmetadata.Key {
	return &tufmetadata.Key{}
}

// rootWithKeys builds a [tufmetadata.RootType] with the given key IDs (each
// backed by a fresh stub key) and roles. The returned map lets tests look up
// the original [tufmetadata.Key] pointers by their key ID.
func rootWithKeys(keyIDs []string, roles map[string][]string) (tufmetadata.RootType, map[string]*tufmetadata.Key) {
	keys := make(map[string]*tufmetadata.Key, len(keyIDs))
	for _, id := range keyIDs {
		keys[id] = stubKey()
	}
	roleMap := make(map[string]*tufmetadata.Role, len(roles))
	for name, ids := range roles {
		roleMap[name] = &tufmetadata.Role{KeyIDs: ids, Threshold: 1}
	}
	root := tufmetadata.RootType{Keys: maps.Clone(keys), Roles: roleMap}
	return root, keys
}

// targetsWithKeys builds a [tufmetadata.TargetsType] (with non-nil
// Delegations) with the given key IDs and delegated roles.
func targetsWithKeys(keyIDs []string, roles []tufmetadata.DelegatedRole) (tufmetadata.TargetsType, map[string]*tufmetadata.Key) {
	keys := make(map[string]*tufmetadata.Key, len(keyIDs))
	for _, id := range keyIDs {
		keys[id] = stubKey()
	}
	targets := tufmetadata.TargetsType{
		Delegations: &tufmetadata.Delegations{
			Keys:  maps.Clone(keys),
			Roles: roles,
		},
	}
	return targets, keys
}

func TestGCRoleKeys_Root(t *testing.T) {
	for _, tc := range []struct {
		name     string
		keyIDs   []string
		roles    map[string][]string
		wantKeep []string
	}{
		{
			name:     "RemovesUnreferenced",
			keyIDs:   []string{"kept-id", "unused-id-1", "unused-id-2"},
			roles:    map[string][]string{tufmetadata.ROOT: {"kept-id"}},
			wantKeep: []string{"kept-id"},
		},
		{
			name:   "KeepsAllReferenced",
			keyIDs: []string{"a", "b", "c", "d"},
			roles: map[string][]string{
				tufmetadata.ROOT:      {"a"},
				tufmetadata.TARGETS:   {"b"},
				tufmetadata.SNAPSHOT:  {"c"},
				tufmetadata.TIMESTAMP: {"d"},
			},
			wantKeep: []string{"a", "b", "c", "d"},
		},
		{
			name:   "SharedKeyAcrossRoles",
			keyIDs: []string{"shared", "other", "unused"},
			roles: map[string][]string{
				tufmetadata.ROOT:     {"shared"},
				tufmetadata.TARGETS:  {"shared", "other"},
				tufmetadata.SNAPSHOT: {"shared"},
			},
			wantKeep: []string{"shared", "other"},
		},
		{
			name:     "NoRoles",
			keyIDs:   []string{"a", "b"},
			roles:    map[string][]string{},
			wantKeep: nil,
		},
		{
			name:   "RolesWithEmptyKeyIDs",
			keyIDs: []string{"a", "b"},
			roles: map[string][]string{
				tufmetadata.ROOT:    {},
				tufmetadata.TARGETS: nil,
			},
			wantKeep: nil,
		},
		{
			name:     "EmptyKeys",
			keyIDs:   nil,
			roles:    map[string][]string{tufmetadata.ROOT: {}},
			wantKeep: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, origKeys := rootWithKeys(tc.keyIDs, tc.roles)

			require.NoError(t, tufext.GCRoleKeys(&root))

			assert.Len(t, root.Keys, len(tc.wantKeep))
			for _, id := range tc.wantKeep {
				assert.Same(t, origKeys[id], root.Keys[id], "key %s should be preserved by identity", id)
			}
			for id := range origKeys {
				if !slices.Contains(tc.wantKeep, id) {
					assert.NotContains(t, root.Keys, id, "key %s should have been GC'd", id)
				}
			}
		})
	}
}

func TestGCRoleKeys_Root_DanglingKeyReference(t *testing.T) {
	root := tufmetadata.RootType{
		Keys: map[string]*tufmetadata.Key{
			"real": stubKey(),
		},
		Roles: map[string]*tufmetadata.Role{
			tufmetadata.ROOT: {KeyIDs: []string{"real", "missing"}, Threshold: 1},
		},
	}

	err := tufext.GCRoleKeys(&root)
	require.Error(t, err)
	assert.ErrorContains(t, err, "missing") //nolint:testifylint // preferable for error-path tests
	assert.ErrorContains(t, err, tufmetadata.ROOT)
}

func TestGCRoleKeys_Root_PreservesRolesMap(t *testing.T) {
	root := tufmetadata.RootType{
		Keys: map[string]*tufmetadata.Key{
			"a": stubKey(),
			"b": stubKey(),
		},
		Roles: map[string]*tufmetadata.Role{
			tufmetadata.ROOT:    {KeyIDs: []string{"a"}, Threshold: 1},
			tufmetadata.TARGETS: {KeyIDs: []string{"b"}, Threshold: 3},
		},
	}

	require.NoError(t, tufext.GCRoleKeys(&root))

	// The Roles map itself should be unchanged.
	require.Len(t, root.Roles, 2)
	assert.Equal(t, []string{"a"}, root.Roles[tufmetadata.ROOT].KeyIDs)
	assert.Equal(t, 1, root.Roles[tufmetadata.ROOT].Threshold)
	assert.Equal(t, []string{"b"}, root.Roles[tufmetadata.TARGETS].KeyIDs)
	assert.Equal(t, 3, root.Roles[tufmetadata.TARGETS].Threshold)
}

func TestGCRoleKeys_Root_PreservesOtherFields(t *testing.T) {
	root := tufmetadata.RootType{
		Type:               tufmetadata.ROOT,
		SpecVersion:        tufmetadata.SPECIFICATION_VERSION,
		ConsistentSnapshot: true,
		Version:            42,
		Keys: map[string]*tufmetadata.Key{
			"a":      stubKey(),
			"unused": stubKey(),
		},
		Roles: map[string]*tufmetadata.Role{
			tufmetadata.ROOT: {KeyIDs: []string{"a"}, Threshold: 1},
		},
	}

	require.NoError(t, tufext.GCRoleKeys(&root))

	assert.Equal(t, tufmetadata.ROOT, root.Type)
	assert.Equal(t, tufmetadata.SPECIFICATION_VERSION, root.SpecVersion)
	assert.True(t, root.ConsistentSnapshot)
	assert.Equal(t, int64(42), root.Version)
}

func TestGCRoleKeys_Root_Idempotent(t *testing.T) {
	keep := stubKey()
	root := tufmetadata.RootType{
		Keys: map[string]*tufmetadata.Key{
			"kept":   keep,
			"unused": stubKey(),
		},
		Roles: map[string]*tufmetadata.Role{
			tufmetadata.ROOT: {KeyIDs: []string{"kept"}, Threshold: 1},
		},
	}

	require.NoError(t, tufext.GCRoleKeys(&root))
	after1 := maps.Clone(root.Keys)

	// A second invocation should produce an equivalent map.
	require.NoError(t, tufext.GCRoleKeys(&root))
	assert.True(t, maps.Equal(after1, root.Keys), "Keys should be identical after a second GC")
	assert.Same(t, keep, root.Keys["kept"])
}

// TestGCRoleKeys_Root_RotationScenario mirrors the shape left behind by
// [tufrepo.Transaction.rotateRoleKeys] just before it calls [GCRoleKeys]: the
// old key IDs have been replaced in the [tufmetadata.Role.KeyIDs] slice, but
// the old keys are still sitting in the top-level [tufmetadata.RootType.Keys]
// map alongside the new ones.
func TestGCRoleKeys_Root_RotationScenario(t *testing.T) {
	newKey := stubKey()
	root := tufmetadata.RootType{
		Keys: map[string]*tufmetadata.Key{
			"old-root-id": stubKey(),
			"new-root-id": newKey,
			"targets-id":  stubKey(),
		},
		Roles: map[string]*tufmetadata.Role{
			tufmetadata.ROOT:    {KeyIDs: []string{"new-root-id"}, Threshold: 1},
			tufmetadata.TARGETS: {KeyIDs: []string{"targets-id"}, Threshold: 1},
		},
	}

	require.NoError(t, tufext.GCRoleKeys(&root))

	assert.Len(t, root.Keys, 2)
	assert.Same(t, newKey, root.Keys["new-root-id"])
	assert.NotContains(t, root.Keys, "old-root-id")
}

func TestGCRoleKeys_Root_NilKeys(t *testing.T) {
	// JSON with "keys": null deserializes into a nil map; GCRoleKeys should
	// tolerate this so long as no role references a missing key.
	root := tufmetadata.RootType{
		Keys: nil,
		Roles: map[string]*tufmetadata.Role{
			tufmetadata.ROOT: {KeyIDs: []string{}, Threshold: 1},
		},
	}

	require.NoError(t, tufext.GCRoleKeys(&root))
	assert.NotNil(t, root.Keys)
	assert.Empty(t, root.Keys)
}

func TestGCRoleKeys_Root_NilRoles(t *testing.T) {
	root := tufmetadata.RootType{
		Keys: map[string]*tufmetadata.Key{
			"a": stubKey(),
		},
		Roles: nil,
	}

	require.NoError(t, tufext.GCRoleKeys(&root))
	assert.Empty(t, root.Keys)
}

func TestGCRoleKeys_Targets(t *testing.T) {
	for _, tc := range []struct {
		name     string
		keyIDs   []string
		roles    []tufmetadata.DelegatedRole
		wantKeep []string
	}{
		{
			name:   "RemovesUnreferenced",
			keyIDs: []string{"kept", "unused"},
			roles: []tufmetadata.DelegatedRole{
				{Name: "delegated", KeyIDs: []string{"kept"}, Threshold: 1},
			},
			wantKeep: []string{"kept"},
		},
		{
			name:   "KeepsAllReferenced",
			keyIDs: []string{"a", "b", "c"},
			roles: []tufmetadata.DelegatedRole{
				{Name: "role1", KeyIDs: []string{"a"}, Threshold: 1},
				{Name: "role2", KeyIDs: []string{"b", "c"}, Threshold: 2},
			},
			wantKeep: []string{"a", "b", "c"},
		},
		{
			name:   "SharedKeyAcrossRoles",
			keyIDs: []string{"shared", "other", "unused"},
			roles: []tufmetadata.DelegatedRole{
				{Name: "role1", KeyIDs: []string{"shared"}, Threshold: 1},
				{Name: "role2", KeyIDs: []string{"shared", "other"}, Threshold: 2},
				{Name: "role3", KeyIDs: []string{"shared"}, Threshold: 1},
			},
			wantKeep: []string{"shared", "other"},
		},
		{
			name:     "NoDelegatedRoles",
			keyIDs:   []string{"a", "b"},
			roles:    nil,
			wantKeep: nil,
		},
		{
			name:   "RolesWithEmptyKeyIDs",
			keyIDs: []string{"a"},
			roles: []tufmetadata.DelegatedRole{
				{Name: "empty1", KeyIDs: []string{}, Threshold: 1},
				{Name: "empty2", KeyIDs: nil, Threshold: 1},
			},
			wantKeep: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			targets, origKeys := targetsWithKeys(tc.keyIDs, tc.roles)

			require.NoError(t, tufext.GCRoleKeys(&targets))

			assert.Len(t, targets.Delegations.Keys, len(tc.wantKeep))
			for _, id := range tc.wantKeep {
				assert.Same(t, origKeys[id], targets.Delegations.Keys[id], "key %s should be preserved by identity", id)
			}
			for id := range origKeys {
				if !slices.Contains(tc.wantKeep, id) {
					assert.NotContains(t, targets.Delegations.Keys, id, "key %s should have been GC'd", id)
				}
			}
		})
	}
}

func TestGCRoleKeys_Targets_DanglingKeyReference(t *testing.T) {
	targets := tufmetadata.TargetsType{
		Delegations: &tufmetadata.Delegations{
			Keys: map[string]*tufmetadata.Key{
				"real": stubKey(),
			},
			Roles: []tufmetadata.DelegatedRole{
				{Name: "mydelegation", KeyIDs: []string{"real", "missing"}, Threshold: 1},
			},
		},
	}

	err := tufext.GCRoleKeys(&targets)
	require.Error(t, err)
	assert.ErrorContains(t, err, "missing") //nolint:testifylint // preferable for error-path tests
	assert.ErrorContains(t, err, "mydelegation")
}

func TestGCRoleKeys_Targets_NilDelegations(t *testing.T) {
	targets := tufmetadata.TargetsType{
		Type:        tufmetadata.TARGETS,
		SpecVersion: tufmetadata.SPECIFICATION_VERSION,
		Version:     5,
		Targets:     map[string]*tufmetadata.TargetFiles{"f": {Length: 7}},
		Delegations: nil,
	}

	require.NoError(t, tufext.GCRoleKeys(&targets))

	assert.Nil(t, targets.Delegations)
	// Other fields should be untouched.
	assert.Equal(t, tufmetadata.TARGETS, targets.Type)
	assert.Equal(t, tufmetadata.SPECIFICATION_VERSION, targets.SpecVersion)
	assert.Equal(t, int64(5), targets.Version)
	assert.Len(t, targets.Targets, 1)
}

func TestGCRoleKeys_Targets_NilDelegationKeys(t *testing.T) {
	targets := tufmetadata.TargetsType{
		Delegations: &tufmetadata.Delegations{
			Keys:  nil,
			Roles: []tufmetadata.DelegatedRole{},
		},
	}

	require.NoError(t, tufext.GCRoleKeys(&targets))
	assert.NotNil(t, targets.Delegations.Keys)
	assert.Empty(t, targets.Delegations.Keys)
}

func TestGCRoleKeys_Targets_SuccinctRolesUnsupported(t *testing.T) {
	targets := tufmetadata.TargetsType{
		Delegations: &tufmetadata.Delegations{
			Keys: map[string]*tufmetadata.Key{
				"a": stubKey(),
				"b": stubKey(),
			},
			SuccinctRoles: &tufmetadata.SuccinctRoles{
				KeyIDs:     []string{"a"},
				Threshold:  1,
				BitLength:  4,
				NamePrefix: "bin",
			},
		},
	}

	err := tufext.GCRoleKeys(&targets)
	require.Error(t, err)
	assert.ErrorContains(t, err, "succinct roles") //nolint:testifylint // preferable for error-path tests

	// Keys map should not have been modified since we errored out.
	assert.Len(t, targets.Delegations.Keys, 2)
}

func TestGCRoleKeys_Targets_PreservesDelegatedRolesSlice(t *testing.T) {
	roles := []tufmetadata.DelegatedRole{
		{Name: "role1", KeyIDs: []string{"a"}, Threshold: 1, Paths: []string{"foo/*"}},
		{Name: "role2", KeyIDs: []string{"b"}, Threshold: 2, Terminating: true},
	}
	targets := tufmetadata.TargetsType{
		Delegations: &tufmetadata.Delegations{
			Keys: map[string]*tufmetadata.Key{
				"a":      stubKey(),
				"b":      stubKey(),
				"unused": stubKey(),
			},
			Roles: roles,
		},
	}

	// Capture the original slice header so we can verify it survives by
	// identity and length.
	origRoles := targets.Delegations.Roles

	require.NoError(t, tufext.GCRoleKeys(&targets))

	// The slice should be the same backing slice (not re-sliced or
	// reallocated) and every DelegatedRole entry should be byte-identical.
	require.Len(t, targets.Delegations.Roles, len(origRoles))
	assert.Equal(t, unsafe.SliceData(origRoles), unsafe.SliceData(targets.Delegations.Roles),
		"Delegations.Roles should not have been reallocated")
	for i := range origRoles {
		assert.Equal(t, origRoles[i], targets.Delegations.Roles[i], "role %d should be unmodified", i)
	}
}

func TestGCRoleKeys_Targets_PreservesOtherFields(t *testing.T) {
	shared := stubKey()
	targets := tufmetadata.TargetsType{
		Type:        tufmetadata.TARGETS,
		SpecVersion: tufmetadata.SPECIFICATION_VERSION,
		Version:     99,
		Targets: map[string]*tufmetadata.TargetFiles{
			"file.txt": {Length: 7},
		},
		Delegations: &tufmetadata.Delegations{
			Keys: map[string]*tufmetadata.Key{
				"a":      shared,
				"unused": stubKey(),
			},
			Roles: []tufmetadata.DelegatedRole{
				{
					Name:        "delegated",
					KeyIDs:      []string{"a"},
					Threshold:   1,
					Terminating: true,
					Paths:       []string{"foo/*"},
				},
			},
		},
	}

	require.NoError(t, tufext.GCRoleKeys(&targets))

	assert.Equal(t, tufmetadata.TARGETS, targets.Type)
	assert.Equal(t, tufmetadata.SPECIFICATION_VERSION, targets.SpecVersion)
	assert.Equal(t, int64(99), targets.Version)
	assert.Len(t, targets.Targets, 1)
	require.Len(t, targets.Delegations.Roles, 1)
	assert.Equal(t, "delegated", targets.Delegations.Roles[0].Name)
	assert.Equal(t, []string{"a"}, targets.Delegations.Roles[0].KeyIDs)
	assert.True(t, targets.Delegations.Roles[0].Terminating)
	assert.Equal(t, []string{"foo/*"}, targets.Delegations.Roles[0].Paths)
}

func TestGCRoleKeys_Targets_Idempotent(t *testing.T) {
	keep := stubKey()
	targets := tufmetadata.TargetsType{
		Delegations: &tufmetadata.Delegations{
			Keys: map[string]*tufmetadata.Key{
				"kept":   keep,
				"unused": stubKey(),
			},
			Roles: []tufmetadata.DelegatedRole{
				{Name: "delegated", KeyIDs: []string{"kept"}, Threshold: 1},
			},
		},
	}

	require.NoError(t, tufext.GCRoleKeys(&targets))
	after1 := maps.Clone(targets.Delegations.Keys)

	// A second invocation should produce an equivalent map.
	require.NoError(t, tufext.GCRoleKeys(&targets))
	assert.True(t, maps.Equal(after1, targets.Delegations.Keys), "Keys should be identical after a second GC")
	assert.Same(t, keep, targets.Delegations.Keys["kept"])
}

// Copyright (C) 2026 Amutable GmbH

package tufext_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/tufext"
)

// sig builds a [tufmetadata.Signature] with the given key ID. The signature
// payload is irrelevant -- [CheckMetadataType] only inspects the KeyID.
func sig(keyID string) tufmetadata.Signature {
	return tufmetadata.Signature{KeyID: keyID, Signature: []byte("ignored")}
}

func TestCheckMetadataType_Root(t *testing.T) {
	require.NoError(t, tufext.CheckMetadataType(tufmetadata.ROOT, tufext.DefaultRoot()))
}

func TestCheckMetadataType_Timestamp(t *testing.T) {
	require.NoError(t, tufext.CheckMetadataType(tufmetadata.TIMESTAMP, tufext.DefaultTimestamp()))
}

func TestCheckMetadataType_Snapshot(t *testing.T) {
	require.NoError(t, tufext.CheckMetadataType(tufmetadata.SNAPSHOT, tufext.DefaultSnapshot()))
}

func TestCheckMetadataType_Targets(t *testing.T) {
	require.NoError(t, tufext.CheckMetadataType(tufmetadata.TARGETS, tufext.DefaultTargets()))
}

func TestCheckMetadataType_DelegatedTargets(t *testing.T) {
	// A delegated targets role has a non-core role name but its JSON _type is
	// still "targets".
	require.NoError(t, tufext.CheckMetadataType("my-delegation", tufext.DefaultTargets()))
}

func TestCheckMetadataType_GoTypeMismatchesJSONType(t *testing.T) {
	// Each Go type with a tampered Signed.Type must be rejected. The role name
	// is set to whatever the JSON _type claims, so the role-vs-type check
	// can't be the one firing -- only the Go-type-vs-JSON-type check applies.
	t.Run("Root", func(t *testing.T) {
		meta := tufext.DefaultRoot()
		meta.Signed.Type = tufmetadata.SNAPSHOT
		err := tufext.CheckMetadataType(tufmetadata.SNAPSHOT, meta)
		require.Error(t, err)
		assert.ErrorContains(t, err, tufmetadata.ROOT) //nolint:testifylint // preferable for error-path tests
		assert.ErrorContains(t, err, tufmetadata.SNAPSHOT)
	})

	t.Run("Timestamp", func(t *testing.T) {
		meta := tufext.DefaultTimestamp()
		meta.Signed.Type = tufmetadata.ROOT
		err := tufext.CheckMetadataType(tufmetadata.ROOT, meta)
		require.Error(t, err)
		assert.ErrorContains(t, err, tufmetadata.TIMESTAMP) //nolint:testifylint // preferable for error-path tests
		assert.ErrorContains(t, err, tufmetadata.ROOT)
	})

	t.Run("Snapshot", func(t *testing.T) {
		meta := tufext.DefaultSnapshot()
		meta.Signed.Type = tufmetadata.TARGETS
		err := tufext.CheckMetadataType(tufmetadata.TARGETS, meta)
		require.Error(t, err)
		assert.ErrorContains(t, err, tufmetadata.SNAPSHOT) //nolint:testifylint // preferable for error-path tests
		assert.ErrorContains(t, err, tufmetadata.TARGETS)
	})

	t.Run("Targets", func(t *testing.T) {
		meta := tufext.DefaultTargets()
		meta.Signed.Type = tufmetadata.TIMESTAMP
		err := tufext.CheckMetadataType(tufmetadata.TIMESTAMP, meta)
		require.Error(t, err)
		assert.ErrorContains(t, err, tufmetadata.TARGETS) //nolint:testifylint // preferable for error-path tests
		assert.ErrorContains(t, err, tufmetadata.TIMESTAMP)
	})
}

func TestCheckMetadataType_EmptyJSONType(t *testing.T) {
	// A Signed.Type that's been zeroed out (e.g. missing _type field in the
	// input JSON) is rejected by the Go-type-vs-JSON-type check.
	meta := tufext.DefaultRoot()
	meta.Signed.Type = ""
	err := tufext.CheckMetadataType(tufmetadata.ROOT, meta)
	require.Error(t, err)
	assert.ErrorContains(t, err, tufmetadata.ROOT)
}

func TestCheckMetadataType_RoleNameMismatchesJSONType(t *testing.T) {
	// The Go type and JSON _type agree, but the caller-supplied role name does
	// not -- only the role-vs-type check can fire here.
	for _, tc := range []struct {
		name     string
		roleName string
	}{
		{name: "RootForSnapshotName", roleName: tufmetadata.SNAPSHOT},
		{name: "RootForTimestampName", roleName: tufmetadata.TIMESTAMP},
		{name: "RootForTargetsName", roleName: tufmetadata.TARGETS},
		{name: "RootForDelegatedName", roleName: "my-delegation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tufext.CheckMetadataType(tc.roleName, tufext.DefaultRoot())
			require.Error(t, err)
			assert.ErrorContains(t, err, tc.roleName) //nolint:testifylint // preferable for error-path tests
			assert.ErrorContains(t, err, tufmetadata.ROOT)
		})
	}
}

func TestCheckMetadataType_CoreRoleNameWithDelegatedTargets(t *testing.T) {
	// A *SignedTargets with _type:"targets" passes for role name "targets"
	// (core) and for any non-core role name (delegated). It must NOT pass for
	// any other core role name.
	for _, roleName := range []string{tufmetadata.ROOT, tufmetadata.TIMESTAMP, tufmetadata.SNAPSHOT} {
		t.Run(roleName, func(t *testing.T) {
			err := tufext.CheckMetadataType(roleName, tufext.DefaultTargets())
			require.Error(t, err)
			assert.ErrorContains(t, err, roleName) //nolint:testifylint // preferable for error-path tests
			assert.ErrorContains(t, err, tufmetadata.TARGETS)
		})
	}
}

func TestCheckMetadataType_NoSignatures(t *testing.T) {
	// An empty (or nil) Signatures slice must not trip the duplicate-key
	// detector.
	t.Run("Empty", func(t *testing.T) {
		meta := tufext.DefaultRoot()
		meta.Signatures = []tufmetadata.Signature{}
		require.NoError(t, tufext.CheckMetadataType(tufmetadata.ROOT, meta))
	})

	t.Run("Nil", func(t *testing.T) {
		meta := tufext.DefaultRoot()
		meta.Signatures = nil
		require.NoError(t, tufext.CheckMetadataType(tufmetadata.ROOT, meta))
	})
}

func TestCheckMetadataType_UniqueSignatures(t *testing.T) {
	meta := tufext.DefaultRoot()
	meta.Signatures = []tufmetadata.Signature{
		sig("key-a"),
		sig("key-b"),
		sig("key-c"),
	}
	require.NoError(t, tufext.CheckMetadataType(tufmetadata.ROOT, meta))
}

func TestCheckMetadataType_DuplicateSignatures(t *testing.T) {
	for _, tc := range []struct {
		name string
		sigs []tufmetadata.Signature
		dup  string
	}{
		{
			name: "Adjacent",
			sigs: []tufmetadata.Signature{sig("dup"), sig("dup")},
			dup:  "dup",
		},
		{
			name: "Separated",
			sigs: []tufmetadata.Signature{sig("a"), sig("b"), sig("a")},
			dup:  "a",
		},
		{
			name: "ManyCopies",
			sigs: []tufmetadata.Signature{sig("x"), sig("x"), sig("x"), sig("x")},
			dup:  "x",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			meta := tufext.DefaultRoot()
			meta.Signatures = tc.sigs
			err := tufext.CheckMetadataType(tufmetadata.ROOT, meta)
			require.Error(t, err)
			assert.ErrorContains(t, err, tc.dup) //nolint:testifylint // preferable for error-path tests
			assert.ErrorContains(t, err, tufmetadata.ROOT)
		})
	}
}

func TestCheckMetadataType_DuplicateSignaturesInDelegatedTargets(t *testing.T) {
	// The duplicate-signature check must run for non-core role names too, and
	// the error message should name the delegated role.
	const roleName = "my-delegation"
	meta := tufext.DefaultTargets()
	meta.Signatures = []tufmetadata.Signature{sig("k"), sig("k")}
	err := tufext.CheckMetadataType(roleName, meta)
	require.Error(t, err)
	assert.ErrorContains(t, err, roleName) //nolint:testifylint // preferable for error-path tests
	assert.ErrorContains(t, err, "k")
}

func TestCheckMetadataType_TypeMismatchPreemptsDuplicateSignatures(t *testing.T) {
	// When both a type mismatch and duplicate signatures are present, the type
	// check fires first. This pins the ordering so a future refactor doesn't
	// silently change which error a caller sees.
	meta := tufext.DefaultRoot()
	meta.Signed.Type = tufmetadata.SNAPSHOT
	meta.Signatures = []tufmetadata.Signature{sig("dup"), sig("dup")}
	err := tufext.CheckMetadataType(tufmetadata.SNAPSHOT, meta)
	require.Error(t, err)
	assert.ErrorContains(t, err, "_type") //nolint:testifylint // preferable for error-path tests
	assert.NotContains(t, err.Error(), "multiple signatures")
}

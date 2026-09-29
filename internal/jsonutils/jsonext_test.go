// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package jsonutils_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/jsonutils"
	"go.amutable.dev/quarry/internal/tufext"
)

type extPayload struct {
	Foo string `json:"foo"`
	Bar int    `json:"bar"`
}

// x- prefix avoids collisions with typed JSON tags; Set can't detect them.
const extField = "x-quarry-test"

// roundTripExtensionJSON exercises Set + Get on the parent struct, then
// confirms the extension survives a JSON marshal/unmarshal of the parent.
func roundTripExtensionJSON[W any](t *testing.T, zero W) {
	t.Helper()
	want := extPayload{Foo: "hello", Bar: 42}

	obj := zero
	old, err := jsonutils.SetExtensionJSON(&obj, extField, want)
	require.NoError(t, err)
	assert.Nil(t, old)

	got, err := jsonutils.GetExtensionJSON[extPayload](obj, extField)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, want, *got)

	encoded, err := json.Marshal(obj)
	require.NoError(t, err)

	decoded, err := jsonutils.Parse[W](encoded)
	require.NoError(t, err)

	got, err = jsonutils.GetExtensionJSON[extPayload](decoded, extField)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, want, *got)
}

// An extension value is stored without HTML escaping, so that a struct which
// keeps its extensions as raw JSON does not end up with "\u0026" baked into
// every URL it was handed. (A struct that decodes its extensions into Go
// values washes the escapes out either way.)
func TestSetExtensionJSON_NoEscape(t *testing.T) {
	const url = "https://example.com/?a=1&b=2"

	obj := extensibleByExtras{Name: "FooOS.raw"}
	_, err := jsonutils.SetExtensionJSON(&obj, extField, url)
	require.NoError(t, err)
	assert.JSONEq(t, `"`+url+`"`, string(obj.Extras[extField]))
	assert.Contains(t, string(obj.Extras[extField]), "?a=1&b=2")

	got, err := jsonutils.GetExtensionJSON[string](obj, extField)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, url, *got)
}

func TestExtensionJSON_TUFTypes(t *testing.T) {
	t.Run("SignedRoot", func(t *testing.T) {
		roundTripExtensionJSON(t, tufext.SignedRoot{})
	})
	t.Run("SignedSnapshot", func(t *testing.T) {
		roundTripExtensionJSON(t, tufext.SignedSnapshot{})
	})
	t.Run("SignedTargets", func(t *testing.T) {
		roundTripExtensionJSON(t, tufext.SignedTargets{})
	})
	t.Run("SignedTimestamp", func(t *testing.T) {
		roundTripExtensionJSON(t, tufext.SignedTimestamp{})
	})
	t.Run("RootType", func(t *testing.T) {
		roundTripExtensionJSON(t, tufmetadata.RootType{})
	})
	t.Run("SnapshotType", func(t *testing.T) {
		roundTripExtensionJSON(t, tufmetadata.SnapshotType{})
	})
	t.Run("TargetsType", func(t *testing.T) {
		roundTripExtensionJSON(t, tufmetadata.TargetsType{})
	})
	t.Run("TimestampType", func(t *testing.T) {
		roundTripExtensionJSON(t, tufmetadata.TimestampType{})
	})
	t.Run("Signature", func(t *testing.T) {
		roundTripExtensionJSON(t, tufmetadata.Signature{})
	})
	t.Run("Key", func(t *testing.T) {
		roundTripExtensionJSON(t, tufmetadata.Key{})
	})
	t.Run("KeyVal", func(t *testing.T) {
		roundTripExtensionJSON(t, tufmetadata.KeyVal{})
	})
	t.Run("Role", func(t *testing.T) {
		roundTripExtensionJSON(t, tufmetadata.Role{})
	})
	t.Run("MetaFiles", func(t *testing.T) {
		roundTripExtensionJSON(t, tufmetadata.MetaFiles{})
	})
	t.Run("TargetFiles", func(t *testing.T) {
		roundTripExtensionJSON(t, tufmetadata.TargetFiles{})
	})
	t.Run("Delegations", func(t *testing.T) {
		roundTripExtensionJSON(t, tufmetadata.Delegations{})
	})
	t.Run("DelegatedRole", func(t *testing.T) {
		roundTripExtensionJSON(t, tufmetadata.DelegatedRole{})
	})
	t.Run("SuccinctRoles", func(t *testing.T) {
		// SuccinctRoles.UnmarshalJSON rejects BitLength outside [1,32].
		roundTripExtensionJSON(t, tufmetadata.SuccinctRoles{BitLength: 4, NamePrefix: "bin"})
	})
}

// extensibleByExtras captures unknown fields under a different name from
// go-tuf's UnrecognizedFields and uses byte-preserving json.RawMessage rather
// than the interface-based capture, to exercise the helper against a
// dissimilar extension convention.
type extensibleByExtras struct {
	Name   string
	Extras map[string]json.RawMessage
}

func (e extensibleByExtras) MarshalJSON() ([]byte, error) {
	dict := map[string]json.RawMessage{}
	for k, v := range e.Extras {
		dict[k] = v
	}
	nameBytes, err := json.Marshal(e.Name)
	if err != nil {
		return nil, err
	}
	dict["name"] = nameBytes
	return json.Marshal(dict)
}

func (e *extensibleByExtras) UnmarshalJSON(data []byte) error {
	dict, err := jsonutils.Parse[map[string]json.RawMessage](data)
	if err != nil {
		return err
	}
	if nameBytes, ok := dict["name"]; ok {
		if err := json.Unmarshal(nameBytes, &e.Name); err != nil {
			return err
		}
		delete(dict, "name")
	}
	e.Extras = dict
	return nil
}

// extensibleByEmbed inlines its unknowns into a top-level interface map
// captured during UnmarshalJSON, similar in spirit to go-tuf but without the
// UnrecognizedFields name.
type extensibleByEmbed struct {
	ID    int
	other map[string]any
}

func (e extensibleByEmbed) MarshalJSON() ([]byte, error) {
	dict := map[string]any{}
	for k, v := range e.other {
		dict[k] = v
	}
	dict["id"] = e.ID
	return json.Marshal(dict)
}

func (e *extensibleByEmbed) UnmarshalJSON(data []byte) error {
	dict, err := jsonutils.Parse[map[string]any](data)
	if err != nil {
		return err
	}
	if v, ok := dict["id"]; ok {
		idF, isFloat := v.(float64)
		if !isFloat {
			return fmt.Errorf("id is %T not number", v)
		}
		e.ID = int(idF)
		delete(dict, "id")
	}
	e.other = dict
	return nil
}

func TestExtensionJSON_CustomTypes(t *testing.T) {
	t.Run("RawMessageExtras", func(t *testing.T) {
		roundTripExtensionJSON(t, extensibleByExtras{Name: "n"})
	})
	t.Run("InterfaceMapExtras", func(t *testing.T) {
		roundTripExtensionJSON(t, extensibleByEmbed{ID: 7})
	})
}

func TestExtensionJSON_Get_Missing(t *testing.T) {
	got, err := jsonutils.GetExtensionJSON[extPayload](tufmetadata.RootType{}, extField)
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestExtensionJSON_Get_ExternallyPopulated(t *testing.T) {
	// Get must work on an UnrecognizedFields populated directly by the caller
	// (or an UnmarshalJSON), not only on values written by SetExtensionJSON.
	obj := tufmetadata.RootType{
		UnrecognizedFields: map[string]any{
			extField: json.RawMessage(`{"foo":"hello","bar":42}`),
		},
	}
	got, err := jsonutils.GetExtensionJSON[extPayload](obj, extField)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, extPayload{Foo: "hello", Bar: 42}, *got)
}

func TestExtensionJSON_Set_NilValue(t *testing.T) {
	// Setting nil writes JSON null. Get returns a non-nil pointer (the field
	// is present), but the parsed payload is the zero value -- distinguishable
	// from "field absent", which returns a nil pointer.
	obj := tufmetadata.RootType{}
	_, err := jsonutils.SetExtensionJSON(&obj, extField, nil)
	require.NoError(t, err)

	got, err := jsonutils.GetExtensionJSON[extPayload](obj, extField)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, extPayload{}, *got)
}

func TestExtensionJSON_NestedValue(t *testing.T) {
	type nested struct {
		A string         `json:"a"`
		B []int          `json:"b"`
		C map[string]int `json:"c"`
		D extPayload     `json:"d"`
	}
	want := nested{
		A: "hello",
		B: []int{1, 2, 3},
		C: map[string]int{"x": 1, "y": 2},
		D: extPayload{Foo: "deep", Bar: 99},
	}

	obj := tufmetadata.RootType{}
	_, err := jsonutils.SetExtensionJSON(&obj, extField, want)
	require.NoError(t, err)

	got, err := jsonutils.GetExtensionJSON[nested](obj, extField)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, want, *got)

	encoded, err := json.Marshal(obj)
	require.NoError(t, err)

	decoded, err := jsonutils.Parse[tufmetadata.RootType](encoded)
	require.NoError(t, err)

	got, err = jsonutils.GetExtensionJSON[nested](decoded, extField)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, want, *got)
}

func TestExtensionJSON_Set_OverwriteReturnsOld(t *testing.T) {
	first := extPayload{Foo: "first", Bar: 1}
	second := extPayload{Foo: "second", Bar: 2}

	obj := tufmetadata.RootType{}
	old, err := jsonutils.SetExtensionJSON(&obj, extField, first)
	require.NoError(t, err)
	assert.Nil(t, old)

	mid, err := jsonutils.GetExtensionJSON[extPayload](obj, extField)
	require.NoError(t, err)
	require.NotNil(t, mid)
	assert.Equal(t, first, *mid)

	old, err = jsonutils.SetExtensionJSON(&obj, extField, second)
	require.NoError(t, err)
	require.NotNil(t, old)

	oldParsed, err := jsonutils.Parse[extPayload](old)
	require.NoError(t, err)
	assert.Equal(t, first, oldParsed)

	got, err := jsonutils.GetExtensionJSON[extPayload](obj, extField)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, second, *got)
}

func TestExtensionJSON_Set_PreservesTypedFields(t *testing.T) {
	obj := tufmetadata.RootType{
		Type:        tufmetadata.ROOT,
		SpecVersion: tufmetadata.SPECIFICATION_VERSION,
		Version:     7,
		Roles: map[string]*tufmetadata.Role{
			tufmetadata.TARGETS: {KeyIDs: []string{"k1", "k2"}, Threshold: 2},
		},
	}
	_, err := jsonutils.SetExtensionJSON(&obj, extField, extPayload{Foo: "x", Bar: 1})
	require.NoError(t, err)
	assert.Equal(t, tufmetadata.ROOT, obj.Type)
	assert.Equal(t, tufmetadata.SPECIFICATION_VERSION, obj.SpecVersion)
	assert.Equal(t, int64(7), obj.Version)
	require.Contains(t, obj.Roles, tufmetadata.TARGETS)
	assert.Equal(t, []string{"k1", "k2"}, obj.Roles[tufmetadata.TARGETS].KeyIDs)
	assert.Equal(t, 2, obj.Roles[tufmetadata.TARGETS].Threshold)
}

func TestExtensionJSON_MultipleExtensions(t *testing.T) {
	obj := tufmetadata.RootType{}
	wantA := extPayload{Foo: "a", Bar: 1}
	wantB := extPayload{Foo: "b", Bar: 2}

	_, err := jsonutils.SetExtensionJSON(&obj, "x-quarry-a", wantA)
	require.NoError(t, err)
	_, err = jsonutils.SetExtensionJSON(&obj, "x-quarry-b", wantB)
	require.NoError(t, err)

	gotA, err := jsonutils.GetExtensionJSON[extPayload](obj, "x-quarry-a")
	require.NoError(t, err)
	require.NotNil(t, gotA)
	assert.Equal(t, wantA, *gotA)

	gotB, err := jsonutils.GetExtensionJSON[extPayload](obj, "x-quarry-b")
	require.NoError(t, err)
	require.NotNil(t, gotB)
	assert.Equal(t, wantB, *gotB)
}

func TestExtensionJSON_Get_WrongType(t *testing.T) {
	obj := tufmetadata.RootType{}
	_, err := jsonutils.SetExtensionJSON(&obj, extField, extPayload{Foo: "x", Bar: 1})
	require.NoError(t, err)

	type incompatible struct {
		Foo []string `json:"foo"`
	}
	_, err = jsonutils.GetExtensionJSON[incompatible](obj, extField)
	require.Error(t, err)
	require.NotErrorIs(t, err, jsonutils.ErrNotExtensible,
		"per-field parse failure must not be wrapped as ErrNotExtensible")
	assert.ErrorContains(t, err, "parse extension")
}

// fixedFields has no unknown-fields capture: stdlib's reflection-based JSON
// silently drops unrecognized keys, so the round-trip check fails.
type fixedFields struct {
	Name string `json:"name"`
}

// droppingFields has a custom marshaller that intentionally re-emits only
// known keys, mirroring a buggy "extension-aware" type.
type droppingFields struct {
	Name string
}

func (d droppingFields) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{"name": d.Name})
}

func (d *droppingFields) UnmarshalJSON(data []byte) error {
	dict, err := jsonutils.Parse[map[string]any](data)
	if err != nil {
		return err
	}
	if v, ok := dict["name"].(string); ok {
		d.Name = v
	}
	return nil
}

func TestExtensionJSON_NotExtensible(t *testing.T) {
	t.Run("Set_FixedFields", func(t *testing.T) {
		obj := fixedFields{Name: "n"}
		_, err := jsonutils.SetExtensionJSON(&obj, extField, extPayload{Foo: "x", Bar: 1})
		require.Error(t, err)
		assert.ErrorIs(t, err, jsonutils.ErrNotExtensible)
	})
	t.Run("Set_DroppingFields", func(t *testing.T) {
		obj := droppingFields{Name: "n"}
		_, err := jsonutils.SetExtensionJSON(&obj, extField, extPayload{Foo: "x", Bar: 1})
		require.Error(t, err)
		assert.ErrorIs(t, err, jsonutils.ErrNotExtensible)
	})
	t.Run("Set_NotAStruct", func(t *testing.T) {
		var obj int
		_, err := jsonutils.SetExtensionJSON(&obj, extField, extPayload{Foo: "x", Bar: 1})
		require.Error(t, err)
		assert.ErrorIs(t, err, jsonutils.ErrNotExtensible)
	})
	t.Run("Get_NotAStruct", func(t *testing.T) {
		_, err := jsonutils.GetExtensionJSON[extPayload](42, extField)
		require.Error(t, err)
		assert.ErrorIs(t, err, jsonutils.ErrNotExtensible)
	})
}

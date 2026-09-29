// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package jsonutils_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.amutable.dev/quarry/internal/jsonutils"
)

// extensible is a struct that carries its own unknown fields, in the style
// [jsonutils.MarshalExtensible] and [jsonutils.UnmarshalExtensible] exist for.
type extensible struct {
	Name    string  `json:"name,omitzero"`
	Size    *uint64 `json:"size,omitzero"`
	Skipped string  `json:"-"`
	hidden  string  // present to check unexported fields are not encoded

	Extra map[string]json.RawMessage `json:"-"`
}

func (ext extensible) MarshalJSON() ([]byte, error) {
	type knownFields extensible // shed the methods to avoid recursing forever
	return jsonutils.MarshalExtensible(knownFields(ext), ext.Extra)
}

func (ext *extensible) UnmarshalJSON(data []byte) error {
	type knownFields extensible // shed the methods to avoid recursing forever
	known, extra, err := jsonutils.UnmarshalExtensible[knownFields](data)
	if err != nil {
		return err
	}
	*ext = extensible(known)
	ext.Extra = extra
	return nil
}

func ptr[T any](v T) *T { return &v }

// Every field is emitted in a single canonical (sorted) order, and fields the
// struct does not encode at all stay out of the way of extensions.
func TestMarshalExtensible(t *testing.T) {
	encoded, err := json.Marshal(&extensible{
		Name:    "FooOS.raw",
		Size:    ptr[uint64](14),
		Skipped: "not encoded",
		hidden:  "not encoded either",
		Extra: map[string]json.RawMessage{
			"xVendorZulu":  json.RawMessage(`{"b":2}`),
			"xVendorAlpha": json.RawMessage(`{"a":1}`),
		},
	})
	require.NoError(t, err)
	//nolint:testifylint // the exact bytes are the point of this test
	assert.Equal(t, `{"name":"FooOS.raw","size":14,"xVendorAlpha":{"a":1},"xVendorZulu":{"b":2}}`, string(encoded))
}

// An object made up of nothing but extension fields is still well-formed.
func TestMarshalExtensibleOnly(t *testing.T) {
	encoded, err := json.Marshal(&extensible{
		Extra: map[string]json.RawMessage{"xVendorAlpha": json.RawMessage(`{}`)},
	})
	require.NoError(t, err)
	//nolint:testifylint // the exact bytes are the point of this test
	assert.Equal(t, `{"xVendorAlpha":{}}`, string(encoded))
}

// The whitespace of an extension value is normalised, so a hand-written
// [json.RawMessage] cannot smuggle newlines into a single-line encoding.
func TestMarshalExtensibleCompacts(t *testing.T) {
	encoded, err := json.Marshal(&extensible{
		Name:  "FooOS.raw",
		Extra: map[string]json.RawMessage{"xVendorAlpha": json.RawMessage("{\n\t\"a\": 1\n}\n")},
	})
	require.NoError(t, err)
	//nolint:testifylint // the exact bytes are the point of this test
	assert.Equal(t, `{"name":"FooOS.raw","xVendorAlpha":{"a":1}}`, string(encoded))
}

// A known field always wins over an extension of the same name -- including
// when it is unset and thus not encoded, so that an extension can never
// masquerade as a field the caller left empty. Names are matched the way
// [encoding/json] matches them, which is case-insensitively.
func TestMarshalExtensibleCollision(t *testing.T) {
	for name, ext := range map[string]extensible{
		"set": {
			Name:  "FooOS.raw",
			Extra: map[string]json.RawMessage{"name": json.RawMessage(`"BarOS.raw"`)},
		},
		"unset": {
			Name:  "FooOS.raw",
			Extra: map[string]json.RawMessage{"size": json.RawMessage(`99`)},
		},
		"other-case": {
			Name:  "FooOS.raw",
			Extra: map[string]json.RawMessage{"Name": json.RawMessage(`"BarOS.raw"`), "SIZE": json.RawMessage(`99`)},
		},
	} {
		encoded, err := json.Marshal(&ext)
		require.NoError(t, err, name)
		//nolint:testifylint // the exact bytes are the point of this test
		assert.Equal(t, `{"name":"FooOS.raw"}`, string(encoded), name)
	}
}

func TestMarshalExtensibleInvalid(t *testing.T) {
	for name, value := range map[string]json.RawMessage{
		"truncated": json.RawMessage(`{`),
		"trailing":  json.RawMessage(`{} junk`),
		"empty":     json.RawMessage(``),
		"nil":       nil,
	} {
		_, err := json.Marshal(&extensible{Extra: map[string]json.RawMessage{"xVendorAlpha": value}})
		// The name of the offending field has to survive into the error.
		require.ErrorContains(t, err, "xVendorAlpha", name)
	}
}

// Only structs (and pointers to them) have fields to extend.
func TestMarshalExtensibleNotAStruct(t *testing.T) {
	_, err := jsonutils.MarshalExtensible([]string{"a"}, map[string]json.RawMessage{"x": json.RawMessage(`1`)})
	require.ErrorIs(t, err, jsonutils.ErrNotExtensible)

	_, _, err = jsonutils.UnmarshalExtensible[[]string]([]byte(`{}`))
	require.ErrorIs(t, err, jsonutils.ErrNotExtensible)
}

func TestUnmarshalExtensible(t *testing.T) {
	var ext extensible
	require.NoError(t, json.Unmarshal([]byte(`{"name":"FooOS.raw","xVendorAlpha":{"a": 1},"xVendorZulu":[1,2]}`), &ext))
	assert.Equal(t, "FooOS.raw", ext.Name)
	assert.Equal(t, map[string]json.RawMessage{
		"xVendorAlpha": json.RawMessage(`{"a": 1}`),
		"xVendorZulu":  json.RawMessage(`[1,2]`),
	}, ext.Extra)
}

// A differently-cased known field is decoded as that field rather than kept as
// an extension, so it cannot end up in the object twice.
func TestUnmarshalExtensibleCase(t *testing.T) {
	for input, want := range map[string]string{
		`{"Name":"CaseOS.raw"}`: `{"name":"CaseOS.raw"}`,
		`{"size":1,"Size":2}`:   `{"size":2}`,
	} {
		var ext extensible
		require.NoError(t, json.Unmarshal([]byte(input), &ext))
		assert.Empty(t, ext.Extra, "decoding %s", input)

		encoded, err := json.Marshal(&ext)
		require.NoError(t, err)
		assert.Equal(t, want, string(encoded), "re-encoding %s", input)
	}
}

// An object with no extension fields decodes to a nil map rather than an empty
// one, so that it compares equal to a hand-built value.
func TestUnmarshalExtensibleNone(t *testing.T) {
	var ext extensible
	require.NoError(t, json.Unmarshal([]byte(`{"name":"FooOS.raw"}`), &ext))
	assert.Equal(t, extensible{Name: "FooOS.raw"}, ext)
}

// Decoding something that is not an object at all is an error, not an object
// full of extension fields.
func TestUnmarshalExtensibleNonObject(t *testing.T) {
	for _, input := range []string{`[]`, `"FooOS.raw"`, `{`, `null junk`} {
		var ext extensible
		require.Error(t, json.Unmarshal([]byte(input), &ext), "decoding %s", input)
	}
}

// A type built on these helpers is extensible in the sense the rest of this
// package means it, so [jsonutils.GetExtensionJSON] and
// [jsonutils.SetExtensionJSON] work on it too.
func TestExtensibleInteroperatesWithGetSet(t *testing.T) {
	roundTripExtensionJSON(t, extensible{})
}

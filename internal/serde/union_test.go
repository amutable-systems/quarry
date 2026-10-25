// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package serde_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.amutable.dev/quarry/internal/jsonutils"
	"go.amutable.dev/quarry/internal/serde"
)

type shape interface {
	serde.Typed
}

// point has no fields and so can be specified by name alone.
type point struct{}

func (point) Type() string { return "point" }

// circle has a required field.
type circle struct {
	Radius int `json:"radius" toml:"radius"`
}

func (circle) Type() string { return "circle" }

func (c *circle) Validate() error {
	if c.Radius == 0 {
		return fmt.Errorf("%w %q", serde.ErrMissingField, "radius")
	}
	return nil
}

type polygonStyle struct {
	Colour string `json:"colour" toml:"colour"`
}

// polygon has only optional fields, including a nested struct.
type polygon struct {
	Name   string       `json:"name,omitzero"   toml:"name"`
	Points []string     `json:"points,omitzero" toml:"points"`
	Style  polygonStyle `json:"style,omitzero"  toml:"style"`
}

func (polygon) Type() string { return "polygon" }

// lenient handles unknown fields itself.
type lenient struct {
	Known     string                     `json:"known" toml:"known"`
	Extra     map[string]json.RawMessage `json:"-"     toml:"-"`
	TOMLExtra map[string]any             `json:"-"     toml:"-"`
}

func (lenient) Type() string { return "lenient" }

func (l *lenient) UnmarshalJSON(data []byte) error {
	type knownFields lenient
	known, extra, err := jsonutils.UnmarshalExtensible[knownFields](data)
	if err != nil {
		return err
	}
	*l = lenient(known)
	l.Extra = extra
	return nil
}

func (l *lenient) UnmarshalTOML(data any) error {
	fields, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("unexpected %T", data)
	}
	fields = maps.Clone(fields)
	if known, ok := fields["known"].(string); ok {
		l.Known = known
		delete(fields, "known")
	}
	l.TOMLExtra = fields
	return nil
}

// sneaky tries to override the tag field when encoded.
type sneaky struct{}

func (sneaky) Type() string { return "sneaky" }

func (sneaky) MarshalJSON() ([]byte, error) { return []byte(`{"Type":"circle"}`), nil }

var shapes = serde.NewUnion[shape](
	serde.UnionOptions{TagField: "type", Name: "shapes"},
	point{},
	circle{},
	polygon{},
	lenient{},
	sneaky{},
)

func TestNewUnion_Variants(t *testing.T) {
	assert.Equal(t, []shape{point{}, circle{}, polygon{}, lenient{}, sneaky{}}, shapes.Variants())
}

type (
	unnamed     struct{}
	otherCircle struct{}
	named       string
)

func (unnamed) Type() string     { return "" }
func (otherCircle) Type() string { return "circle" }
func (named) Type() string       { return "named" }

func TestNewUnion_Panics(t *testing.T) {
	for _, tc := range []struct {
		name     string
		variants []shape
		opts     serde.UnionOptions
	}{
		{"EmptyTagField", []shape{point{}}, serde.UnionOptions{Name: "test"}},
		{"EmptyType", []shape{unnamed{}}, serde.UnionOptions{TagField: "type"}},
		{"NilVariant", []shape{nil}, serde.UnionOptions{TagField: "type"}},
		{"PointerVariant", []shape{&point{}}, serde.UnionOptions{TagField: "type"}},
		{"NonStructVariant", []shape{named("")}, serde.UnionOptions{TagField: "type"}},
		{"DuplicateType", []shape{circle{}, otherCircle{}}, serde.UnionOptions{TagField: "type"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Panics(t, func() { serde.NewUnion(tc.opts, tc.variants...) })
		})
	}
}

func TestUnion_DecodeJSON(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
		want shape
	}{
		{"Null", `null`, nil},
		{"BareName", `"point"`, point{}},
		{"BareNameObject", `{"type": "point"}`, point{}},
		{"RequiredField", `{"type": "circle", "radius": 2}`, circle{Radius: 2}},
		{"FieldCaseInsensitive", `{"type": "circle", "RADIUS": 3}`, circle{Radius: 3}},
		{"OptionalFields", `{"type": "polygon", "points": ["a", "b"], "style": {"colour": "red"}}`, polygon{Points: []string{"a", "b"}, Style: polygonStyle{Colour: "red"}}},
		{"OptionalFieldsBare", `"polygon"`, polygon{}},
		{"Lenient", `{"type": "lenient", "known": "k", "extra": 1}`, lenient{Known: "k", Extra: map[string]json.RawMessage{"extra": json.RawMessage(`1`)}}},
		{"LenientBare", `"lenient"`, lenient{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := shapes.DecodeJSON([]byte(tc.data))
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestUnion_DecodeJSON_Invalid(t *testing.T) {
	for _, tc := range []struct {
		name    string
		data    string
		wantErr string
	}{
		{"BareRequiredField", `"circle"`, `shapes "circle" cannot be specified by name alone: missing required field "radius"`},
		{"MissingRequiredField", `{"type": "circle"}`, `shapes "circle": missing required field "radius"`},
		{"NullRequiredField", `{"type": "circle", "radius": null}`, `shapes "circle": missing required field "radius"`},
		{"WrongFieldType", `{"type": "circle", "radius": "x"}`, `shapes "circle": json: cannot unmarshal string`},
		{"UnknownField", `{"type": "circle", "radius": 1, "extra": 1}`, `shapes "circle" has unsupported field "extra"`},
		{"NestedUnknownField", `{"type": "polygon", "style": {"colour": "red", "width": 2}}`, `shapes "polygon" has unsupported field "width"`},
		{"TagDiffersInCase", `{"type": "circle", "radius": 1, "Type": "point"}`, `shapes "circle" has unsupported field "Type"`},
		{"TagWrongCase", `{"Type": "circle", "radius": 1}`, `shapes: missing required field "type"`},
		{"MissingTag", `{"radius": 1}`, `shapes: missing required field "type"`},
		{"NumberTag", `{"type": 1}`, `shapes: field "type" has incorrect value type: float64 is not a string`},
		{"NullTag", `{"type": null}`, `shapes: field "type" has incorrect value type: <nil> is not a string`},
		{"Array", `["point"]`, `shapes: expected a string or object, got []interface {}`},
		{"Number", `1`, `shapes: expected a string or object, got float64`},
		{"Boolean", `true`, `shapes: expected a string or object, got bool`},
		{"InvalidJSON", `{"type": `, `shapes: unexpected end of JSON input`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := shapes.DecodeJSON([]byte(tc.data))
			require.Error(t, err)
			assert.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestUnion_DecodeJSON_ErrorTypes(t *testing.T) {
	t.Run("MissingField", func(t *testing.T) {
		_, err := shapes.DecodeJSON([]byte(`"circle"`))
		require.ErrorIs(t, err, serde.ErrMissingField)
	})

	for _, data := range []string{`"hexagon"`, `{"type": "hexagon", "sides": 6}`} {
		t.Run("UnknownType", func(t *testing.T) {
			_, err := shapes.DecodeJSON([]byte(data))
			unknownErr, ok := errors.AsType[*serde.UnknownTypeError](err)
			require.True(t, ok, "error should be UnknownTypeError: %v", err)
			assert.Equal(t, &serde.UnknownTypeError{Union: "shapes", Tag: "hexagon"}, unknownErr)
			assert.EqualError(t, err, `unsupported shapes type "hexagon"`)
		})
	}

	t.Run("UnknownField", func(t *testing.T) {
		_, err := shapes.DecodeJSON([]byte(`{"type": "circle", "radius": 1, "z": 1, "a": 2}`))
		unknownErr, ok := errors.AsType[*serde.UnknownFieldError](err)
		require.True(t, ok, "error should be UnknownFieldError: %v", err)
		assert.Equal(t, &serde.UnknownFieldError{Union: "shapes", Tag: "circle", Field: "a"}, unknownErr)
	})
}

func TestUnion_DecodeJSON_TagField(t *testing.T) {
	upstreams := serde.NewUnion[shape](
		serde.UnionOptions{TagField: "proto", Name: "upstream"},
		point{},
		circle{},
	)

	got, err := upstreams.DecodeJSON([]byte(`{"proto": "circle", "radius": 1}`))
	require.NoError(t, err)
	assert.Equal(t, circle{Radius: 1}, got)

	_, err = upstreams.DecodeJSON([]byte(`{"type": "point"}`))
	require.ErrorIs(t, err, serde.ErrMissingField)
	assert.ErrorContains(t, err, `upstream: missing required field "proto"`)
}

// tomlShape is how a union is expected to be used from a TOML document.
type tomlShape struct{ shape }

func (s *tomlShape) UnmarshalTOML(data any) (err error) {
	s.shape, err = shapes.DecodeTOML(data)
	return err
}

func decodeTOMLShape(t *testing.T, doc string) (shape, error) {
	t.Helper()
	var config struct {
		Shape *tomlShape `toml:"shape"`
	}
	// Start the document on line 2 so that the (misleading) line numbers of
	// the re-encoded document can be distinguished from the real ones.
	meta, err := toml.Decode("\n"+doc, &config)
	if err != nil {
		return nil, err
	}
	assert.Empty(t, meta.Undecoded(), "union keys should all be marked as decoded")
	require.NotNil(t, config.Shape)
	return config.Shape.shape, nil
}

func TestUnion_DecodeTOML(t *testing.T) {
	for _, tc := range []struct {
		name string
		doc  string
		want shape
	}{
		{"BareName", `shape = "point"`, point{}},
		{"BareNameTable", `shape = { type = "point" }`, point{}},
		{"RequiredField", `shape = { type = "circle", radius = 2 }`, circle{Radius: 2}},
		{"OptionalFields", `shape = { type = "polygon", points = ["a", "b"], style = { colour = "red" } }`, polygon{Points: []string{"a", "b"}, Style: polygonStyle{Colour: "red"}}},
		{"Table", "[shape]\ntype = \"polygon\"\nname = \"x\"\n", polygon{Name: "x"}},
		{"Lenient", `shape = { type = "lenient", known = "k", extra = 1 }`, lenient{Known: "k", TOMLExtra: map[string]any{"extra": int64(1)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeTOMLShape(t, tc.doc)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestUnion_DecodeTOML_Invalid(t *testing.T) {
	for _, tc := range []struct {
		name    string
		doc     string
		wantErr string
	}{
		{"BareRequiredField", `shape = "circle"`, `shapes "circle" cannot be specified by name alone: missing required field "radius"`},
		{"MissingRequiredField", `shape = { type = "circle" }`, `shapes "circle": missing required field "radius"`},
		{"WrongFieldType", `shape = { type = "circle", radius = "x" }`, `shapes "circle": toml: (last key "radius"): incompatible types`},
		{"UnknownField", `shape = { type = "circle", radius = 1, extra = 1 }`, `shapes "circle" has unsupported field "extra"`},
		{"NestedUnknownField", `shape = { type = "polygon", style = { colour = "red", width = 2 } }`, `shapes "polygon" has unsupported field "style.width"`},
		{"UnknownTable", `shape = { type = "polygon", foo = { bar = 1, baz = 2 } }`, `shapes "polygon" has unsupported field "foo"`},
		{"MissingTag", `shape = { radius = 1 }`, `shapes: missing required field "type"`},
		{"NumberTag", `shape = { type = 1 }`, `shapes: field "type" has incorrect value type: int64 is not a string`},
		{"UnknownType", `shape = { type = "hexagon" }`, `unsupported shapes type "hexagon"`},
		{"Integer", `shape = 1`, `shapes: expected a string or table, got int64`},
		{"Array", `shape = ["point"]`, `shapes: expected a string or table, got []interface {}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeTOMLShape(t, tc.doc)
			require.ErrorContains(t, err, tc.wantErr)
			// Line numbers from the re-encoded document would be misleading.
			assert.NotContains(t, err.Error(), "line 1 ")
		})
	}
}

func TestUnion_DecodeTOML_DoesNotModifyInput(t *testing.T) {
	data := map[string]any{"type": "circle", "radius": int64(1)}
	got, err := shapes.DecodeTOML(data)
	require.NoError(t, err)
	assert.Equal(t, circle{Radius: 1}, got)
	assert.Equal(t, map[string]any{"type": "circle", "radius": int64(1)}, data)
}

type square struct{}

func (square) Type() string { return "square" }

func TestUnion_EncodeJSON(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value shape
		want  string
	}{
		{"Nil", nil, `null`},
		{"BareName", point{}, `"point"`},
		{"EmptyOptionalFields", polygon{}, `"polygon"`},
		{"Fields", circle{Radius: 2}, `{"radius":2,"type":"circle"}`},
		{"NoHTMLEscape", polygon{Name: "<&>"}, `{"name":"<&>","type":"polygon"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := shapes.EncodeJSON(tc.value)
			require.NoError(t, err)
			assert.Equal(t, tc.want, string(got))

			// Make sure it round-trips.
			decoded, err := shapes.DecodeJSON(got)
			require.NoError(t, err)
			assert.Equal(t, tc.value, decoded)
		})
	}
}

func TestUnion_EncodeJSON_Invalid(t *testing.T) {
	for _, tc := range []struct {
		name    string
		value   shape
		wantErr string
	}{
		{"TagConflict", sneaky{}, `shapes "sneaky": variant field "Type" conflicts with tag field "type"`},
		{"Unregistered", square{}, `shapes: serde_test.square is not a registered variant`},
		{"WrongTypeForTag", otherCircle{}, `shapes: serde_test.otherCircle is not a registered variant`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := shapes.EncodeJSON(tc.value)
			require.Error(t, err)
			assert.ErrorContains(t, err, tc.wantErr)
		})
	}
}

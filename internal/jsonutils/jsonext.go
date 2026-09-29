// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package jsonutils

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ErrNotExtensible is returned by [GetExtensionJSON] and [SetExtensionJSON]
// when given a top-level structure that doesn't support UnrecognizedFields.
var ErrNotExtensible = errors.New("json structure not extensible")

// reParseJSON takes an arbitrary object and then re-parses as though it were
// JSON for the given type parameter. This is necessary to "cast" pre-parsed
// any interfaces into something strongly typed.
func reParseJSON[T any](data any) (T, error) {
	var (
		encoded []byte
		err     error
	)
	switch data := data.(type) {
	case json.RawMessage:
		encoded = []byte(data) // no need to waste cycles
	default:
		encoded, err = MarshalNoEscapeHTML(data)
	}
	if err != nil {
		return *new(T), fmt.Errorf("re-marshal %v (%T): %w", data, data, err)
	}
	return Parse[T](encoded)
}

// GetExtensionJSON returns the JSON-parsed value of the extension with the
// given field name in certain kinds of extensible data objects.
func GetExtensionJSON[T any](extStruct any, field string) (*T, error) {
	// Get the set of structure fields as json.RawMessage so we can re-parse
	// them slightly more efficiently and without triggering parsing errors for
	// other fields.
	structFields, err := reParseJSON[map[string]json.RawMessage](extStruct)
	if err != nil {
		return nil, fmt.Errorf("%w: re-parse %T as generic struct: %w", ErrNotExtensible, extStruct, err)
	}
	extBytes, ok := structFields[field]
	if !ok {
		return nil, nil //nolint:nilnil // nil indicates no extension found
	}
	data, err := Parse[T](extBytes)
	if err != nil {
		return nil, fmt.Errorf("parse extension %v as %T: %w", field, data, err)
	}
	return &data, nil
}

// SetExtensionJSON places the JSON-encoded version of the given data as an
// extension with the given field name. If there was already an existing value
// with the same extension name, the old (unparsed) value is returned.
//
// The value is encoded without HTML escaping (see [MarshalNoEscapeHTML]), as
// otherwise a "&" in something like a URL would be escaped into the stored
// bytes and could never be un-escaped again by a struct that keeps its
// extensions as [json.RawMessage].
func SetExtensionJSON[W any](extStruct *W, field string, value any) (json.RawMessage, error) {
	extBytes, err := MarshalNoEscapeHTML(value)
	if err != nil {
		return nil, fmt.Errorf("marshal value %T: %w", value, err)
	}
	structFields, err := reParseJSON[map[string]json.RawMessage](*extStruct)
	if err != nil {
		return nil, fmt.Errorf("%w: re-parse %T as generic struct: %w", ErrNotExtensible, *new(W), err)
	}

	var oldExtBytes json.RawMessage
	oldExtBytes, structFields[field] = structFields[field], json.RawMessage(extBytes)

	newExtStruct, err := reParseJSON[W](structFields)
	if err != nil {
		return nil, fmt.Errorf("%w: re-parse generic struct to %T: %w", ErrNotExtensible, *new(W), err)
	}

	// Make sure that round-tripping the new extension structure through
	// encoding still includes the same extension fields. If not, then the
	// struct doesn't support extensions of this form.
	roundTripStructFields, err := reParseJSON[map[string]json.RawMessage](newExtStruct)
	if err != nil {
		return nil, fmt.Errorf("%w: re-parse modified %T as generic struct: %w", ErrNotExtensible, *new(W), err)
	}
	if _, ok := roundTripStructFields[field]; !ok {
		return nil, fmt.Errorf("%w: round-tripped %T does not contain extension %q", ErrNotExtensible, *new(W), field)
	}
	// TODO: It might be nice to check if the bytes were also round-tripped
	// properly but this runs into canonicalisation issues very quickly. (And
	// in extreme cases it might not even be comparable.) Users just need to be
	// careful to not use extension field names that match struct field names.

	*extStruct = newExtStruct
	return oldExtBytes, nil
}

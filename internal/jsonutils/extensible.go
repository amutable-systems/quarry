// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package jsonutils

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"strings"
)

// TODO(json-v2): The majority of extensible structure logic here is needed
// because encoding/json/v2 is experimental, and we should switch to it as soon
// as we can (the main feature we want is the "unknown"-tagged
// map[string]jsontext.Value field).

// fieldNames is the set of JSON object keys that a struct type encodes to. The
// names are stored lower-cased because [encoding/json] matches object keys
// against struct fields case-insensitively but we are dealing with
// case-sensitive maps in the rest of our logic.
type fieldNames map[string]struct{}

// has reports whether the given object key names one of the known fields.
func (known fieldNames) has(name string) bool {
	_, ok := known[strings.ToLower(name)]
	return ok
}

// jsonFieldNames returns the [fieldNames] of the given struct type (or of the
// type a pointer type points at). Deriving this from the struct itself, rather
// than having callers hand over a list, means a newly added field can never be
// forgotten and end up being treated as an extension field.
func jsonFieldNames[T any]() (fieldNames, error) {
	typ := reflect.TypeFor[T]()
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		return nil, fmt.Errorf("%w: %v is not a struct", ErrNotExtensible, typ)
	}
	names := make(fieldNames, typ.NumField())
	for _, field := range reflect.VisibleFields(typ) {
		tag := field.Tag.Get("json")
		if !field.IsExported() || tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name == "" {
			name = field.Name
		}
		names[strings.ToLower(name)] = struct{}{}
	}
	return names, nil
}

// MarshalExtensible encodes a struct together with a set of extension fields
// that the struct itself has no field for, for use in the [json.Marshaler] of
// a type that stores its unknown fields in a map. The struct must be passed as
// a type that does *not* implement [json.Marshaler], or encoding it will
// recurse forever.
//
// An extension field whose name collides with one of the struct's own fields
// is dropped -- the typed field always wins, including when it is unset and
// thus not encoded at all, so that an extension can never masquerade as a
// field the caller left empty. Names are compared case-insensitively, as that
// is how [encoding/json] matches them when decoding.
func MarshalExtensible[T any](object T, extensions map[string]json.RawMessage) ([]byte, error) {
	known, err := jsonFieldNames[T]()
	if err != nil {
		return nil, err
	}
	encoded, err := MarshalNoEscapeHTML(object)
	if err != nil {
		return nil, fmt.Errorf("encode %T: %w", object, err)
	}
	// Round-trip the encoded struct through a generic JSON object so that the
	// merged result is produced by the encoder itself.
	fields, err := Parse[map[string]json.RawMessage](encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: re-parse encoded %T as generic struct: %w", ErrNotExtensible, object, err)
	}
	for name, value := range extensions {
		if known.has(name) {
			continue
		}
		if !json.Valid(value) {
			// Checked here rather than left to the encoder below, which would
			// not be able to say which field was at fault.
			return nil, fmt.Errorf("extension field %q is not valid json", name)
		}
		fields[name] = value
	}
	return MarshalNoEscapeHTML(fields)
}

// UnmarshalExtensible decodes a struct, splitting the fields the struct knows
// about (returned as the decoded value, whose type must not implement
// [json.Unmarshaler]) from the extension fields, which are returned unparsed.
// A nil map is returned if there are no extension fields, so that an object
// without any decodes to a value equal to a hand-built one.
func UnmarshalExtensible[T any](data []byte) (T, map[string]json.RawMessage, error) {
	known, err := jsonFieldNames[T]()
	if err != nil {
		return *new(T), nil, err
	}
	object, err := Parse[T](data)
	if err != nil {
		return object, nil, err
	}
	extensions, err := Parse[map[string]json.RawMessage](data)
	if err != nil {
		return object, nil, err
	}
	maps.DeleteFunc(extensions, func(name string, _ json.RawMessage) bool {
		return known.has(name)
	})
	if len(extensions) == 0 {
		extensions = nil
	}
	return object, extensions, nil
}

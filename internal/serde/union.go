// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package serde

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"go.amutable.dev/quarry/internal/jsonutils"
)

// Typed is implemented by every variant of a [Union]. Type returns the value of
// the union's tag field for that variant.
type Typed interface {
	Type() string
}

// Validator is optionally implemented on the pointer receiver of a [Union]
// variant. It is called after decoding and is where required fields are
// checked, because the native decoders cannot distinguish missing fields from
// zero values (or from null). Validate must not modify the variant.
type Validator interface {
	Validate() error
}

// UnionOptions configures a [Union].
type UnionOptions struct {
	// TagField is the key that selects the variant ("type", "proto", ...).
	TagField string
	// Name is used in error messages ("root_trust", "upstream", ...).
	Name string
}

// Union is a set of variants implementing I, selected by a tag field (the
// variant is selected based on [Typed.Type]).
//
// After the tag field has been removed, the rest of the object is decoded into
// the variant using the native decoder for the format (and so struct tags are
// used to define the field names).
//
// Unknown fields result in an [UnknownFieldError]. Variants that wish to
// handle unknown fields themselves can implement [json.Unmarshaler] or
// [toml.Unmarshaler].
//
// A bare string is accepted as shorthand for an object containing only the tag
// field, and variants that encode to an empty object are always encoded as a
// bare string.
//
// The only valid way to create a [Union] is [NewUnion].
type Union[I Typed] struct {
	opts     UnionOptions
	order    []I
	variants map[string]reflect.Type
}

// NewUnion creates a [Union] from the zero values of its variants and is
// primarily intended to be called in a module-level initialisation function.
//
// NewUnion panics if TagField is empty, if a variant is not a struct, or if a
// variant's Type() is empty or is used by more than one variant.
func NewUnion[I Typed](opts UnionOptions, variants ...I) *Union[I] {
	if opts.TagField == "" {
		panic(fmt.Sprintf("serde: union %q must have a TagField", opts.Name))
	}
	union := &Union[I]{
		opts:     opts,
		order:    variants,
		variants: make(map[string]reflect.Type, len(variants)),
	}
	for _, variant := range variants {
		typ := reflect.TypeOf(variant)
		if typ == nil || typ.Kind() != reflect.Struct {
			panic(fmt.Sprintf("serde: union %q variant %v must be a struct", opts.Name, typ))
		}
		tag := variant.Type()
		if tag == "" {
			panic(fmt.Sprintf("serde: union %q variant %v has an empty Type()", opts.Name, typ))
		}
		if other, ok := union.variants[tag]; ok {
			panic(fmt.Sprintf("serde: union %q variants %v and %v have the same Type() %q", opts.Name, other, typ, tag))
		}
		union.variants[tag] = typ
	}
	return union
}

// Variants returns the zero value of every variant, in registration order.
// This is intended for tests that check type switches over I are exhaustive.
func (u *Union[I]) Variants() []I {
	return slices.Clone(u.order)
}

func (u *Union[I]) errorf(tag, format string, args ...any) error {
	return fmt.Errorf("%s %q: %w", u.opts.Name, tag, fmt.Errorf(format, args...))
}

// tag returns the tag value from a generically decoded object.
func (u *Union[I]) tag(fields map[string]any) (string, error) {
	rawTag, ok := fields[u.opts.TagField]
	if !ok {
		return "", fmt.Errorf("%s: %w %q", u.opts.Name, ErrMissingField, u.opts.TagField)
	}
	tag, ok := rawTag.(string)
	if !ok {
		return "", fmt.Errorf("%s: field %q has incorrect value type: %T is not a string", u.opts.Name, u.opts.TagField, rawTag)
	}
	return tag, nil
}

// decode decodes the variant for the given tag using the given decode
// function, and then validates it.
func (u *Union[I]) decode(tag string, bare bool, decode func(ptr any) error) (I, error) {
	typ, ok := u.variants[tag]
	if !ok {
		return *new(I), &UnknownTypeError{Union: u.opts.Name, Tag: tag}
	}
	ptr := reflect.New(typ)
	if err := decode(ptr.Interface()); err != nil {
		return *new(I), err
	}
	if validator, ok := ptr.Interface().(Validator); ok {
		if err := validator.Validate(); err != nil {
			if bare {
				return *new(I), fmt.Errorf("%s %q cannot be specified by name alone: %w", u.opts.Name, tag, err)
			}
			return *new(I), u.errorf(tag, "%w", err)
		}
	}
	return ptr.Elem().Interface().(I), nil //nolint:forcetypeassert // checked by NewUnion
}

// DecodeJSON decodes a JSON value into one of the union's variants. A JSON
// null decodes to the zero value of I.
func (u *Union[I]) DecodeJSON(data []byte) (I, error) {
	value, err := jsonutils.Parse[any](data)
	if err != nil {
		return *new(I), fmt.Errorf("%s: %w", u.opts.Name, err)
	}
	switch value := value.(type) {
	case nil:
		return *new(I), nil
	case string:
		return u.decode(value, true, func(ptr any) error {
			return u.decodeJSON(value, []byte(`{}`), ptr)
		})
	// NOTE: In order to avoid open-coding reflection code, we need to re-parse
	// the same data twice then serialise it before re-parsing it again. Yeah
	// it kinda sucks but this probably won't be a performance problem. I hope.
	case map[string]any:
		tag, err := u.tag(value)
		if err != nil {
			return *new(I), err
		}
		fields, err := jsonutils.Parse[map[string]json.RawMessage](data)
		if err != nil {
			return *new(I), fmt.Errorf("%s: %w", u.opts.Name, err)
		}
		delete(fields, u.opts.TagField)
		rest, err := jsonutils.MarshalNoEscapeHTML(fields)
		if err != nil {
			return *new(I), u.errorf(tag, "re-encode fields: %w", err)
		}
		return u.decode(tag, false, func(ptr any) error {
			return u.decodeJSON(tag, rest, ptr)
		})
	default:
		return *new(I), fmt.Errorf("%s: expected a string or object, got %T", u.opts.Name, value)
	}
}

// decodeJSON decodes data into ptr (the variant for tag), disallowing unknown
// fields.
func (u *Union[I]) decodeJSON(tag string, data []byte, ptr any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(ptr); err != nil {
		// TODO(json-v2): encoding/json reports unknown fields as untyped
		// errors (without the path of nested fields). With encoding/json/v2
		// we'll get structured errors (including JSON field paths).
		if quoted, ok := strings.CutPrefix(err.Error(), "json: unknown field "); ok {
			if field, unquoteErr := strconv.Unquote(quoted); unquoteErr == nil {
				err = &UnknownFieldError{Union: u.opts.Name, Tag: tag, Field: field}
			}
		}
		return u.errorf(tag, "%w", err)
	}
	return nil
}

// DecodeTOML decodes a value (as passed to [toml.Unmarshaler.UnmarshalTOML])
// into one of the union's variants.
func (u *Union[I]) DecodeTOML(data any) (I, error) {
	switch data := data.(type) {
	case string:
		return u.decode(data, true, func(ptr any) error {
			return u.decodeTOML(data, map[string]any{}, ptr)
		})
	case map[string]any:
		tag, err := u.tag(data)
		if err != nil {
			return *new(I), err
		}
		// We need to make a shallow copy of the table because toml.Decoder
		// internally will loop through the map after UnmarshalTOML is called
		// to decide which keys were undecoded and so modifying the map will
		// result in those keys being left marked as undecoded.
		fields := maps.Clone(data)
		delete(fields, u.opts.TagField)
		return u.decode(tag, false, func(ptr any) error {
			return u.decodeTOML(tag, fields, ptr)
		})
	default:
		return *new(I), fmt.Errorf("%s: expected a string or table, got %T", u.opts.Name, data)
	}
}

// decodeTOML decodes fields into ptr (the variant for tag), disallowing unknown
// fields.
func (u *Union[I]) decodeTOML(tag string, fields map[string]any, ptr any) error {
	// There is no public API in BurntSushi/toml to decode a map[string]any
	// into a struct, so round-trip it through the TOML encoder. Unfortunately
	// this means that a lot of stuff gets auto-converted in a potentially
	// lossy way, which might be somewhat problematic but that's TOML for you.
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(fields); err != nil {
		return u.errorf(tag, "re-encode fields: %w", err)
	}
	meta, err := toml.Decode(buf.String(), ptr)
	if err != nil {
		err = prettifyTOMLError(err)
		return u.errorf(tag, "%w", err)
	}
	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		return &UnknownFieldError{Union: u.opts.Name, Tag: tag, Field: undecoded[0].String()}
	}
	return nil
}

// tomlLineRegexp matches the line information that BurntSushi/toml includes in
// some decoding errors.
// TODO: This is awful and fragile.
var tomlLineRegexp = regexp.MustCompile(`^toml: line [0-9]+ `)

// prettifyTOMLError cleans up the errors returned from BurntSushi/toml.
func prettifyTOMLError(err error) error {
	if err == nil {
		return nil
	}
	if parseErr, ok := errors.AsType[toml.ParseError](err); ok {
		if parseErr.LastKey == "" {
			return errors.New(parseErr.Message)
		}
		return fmt.Errorf("field %s: %s", parseErr.LastKey, parseErr.Message)
	}
	// Because we implement TOML decoding by re-encoding map[string]any to
	// a TOML document, the line numbers in the error message become
	// confusing so we strip them out.
	// TODO: Maybe it's better to not do this at all?
	if msg := err.Error(); tomlLineRegexp.MatchString(msg) {
		return errors.New(tomlLineRegexp.ReplaceAllLiteralString(msg, "toml: "))
	}
	return err
}

// EncodeJSON encodes v (which must be one of the union's variants) as JSON. A
// nil v is encoded as a JSON null, and variants which encode to an empty
// object are encoded as a bare string.
//
// Variants that implement [json.Marshaler] must not escape HTML in their
// output (use [jsonutils.MarshalNoEscapeHTML] or
// [jsonutils.MarshalExtensible]).
func (u *Union[I]) EncodeJSON(v I) ([]byte, error) {
	if any(v) == nil {
		return []byte("null"), nil
	}
	tag := v.Type()
	if typ, ok := u.variants[tag]; !ok || typ != reflect.TypeOf(v) {
		return nil, fmt.Errorf("%s: %T is not a registered variant", u.opts.Name, v)
	}

	encoded, err := jsonutils.MarshalNoEscapeHTML(v)
	if err != nil {
		return nil, u.errorf(tag, "%w", err)
	}
	fields, err := jsonutils.Parse[map[string]json.RawMessage](encoded)
	if err != nil || fields == nil {
		return nil, u.errorf(tag, "variant must encode to a JSON object")
	}
	for key := range fields {
		if strings.EqualFold(key, u.opts.TagField) {
			return nil, u.errorf(tag, "variant field %q conflicts with tag field %q", key, u.opts.TagField)
		}
	}

	encodedTag, err := jsonutils.MarshalNoEscapeHTML(tag)
	if err != nil {
		return nil, u.errorf(tag, "%w", err)
	}
	if len(fields) == 0 {
		return encodedTag, nil
	}
	fields[u.opts.TagField] = encodedTag
	return jsonutils.MarshalNoEscapeHTML(fields)
}

// TODO: EncodeTOML? We don't use it so it's easier to skip for now...

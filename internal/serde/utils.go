// Copyright (C) 2026 Amutable GmbH

package serde

import (
	"errors"
	"fmt"
)

// ErrMissingField is returned by [parseMapKey] if the key is missing entirely.
var ErrMissingField = errors.New("missing required field")

// ParseMapKey takes the value from the map with the given key, parses it into
// the given slot, and drops it from the original map. This is quite handy for
// detecting unsupported fields in an ergonomic way when parsing maps from
// encodings like JSON or TOML.
func ParseMapKey[T any](data map[string]any, key string, slot *T) error {
	if valAny, ok := data[key]; !ok {
		return fmt.Errorf("%w %q", ErrMissingField, key)
	} else if val, ok := valAny.(T); !ok {
		return fmt.Errorf("field %q has incorrect value type: %v (%T) is not a %T", key, valAny, valAny, *new(T))
	} else { //nolint:revive // variable chaining makes this uglier vis-a-vis indent-error-flow
		*slot = val
		delete(data, key)
		return nil
	}
}

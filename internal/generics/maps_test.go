// Copyright (C) 2026 Amutable GmbH

package generics_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.amutable.dev/quarry/internal/generics"
)

func TestMapContains(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    map[string]int
		key  string
		want bool
	}{
		{"Present", map[string]int{"a": 1, "b": 2}, "a", true},
		{"Absent", map[string]int{"a": 1, "b": 2}, "c", false},
		{"ZeroValue", map[string]int{"a": 0}, "a", true},
		{"EmptyMap", map[string]int{}, "a", false},
		{"NilMap", nil, "a", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, generics.MapContains(tc.m, tc.key))
		})
	}
}

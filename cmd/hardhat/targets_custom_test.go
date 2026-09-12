// Copyright (C) 2026 Amutable GmbH

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.amutable.dev/quarry/internal/tufext"
)

func customFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "custom.json")              //nolint:forbidigo // test code
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644)) //nolint:forbidigo // test code
	return path
}

func TestApplyCustomFrom(t *testing.T) {
	builder := tufext.NewTargetsBuilder()
	_, err := builder.AddTargetFile("a.raw", 1, hashAlgorithm.FromBytes([]byte("a")))
	require.NoError(t, err)
	existing, err := builder.AddTargetFile("b.raw", 1, hashAlgorithm.FromBytes([]byte("b")))
	require.NoError(t, err)
	old := json.RawMessage(`{"quarry":{"old":true},"keep":1}`)
	existing.Custom = &old

	null := json.RawMessage(`null`)
	_, err = builder.AddTargetFile("c.raw", 1, hashAlgorithm.FromBytes([]byte("c")))
	require.NoError(t, err)
	builder.TargetsType().Targets["c.raw"].Custom = &null

	path := customFile(t, `{
		"a.raw": {"quarry": {"version": "1", "update": true}},
		"b.raw": {"quarry": {"version": "1"}},
		"c.raw": {"quarry": {"version": "1"}}
	}`)
	require.NoError(t, applyCustomFrom(builder, path))

	targets := builder.TargetsType().Targets
	var a map[string]any
	require.NoError(t, json.Unmarshal(*targets["a.raw"].Custom, &a))
	assert.Equal(t, map[string]any{"quarry": map[string]any{"version": "1", "update": true}}, a)

	// Keys are merged at the top level. "quarry" is replaced and "keep" survives.
	var b map[string]any
	require.NoError(t, json.Unmarshal(*targets["b.raw"].Custom, &b))
	assert.Equal(t, map[string]any{"quarry": map[string]any{"version": "1"}, "keep": float64(1)}, b)

	// An existing "custom": null is replaced.
	var c map[string]any
	require.NoError(t, json.Unmarshal(*targets["c.raw"].Custom, &c))
	assert.Equal(t, map[string]any{"quarry": map[string]any{"version": "1"}}, c)
}

func TestApplyCustomFromRejects(t *testing.T) {
	builder := tufext.NewTargetsBuilder()
	_, err := builder.AddTargetFile(".zzz-quarry-special/sysupdate.d=1/ATTR", 1, hashAlgorithm.FromBytes([]byte("a")))
	require.NoError(t, err)
	for content, want := range map[string]string{
		`{"missing.raw": {"quarry": {}}}`:                            `target "missing.raw" does not exist`,
		`["not", "an", "object"]`:                                    "invalid json",
		`{".zzz-quarry-special/sysupdate.d=1/ATTR": {"quarry": {}}}`: "is quarry metadata",
	} {
		require.ErrorContains(t, applyCustomFrom(builder, customFile(t, content)), want, content)
	}
}

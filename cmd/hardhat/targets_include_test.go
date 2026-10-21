// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A signed targets file is included into an unsigned one, which needs no
// keystore.
func TestTargetsUnsignedInclude(t *testing.T) {
	dir := t.TempDir()
	include := filepath.Join(dir, "include.json") //nolint:forbidigo // test code
	doc := `{"signatures": [{"keyid": "x", "sig": "00"}], "signed": {
		"_type": "targets", "spec_version": "1.0.31", "version": 1, "expires": "2030-01-01T00:00:00Z",
		"targets": {
			"a.raw": {"length": 1, "hashes": {"sha256": "` + strings.Repeat("a", 64) + `"}}
		}}}`
	require.NoError(t, os.WriteFile(include, []byte(doc), 0o644)) //nolint:forbidigo // test code
	out := filepath.Join(dir, "targets.json")                     //nolint:forbidigo // test code

	require.NoError(t, targetsCommand.Run(t.Context(), []string{
		"targets",
		"--unsigned",
		"--include-from", include,
		"--output", out,
	}))

	data, err := os.ReadFile(out) //nolint:forbidigo // test code
	require.NoError(t, err)
	var got struct {
		Signatures []json.RawMessage          `json:"signatures"`
		Signed     map[string]json.RawMessage `json:"signed"`
	}
	require.NoError(t, json.Unmarshal(data, &got))
	assert.NotNil(t, got.Signatures)
	assert.Empty(t, got.Signatures)
	// The zero time states that the expiry is not checked.
	assert.JSONEq(t, `"0001-01-01T00:00:00Z"`, string(got.Signed["expires"]))
	var targets map[string]map[string]any
	require.NoError(t, json.Unmarshal(got.Signed["targets"], &targets))
	assert.Contains(t, targets, "a.raw")
}

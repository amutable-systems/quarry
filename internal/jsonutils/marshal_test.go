// Copyright (C) 2026 Amutable GmbH

package jsonutils_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.amutable.dev/quarry/internal/jsonutils"
)

func TestMarshalNoEscapeHTML(t *testing.T) {
	value := map[string]string{"url": "https://example.com/?a=1&b=2<3>4"}

	// [json.Marshal] mangles all three of these characters by default.
	escaped, err := json.Marshal(value)
	require.NoError(t, err)
	assert.JSONEq(t, `{"url":"https://example.com/?a=1&b=2<3>4"}`, string(escaped))
	assert.Contains(t, string(escaped), `\u0026`)

	unescaped, err := jsonutils.MarshalNoEscapeHTML(value)
	require.NoError(t, err)
	//nolint:testifylint // the exact bytes are the point of this test
	assert.Equal(t, `{"url":"https://example.com/?a=1&b=2<3>4"}`, string(unescaped))
}

// Unlike [json.Encoder.Encode], no trailing newline is left behind.
func TestMarshalNoEscapeHTMLNoNewline(t *testing.T) {
	encoded, err := jsonutils.MarshalNoEscapeHTML([]string{"a", "b"})
	require.NoError(t, err)
	assert.Equal(t, `["a","b"]`, string(encoded))
}

func TestMarshalNoEscapeHTMLError(t *testing.T) {
	_, err := jsonutils.MarshalNoEscapeHTML(make(chan int))
	require.Error(t, err)
}

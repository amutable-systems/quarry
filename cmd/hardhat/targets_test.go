// Copyright (C) 2026 Amutable GmbH

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func lengthServer(t *testing.T, handler http.HandlerFunc) *url.URL {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	return u
}

func TestGetContentLength(t *testing.T) {
	body := []byte("some target data")
	u := lengthServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	})

	length, err := getContentLength(t.Context(), u)
	require.NoError(t, err)
	assert.Equal(t, int64(len(body)), length)
}

func TestGetContentLengthNotFound(t *testing.T) {
	// An error page has a Content-Length too; it must not be mistaken
	// for the target's length.
	u := lengthServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no such target", http.StatusNotFound)
	})

	_, err := getContentLength(t.Context(), u)
	require.ErrorContains(t, err, "status code 404")
}

func TestGetContentLengthUnknown(t *testing.T) {
	// Chunked responses carry no Content-Length; -1 must be an error,
	// not a value to store in targets.json.
	u := lengthServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = http.NewResponseController(w).Flush() // forces chunked transfer-encoding
		_, _ = w.Write([]byte("chunk"))
	})

	_, err := getContentLength(t.Context(), u)
	require.ErrorContains(t, err, "no Content-Length")
}

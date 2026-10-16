//go:build insecure

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package tufclient_test

import (
	"bytes"
	"crypto/sha256"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/testrepo"
	"go.amutable.dev/quarry/internal/tufclient"
	"go.amutable.dev/quarry/internal/tufext"
)

const targetPath = "foo/target.txt"

// serverRepo returns the [tufext.Repository] for the given server.
func serverRepo(t *testing.T, srv *testrepo.Server) *tufext.Repository {
	t.Helper()
	cfg := testrepo.Config(t, srv.ConfigBlock("testrepo"))
	repo, ok := cfg.Repos["testrepo"]
	require.True(t, ok, "config did not yield repository testrepo")
	return repo.AsRepository()
}

// targetURLPath returns the URL path the test target is fetched from.
func targetURLPath(srv *testrepo.Server) string {
	return strings.TrimPrefix(srv.DataRootURL(), srv.URL) + "/" + targetPath
}

// failOnFetch registers a handler for the test target's fetch URL that fails
// the test if it receives any request at all. The exact-path pattern takes
// precedence over the server's target file serving.
func failOnFetch(t *testing.T, srv *testrepo.Server) {
	t.Helper()
	srv.Handle(targetURLPath(srv), http.HandlerFunc(func(wtr http.ResponseWriter, req *http.Request) {
		t.Errorf("unexpected request to %s", req.URL)
		http.NotFound(wtr, req)
	}))
}

// serveStatus registers a handler for the given mux pattern that responds
// with an empty body and the given status code.
func serveStatus(srv *testrepo.Server, pattern string, status int) {
	srv.Handle(pattern, http.HandlerFunc(func(wtr http.ResponseWriter, _ *http.Request) {
		wtr.WriteHeader(status)
	}))
}

// newTargetInfo returns a [tufclient.TargetInfo] whose length and hashes match
// data. Any extensions (inline data, override URLs) must be applied in ext
// rather than afterwards -- SetExtensionJSON round-trips the struct through
// JSON, which drops non-JSON fields like Path.
func newTargetInfo(repo *tufext.Repository, data []byte, ext func(*tufmetadata.TargetFiles)) *tufclient.TargetInfo {
	sum := sha256.Sum256(data)
	target := &tufmetadata.TargetFiles{
		Length: int64(len(data)),
		Hashes: tufmetadata.Hashes{"sha256": sum[:]},
	}
	if ext != nil {
		ext(target)
	}
	target.Path = targetPath
	return &tufclient.TargetInfo{
		TargetFiles: target,
		Repo:        repo,
	}
}

// fetchAll fetches the target and reads the entire stream, verifying the
// Close error as required for [hardening.VerifiedReadCloser]-backed streams.
func fetchAll(t *testing.T, info *tufclient.TargetInfo) []byte {
	t.Helper()
	rdr, err := info.Fetch(t.Context())
	require.NoError(t, err)
	got, err := io.ReadAll(rdr)
	require.NoError(t, err)
	require.NoError(t, rdr.Close())
	return got
}

// Valid inline data short-circuits Fetch entirely -- the data is returned from
// the metadata itself without any network access.
func TestTargetInfoFetchInlineData(t *testing.T) {
	data := []byte("inline target file contents")
	srv := testrepo.New(t)
	failOnFetch(t, srv)
	info := newTargetInfo(serverRepo(t, srv), data, func(target *tufmetadata.TargetFiles) {
		tufext.TargetFilesExt(target).WithInlineData(data)
	})

	assert.Equal(t, data, fetchAll(t, info))
}

// A zero-length target (such as a sentinel machine tag) needs no inline data
// to be short-circuited -- its contents are known from the metadata alone, so
// it is never fetched even if the repository did not bother to inline it.
func TestTargetInfoFetchZeroLength(t *testing.T) {
	srv := testrepo.New(t)
	failOnFetch(t, srv)
	info := newTargetInfo(serverRepo(t, srv), []byte{}, nil)

	assert.Empty(t, fetchAll(t, info))
}

// Invalid inline data is not fatal -- Fetch falls back to fetching the target
// from the candidate URLs.
func TestTargetInfoFetchInlineDataCorruptFallback(t *testing.T) {
	data := []byte("the genuine data")
	srv := testrepo.New(t)
	srv.WriteTarget(t, targetPath, bytes.NewReader(data))
	info := newTargetInfo(serverRepo(t, srv), data, func(target *tufmetadata.TargetFiles) {
		tufext.TargetFilesExt(target).WithInlineData([]byte("the corrupt data"))
	})

	assert.Equal(t, data, fetchAll(t, info))
}

// If the inline data is invalid and no candidate URL has the target either
// (the target file was never written, so all fetches 404), a wrapped
// [fs.ErrNotExist] is returned.
func TestTargetInfoFetchInlineDataCorruptNotFound(t *testing.T) {
	data := []byte("the genuine data")
	srv := testrepo.New(t)
	info := newTargetInfo(serverRepo(t, srv), data, func(target *tufmetadata.TargetFiles) {
		tufext.TargetFilesExt(target).WithInlineData([]byte("the corrupt data"))
	})

	_, err := info.Fetch(t.Context())
	require.ErrorIs(t, err, fs.ErrNotExist)
}

// Non-404 fetch errors are not fatal either -- Fetch tries every candidate
// URL before giving up.
func TestTargetInfoFetchBadURLFallback(t *testing.T) {
	data := []byte("the genuine data")
	srv := testrepo.New(t)
	srv.WriteTarget(t, targetPath, bytes.NewReader(data))
	serveStatus(srv, "/error/", http.StatusInternalServerError)
	overrideURL, err := url.Parse(srv.URL + "/error/" + targetPath)
	require.NoError(t, err)
	info := newTargetInfo(serverRepo(t, srv), data, func(target *tufmetadata.TargetFiles) {
		tufext.TargetFilesExt(target).WithOverrideURL(overrideURL)
	})

	assert.Equal(t, data, fetchAll(t, info))
}

// If every candidate URL fails (even with non-404 errors), a wrapped
// [fs.ErrNotExist] is returned.
func TestTargetInfoFetchAllURLsFail(t *testing.T) {
	data := []byte("the genuine data")
	srv := testrepo.New(t)
	// The exact-path pattern overrides the target file serving for the test
	// target, so the data root fails with a non-404 error.
	serveStatus(srv, targetURLPath(srv), http.StatusInternalServerError)
	info := newTargetInfo(serverRepo(t, srv), data, nil)

	_, err := info.Fetch(t.Context())
	require.ErrorIs(t, err, fs.ErrNotExist)
}

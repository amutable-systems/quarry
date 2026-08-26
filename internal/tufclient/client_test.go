// Copyright (C) 2026 Amutable GmbH

package tufclient_test

import (
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/tufclient"
	"go.amutable.dev/quarry/internal/tufclient/config"
	"go.amutable.dev/quarry/internal/tufext"
)

const targetPath = "foo/target.txt"

// testRepo returns a [config.Repository] whose data_root_url is the given base
// URL.
func testRepo(t *testing.T, dataRootURL string) *config.Repository {
	t.Helper()
	conf, err := config.Parse(strings.NewReader(fmt.Sprintf(`
config_version = 1
[repo.testrepo]
root_trust = "insecure-tofu"
data_root_url = %q
`, dataRootURL)))
	require.NoError(t, err)
	return conf.Repos["testrepo"]
}

// newTargetInfo returns a [tufclient.TargetInfo] whose length and hashes match
// data. Any extensions (inline data, override URLs) must be applied in ext
// rather than afterwards -- SetExtensionJSON round-trips the struct through
// JSON, which drops non-JSON fields like Path.
func newTargetInfo(repo *config.Repository, data []byte, ext func(*tufmetadata.TargetFiles)) *tufclient.TargetInfo {
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

// targetServer returns the base URL of an HTTP server that responds with the
// given status and body for requests to the test target's path.
func targetServer(t *testing.T, status int, body []byte) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/"+targetPath, r.URL.Path)
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// unusedServer returns the base URL of an HTTP server that fails the test if
// it receives any request at all.
func unusedServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request to %s", r.URL)
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
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
	repo := testRepo(t, unusedServer(t))
	info := newTargetInfo(repo, data, func(target *tufmetadata.TargetFiles) {
		tufext.TargetFilesExt(target).WithInlineData(data)
	})

	assert.Equal(t, data, fetchAll(t, info))
}

// Invalid inline data is not fatal -- Fetch falls back to fetching the target
// from the candidate URLs.
func TestTargetInfoFetchInlineDataCorruptFallback(t *testing.T) {
	data := []byte("the genuine data")
	repo := testRepo(t, targetServer(t, http.StatusOK, data))
	info := newTargetInfo(repo, data, func(target *tufmetadata.TargetFiles) {
		tufext.TargetFilesExt(target).WithInlineData([]byte("the corrupt data"))
	})

	assert.Equal(t, data, fetchAll(t, info))
}

// If the inline data is invalid and no candidate URL has the target either, a
// wrapped [fs.ErrNotExist] is returned.
func TestTargetInfoFetchInlineDataCorruptNotFound(t *testing.T) {
	data := []byte("the genuine data")
	repo := testRepo(t, targetServer(t, http.StatusNotFound, nil))
	info := newTargetInfo(repo, data, func(target *tufmetadata.TargetFiles) {
		tufext.TargetFilesExt(target).WithInlineData([]byte("the corrupt data"))
	})

	_, err := info.Fetch(t.Context())
	require.ErrorIs(t, err, fs.ErrNotExist)
}

// Non-404 fetch errors are not fatal either -- Fetch tries every candidate
// URL before giving up.
func TestTargetInfoFetchBadURLFallback(t *testing.T) {
	data := []byte("the genuine data")
	repo := testRepo(t, targetServer(t, http.StatusOK, data))
	overrideURL, err := url.Parse(targetServer(t, http.StatusInternalServerError, nil) + "/" + targetPath)
	require.NoError(t, err)
	info := newTargetInfo(repo, data, func(target *tufmetadata.TargetFiles) {
		tufext.TargetFilesExt(target).WithOverrideURL(overrideURL)
	})

	assert.Equal(t, data, fetchAll(t, info))
}

// If every candidate URL fails (even with non-404 errors), a wrapped
// [fs.ErrNotExist] is returned.
func TestTargetInfoFetchAllURLsFail(t *testing.T) {
	data := []byte("the genuine data")
	repo := testRepo(t, targetServer(t, http.StatusInternalServerError, nil))
	info := newTargetInfo(repo, data, nil)

	_, err := info.Fetch(t.Context())
	require.ErrorIs(t, err, fs.ErrNotExist)
}

// Copyright (C) 2026 Amutable GmbH

package tufclient_test

import (
	"crypto/sha256"
	"io"
	"testing"

	"github.com/opencontainers/umoci/pkg/hardening"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/tufclient"
	"go.amutable.dev/quarry/internal/tufclient/config"
	"go.amutable.dev/quarry/internal/tufext"
)

// inlineTargetInfo returns a [tufclient.TargetInfo] whose length and hashes
// match data, with inline embedded as the target's inline data. The repository
// has no DataRootURL, so any attempt to fall back to URL-based fetching would
// crash rather than pass silently.
func inlineTargetInfo(data, inline []byte) *tufclient.TargetInfo {
	sum := sha256.Sum256(data)
	target := &tufmetadata.TargetFiles{
		Length: int64(len(data)),
		Hashes: tufmetadata.Hashes{"sha256": sum[:]},
	}
	tufext.TargetFilesExt(target).WithInlineData(inline)
	// NOTE: Path must be set after WithInlineData -- SetExtensionJSON
	// round-trips the struct through JSON, which drops non-JSON fields.
	target.Path = "foo/inline.txt"
	return &tufclient.TargetInfo{
		TargetFiles: target,
		Repo:        &config.Repository{Name: "testrepo"},
	}
}

// Inline data short-circuits Fetch entirely -- the data is returned from the
// metadata itself without any network access.
func TestTargetInfoFetchInlineData(t *testing.T) {
	data := []byte("inline target file contents")
	info := inlineTargetInfo(data, data)

	rdr, err := info.Fetch(t.Context())
	require.NoError(t, err)
	got, err := io.ReadAll(rdr)
	require.NoError(t, err)
	require.NoError(t, rdr.Close())
	assert.Equal(t, data, got)
}

// Invalid inline data is fatal -- Fetch must not fall back to the fetch URLs,
// as the signed metadata is inconsistent with itself.
func TestTargetInfoFetchInlineDataCorrupt(t *testing.T) {
	info := inlineTargetInfo([]byte("the genuine data"), []byte("the corrupt data"))

	_, err := info.Fetch(t.Context())
	require.ErrorIs(t, err, hardening.ErrDigestMismatch)
}

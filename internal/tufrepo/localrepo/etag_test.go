// Copyright (C) 2026 Amutable GmbH

package localrepo

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	storeopts "go.amutable.dev/quarry/internal/tufrepo/opts"
)

func etagPtr(e storeopts.ETag) *storeopts.ETag { return &e }

func TestEtagMatches(t *testing.T) {
	for _, tc := range []struct {
		name    string
		etag    storeopts.ETag
		policy  *storeopts.ETag
		wantErr bool
	}{
		{"NilPolicyRejects", "abc", nil, true},
		{"NilPolicyRejectsEmpty", "", nil, true},
		{"EmptyPolicyMatchesEmpty", "", etagPtr(""), false},
		{"EmptyPolicyRejectsNonEmpty", "abc", etagPtr(""), true},
		{"WildcardMatchesAny", "abc", etagPtr(storeopts.WildcardETag), false},
		{"WildcardMatchesEmpty", "", etagPtr(storeopts.WildcardETag), false},
		{"ExactMatch", "abc", etagPtr("abc"), false},
		{"ExactMismatch", "abc", etagPtr("xyz"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := etagMatches(tc.etag, tc.policy)
			if tc.wantErr {
				require.ErrorIs(t, err, storeopts.ErrETagMismatch)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDescribePolicy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy *storeopts.ETag
		want   string
	}{
		{"Nil", nil, "no-clobber [default]"},
		{"Empty", etagPtr(""), "no-clobber"},
		{"Wildcard", etagPtr(storeopts.WildcardETag), "clobber-all"},
		{"Custom", etagPtr("abc"), "if-matches-abc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, describePolicy(tc.policy))
		})
	}
}

// openEtagFile creates a new regular file in a per-test tempdir.
func openEtagFile(t *testing.T, name string) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)                  //nolint:forbidigo // test code
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644) //nolint:forbidigo // test code
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestFileEtag_StableAcrossCalls(t *testing.T) {
	f := openEtagFile(t, "f")
	_, err := f.WriteString("hello")
	require.NoError(t, err)

	etag1, err := fileEtag(f)
	require.NoError(t, err)
	assert.NotEmpty(t, etag1)

	etag2, err := fileEtag(f)
	require.NoError(t, err)
	assert.Equal(t, etag1, etag2)
}

func TestFileEtag_DistinctFiles(t *testing.T) {
	f1 := openEtagFile(t, "f1")
	f2 := openEtagFile(t, "f2")

	etag1, err := fileEtag(f1)
	require.NoError(t, err)
	etag2, err := fileEtag(f2)
	require.NoError(t, err)
	assert.NotEqual(t, etag1, etag2)
}

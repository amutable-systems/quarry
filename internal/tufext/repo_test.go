// Copyright (C) 2026 Amutable GmbH

package tufext_test

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.amutable.dev/quarry/internal/tufext"
)

func mustParseURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	require.NoError(t, err)
	return u
}

func TestRepository_URLs(t *testing.T) {
	for _, tc := range []struct {
		name         string
		repo         tufext.Repository
		wantMetaRoot string
		wantDataRoot string
	}{
		{
			name:         "Defaults",
			repo:         tufext.Repository{Name: "updates.example.com/alpha"},
			wantMetaRoot: "https://updates.example.com/alpha",
			wantDataRoot: "https://updates.example.com/alpha/targets",
		},
		{
			name: "MetaRootURL",
			repo: tufext.Repository{
				Name:        "alpha",
				MetaRootURL: mustParseURL(t, "https://meta.example.com/sub"),
			},
			wantMetaRoot: "https://meta.example.com/sub",
			wantDataRoot: "https://meta.example.com/sub/targets",
		},
		{
			name: "BothURLs",
			repo: tufext.Repository{
				Name:        "alpha",
				MetaRootURL: mustParseURL(t, "https://meta.example.com/sub"),
				DataRootURL: mustParseURL(t, "https://data.example.com/blobs"),
			},
			wantMetaRoot: "https://meta.example.com/sub",
			wantDataRoot: "https://data.example.com/blobs",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			metaRootURL, err := tc.repo.RootURL()
			require.NoError(t, err)
			assert.Equal(t, tc.wantMetaRoot, metaRootURL.String())
			dataRootURL, err := tc.repo.DataURL()
			require.NoError(t, err)
			assert.Equal(t, tc.wantDataRoot, dataRootURL.String())

			rootURL, err := tc.repo.RootURL("1.root.json")
			require.NoError(t, err)
			assert.Equal(t, tc.wantMetaRoot+"/1.root.json", rootURL.String())
			targetURL, err := tc.repo.DataURL("foo", "bar.txt")
			require.NoError(t, err)
			assert.Equal(t, tc.wantDataRoot+"/foo/bar.txt", targetURL.String())
		})
	}
}

func TestRepository_URLs_InvalidName(t *testing.T) {
	repo := tufext.Repository{Name: "bad name"}
	_, err := repo.RootURL()
	require.Error(t, err)
	_, err = repo.DataURL()
	require.Error(t, err)

	// The name is only parsed when the metadata URL has to be derived from it.
	repo.MetaRootURL = mustParseURL(t, "https://meta.example.com/sub")
	dataRootURL, err := repo.DataURL()
	require.NoError(t, err)
	assert.Equal(t, "https://meta.example.com/sub/targets", dataRootURL.String())
}

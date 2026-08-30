//go:build insecure

// Copyright (C) 2026 Amutable GmbH

package testrepo_test

import (
	"bytes"
	"io"
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.amutable.dev/quarry/internal/testrepo"
	"go.amutable.dev/quarry/internal/tufclient"
	"go.amutable.dev/quarry/internal/tufclient/config"
)

// newClient constructs a [tufclient.Client] whose resources are cleaned up
// when the test finishes.
func newClient(t *testing.T, cfg *config.Config) *tufclient.Client {
	t.Helper()
	client, err := tufclient.NewClient(t.Context(), cfg)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, client.Close()) })
	return client
}

// clientRepoNames returns the names of all repositories usable by the client.
func clientRepoNames(t *testing.T, client *tufclient.Client) []string {
	t.Helper()
	var names []string
	for name := range client.IterRepos(t.Context()) {
		names = append(names, name)
	}
	return names
}

// fetchAll fetches the given target and returns its contents.
func fetchAll(t *testing.T, info *tufclient.TargetInfo) []byte {
	t.Helper()
	rdr, err := info.Fetch(t.Context())
	require.NoError(t, err)
	data, err := io.ReadAll(rdr)
	require.NoError(t, err)
	require.NoError(t, rdr.Close())
	return data
}

// layouts are the repository layout variants every smoke test should hold
// under: the standard layout (metadata at the repository root, data under
// "targets") and the variants moving either root to a subdirectory.
var layouts = []struct {
	name string
	opts []testrepo.Option
}{
	{"Standard", nil},
	{"MetaSubdir", []testrepo.Option{testrepo.WithMetaSubdir("tufmeta")}},
	{"DataSubdir", []testrepo.Option{testrepo.WithDataSubdir("blobs")}},
	{"MetaAndDataSubdir", []testrepo.Option{
		testrepo.WithMetaSubdir("tufmeta"),
		testrepo.WithDataSubdir("nested/blobs"),
	}},
	// WithDataSubdir("") clears the data prefix, so the roots are swapped
	// compared to the standard layout.
	{"DataAtRoot", []testrepo.Option{
		testrepo.WithMetaSubdir("tufmeta"),
		testrepo.WithDataSubdir(""),
	}},
	// Subdirectory names are cleaned lexically, so slash-wrapped or
	// doubled-slash names must behave like their clean spellings.
	{"MessySubdirNames", []testrepo.Option{
		testrepo.WithMetaSubdir("/tufmeta/"),
		testrepo.WithDataSubdir("nested//blobs/"),
	}},
}

// A bare [testrepo.New] server must produce complete and valid repository
// metadata -- a client must be able to bootstrap trust, load the repository,
// and refresh against it (a missing-target lookup after a successful refresh
// fails with [fs.ErrNotExist], while broken metadata would surface a refresh
// error instead).
func TestNew_ClientRefreshable(t *testing.T) {
	for _, layout := range layouts {
		t.Run(layout.name, func(t *testing.T) {
			srv := testrepo.New(t, layout.opts...)
			client := newClient(t, testrepo.Config(t, srv.ConfigBlock("test-repo")))
			require.Equal(t, []string{"test-repo"}, clientRepoNames(t, client))

			_, err := client.GetTargetInfo(t.Context(), "no/such/target")
			require.ErrorIs(t, err, fs.ErrNotExist)
		})
	}
}

// Targets published through transactions must be visible to clients, with
// their contents fetchable as real files from the targets subdirectory.
func TestServer_PublishFlow(t *testing.T) {
	seedData, updateData := []byte("seeded data"), []byte("updated data")

	for _, layout := range layouts {
		t.Run(layout.name, func(t *testing.T) {
			srv := testrepo.New(t, layout.opts...)
			cfg := testrepo.Config(t, srv.ConfigBlock("test-repo"))
			srv.Publish(t, srv.AddTarget(t, "seed.txt", bytes.NewReader(seedData)))

			client := newClient(t, cfg)
			info, err := client.GetTargetInfo(t.Context(), "seed.txt")
			require.NoError(t, err)
			assert.Equal(t, seedData, fetchAll(t, info))

			srv.Publish(t, srv.AddTarget(t, "nested/update.txt", bytes.NewReader(updateData)))

			// A go-tuf updater only refreshes once, so use a fresh client
			// (sharing the same metadata cache directory) to observe the
			// update.
			client2 := newClient(t, cfg)
			info, err = client2.GetTargetInfo(t.Context(), "nested/update.txt")
			require.NoError(t, err)
			assert.Equal(t, updateData, fetchAll(t, info))

			// The published update must not have lost the earlier target.
			_, err = client2.GetTargetInfo(t.Context(), "seed.txt")
			require.NoError(t, err)
		})
	}
}

// ConfigBlock must support bootstrapping trust without TOFU -- both inline
// and bundled root_trust blocks must produce a loadable, refreshable
// repository whose initial root.json comes from the trust source.
func TestConfigBlock_RootTrusts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		trust func(srv *testrepo.Server, t *testing.T) testrepo.ConfigRootTrust
	}{
		{"Inline", (*testrepo.Server).InlineTrust},
		{"Bundled", (*testrepo.Server).BundledTrust},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte("trusted data")
			srv := testrepo.New(t)
			srv.Publish(t, srv.AddTarget(t, "file.txt", bytes.NewReader(data)))

			cfg := testrepo.Config(t,
				srv.ConfigBlock("test-repo", testrepo.ConfigWithRootTrust(tc.trust(srv, t))))
			client := newClient(t, cfg)
			require.Equal(t, []string{"test-repo"}, clientRepoNames(t, client))

			info, err := client.GetTargetInfo(t.Context(), "file.txt")
			require.NoError(t, err)
			assert.Equal(t, data, fetchAll(t, info))
		})
	}
}

// [testrepo.NewBroken] servers must be treated as skippable by NewClient.
func TestNewBroken_Skippable(t *testing.T) {
	broken := testrepo.NewBroken(t)
	client := newClient(t, testrepo.Config(t, broken.ConfigBlock("broken-repo")))
	assert.Empty(t, clientRepoNames(t, client))
}

// t.TempDir embeds the test name, so [testrepo.Config] must %-escape the
// cache_dir for subtests with "%" in their name to survive config expansion.
func TestConfig_PercentInTestName(t *testing.T) {
	t.Run("100%", func(t *testing.T) {
		srv := testrepo.New(t)
		cfg := testrepo.Config(t, srv.ConfigBlock("test-repo"))
		// Guards against this test becoming vacuous: if t.TempDir ever stops
		// preserving "%" from test names, the escaping is no longer exercised.
		require.Contains(t, cfg.CacheDir, "%")

		client := newClient(t, cfg)
		assert.Equal(t, []string{"test-repo"}, clientRepoNames(t, client))
	})
}

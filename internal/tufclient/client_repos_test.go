//go:build insecure

// Copyright (C) 2026 Amutable GmbH

package tufclient_test

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

// clientRepoNames returns the names of all repositories usable by the client,
// in iteration order.
func clientRepoNames(t *testing.T, client *tufclient.Client) []string {
	t.Helper()
	var names []string
	for name := range client.IterRepos(t.Context()) {
		names = append(names, name)
	}
	return names
}

// Repositories whose root.json cannot be fetched from the root_trust source
// are silently dropped from the client rather than causing a fatal error.
func TestNewClient_SkipsBrokenRepo(t *testing.T) {
	valid, broken := testrepo.New(t), testrepo.NewBroken(t)
	cfg := testrepo.Config(t,
		valid.ConfigBlock("valid-repo"),
		broken.ConfigBlock("broken-repo"),
	)

	client := newClient(t, cfg)
	assert.Equal(t, []string{"valid-repo"}, clientRepoNames(t, client))
}

// A client with no usable repositories is valid but all lookups fail with
// [fs.ErrNotExist].
func TestNewClient_NoUsableRepos(t *testing.T) {
	broken := testrepo.NewBroken(t)
	cfg := testrepo.Config(t, broken.ConfigBlock("broken-repo"))

	client := newClient(t, cfg)
	assert.Empty(t, clientRepoNames(t, client))

	_, err := client.GetTargetInfo(t.Context(), "some/target.txt")
	require.ErrorIs(t, err, fs.ErrNotExist)
}

// WithRepos restricts the client to the given repositories.
func TestWithRepos(t *testing.T) {
	repoA, repoB, repoC := testrepo.New(t), testrepo.New(t), testrepo.New(t)
	cfg := testrepo.Config(t,
		repoA.ConfigBlock("repo-a"),
		repoB.ConfigBlock("repo-b"),
		repoC.ConfigBlock("repo-c"),
	)

	client := newClient(t, cfg)
	require.ElementsMatch(t, []string{"repo-a", "repo-b", "repo-c"}, clientRepoNames(t, client))

	require.NoError(t, client.WithRepos("repo-a"))
	assert.Equal(t, []string{"repo-a"}, clientRepoNames(t, client))

	require.NoError(t, client.WithRepos("repo-a", "repo-c"))
	assert.ElementsMatch(t, []string{"repo-a", "repo-c"}, clientRepoNames(t, client))
}

// Calling WithRepos with no names re-enables all loaded repositories.
func TestWithRepos_EmptyReenablesAll(t *testing.T) {
	repoA, repoB := testrepo.New(t), testrepo.New(t)
	cfg := testrepo.Config(t,
		repoA.ConfigBlock("repo-a"),
		repoB.ConfigBlock("repo-b"),
	)

	client := newClient(t, cfg)
	require.NoError(t, client.WithRepos("repo-a"))
	require.Equal(t, []string{"repo-a"}, clientRepoNames(t, client))

	require.NoError(t, client.WithRepos())
	assert.ElementsMatch(t, []string{"repo-a", "repo-b"}, clientRepoNames(t, client))
}

// Requesting a repository that is not defined in the configuration at all is
// an error.
func TestWithRepos_UnknownRepo(t *testing.T) {
	valid := testrepo.New(t)
	cfg := testrepo.Config(t, valid.ConfigBlock("valid-repo"))

	client := newClient(t, cfg)
	err := client.WithRepos("nonexistent-repo")
	require.ErrorContains(t, err, "unknown repository nonexistent-repo")

	// A failed subset is not applied -- the previous state is kept.
	assert.Equal(t, []string{"valid-repo"}, clientRepoNames(t, client))
}

// Explicitly requesting a repository that failed to load (and so was skipped
// by NewClient) returns the load error instead of silently dropping the
// repository from the subset.
func TestWithRepos_BrokenRepoError(t *testing.T) {
	valid, broken := testrepo.New(t), testrepo.NewBroken(t)
	cfg := testrepo.Config(t,
		valid.ConfigBlock("valid-repo"),
		broken.ConfigBlock("broken-repo"),
	)

	client := newClient(t, cfg)

	err := client.WithRepos("broken-repo")
	require.ErrorIs(t, err, tufclient.ErrSkippableRepo)
	require.ErrorContains(t, err, "broken-repo")

	// The subset also fails if only some of the requested repositories are
	// broken.
	err = client.WithRepos("valid-repo", "broken-repo")
	require.ErrorIs(t, err, tufclient.ErrSkippableRepo)

	// A failed subset is not applied -- the previous state is kept.
	assert.Equal(t, []string{"valid-repo"}, clientRepoNames(t, client))
}

// A skipped repository outside the requested subset does not cause an error.
func TestWithRepos_SkippedRepoOutsideSubset(t *testing.T) {
	valid, broken := testrepo.New(t), testrepo.NewBroken(t)
	cfg := testrepo.Config(t,
		valid.ConfigBlock("valid-repo"),
		broken.ConfigBlock("broken-repo"),
	)

	client := newClient(t, cfg)
	require.NoError(t, client.WithRepos("valid-repo"))
	assert.Equal(t, []string{"valid-repo"}, clientRepoNames(t, client))
}

// A repository whose remote root_trust source serves an invalid root.json is
// skippable -- NewClient drops it, but WithRepos still surfaces the
// underlying validation error if the repository is requested explicitly.
func TestNewClient_SkipsInvalidRemoteRoot(t *testing.T) {
	valid, invalid := testrepo.New(t), testrepo.NewBroken(t)
	invalid.Handle("/1.root.json", http.HandlerFunc(func(wtr http.ResponseWriter, _ *http.Request) {
		_, _ = wtr.Write([]byte("this is not json {"))
	}))
	cfg := testrepo.Config(t,
		valid.ConfigBlock("valid-repo"),
		invalid.ConfigBlock("invalid-repo"),
	)

	client := newClient(t, cfg)
	assert.Equal(t, []string{"valid-repo"}, clientRepoNames(t, client))

	err := client.WithRepos("invalid-repo")
	require.ErrorIs(t, err, tufclient.ErrSkippableRepo)
	require.ErrorContains(t, err, "root_trust root.json is invalid JSON")
}

// A repository with a non-remote root_trust source that fails to load is a
// fatal error for NewClient, never a skippable one -- local sources are meant
// to always exist and be valid.
func TestNewClient_LocalRootTrustFatal(t *testing.T) {
	for _, test := range []struct {
		name, trustValue, expectedErr string
	}{
		{"BundledMissingPath", `{ type = "bundled", path = "/nonexistent/quarry-test/root.json" }`, "fetch trusted root.json"},
		{"InlineInvalidJSON", `{ type = "inline", "root.json" = 'this is not json {' }`, "root_trust root.json is invalid JSON"},
	} {
		t.Run(test.name, func(t *testing.T) {
			srv := testrepo.New(t)
			cfg := testrepo.Config(t,
				srv.ConfigBlock("local-trust-repo", testrepo.ConfigWithRootTrust(testrepo.ConfigRootTrust{
					RawValue: test.trustValue,
				})),
			)

			_, err := tufclient.NewClient(t.Context(), cfg)
			require.Error(t, err)
			require.NotErrorIs(t, err, tufclient.ErrSkippableRepo,
				"errors from non-remote root_trust sources must not be skippable")
			require.ErrorContains(t, err, "bad repo local-trust-repo")
			require.ErrorContains(t, err, test.expectedErr)
		})
	}
}

// Once a repository's root.json has been cached, the root_trust source is no
// longer consulted -- a broken local trust source does not stop the client
// from loading the repository from the cache.
func TestNewClient_CachedRootIgnoresRootTrust(t *testing.T) {
	srv := testrepo.New(t)

	rootJSON, err := srv.Root.ToBytes(false)
	require.NoError(t, err)
	rootPath := filepath.Join(t.TempDir(), "root.json")         //nolint:forbidigo // test code writing inside a test tempdir
	require.NoError(t, os.WriteFile(rootPath, rootJSON, 0o644)) //nolint:forbidigo // test code writing inside a test tempdir

	// bundled paths are %-expanded by config.Parse, and t.TempDir() embeds
	// the test name -- which may contain "%" for some subtests.
	escapedPath := strings.ReplaceAll(rootPath, "%", "%%")
	cfg := testrepo.Config(t,
		srv.ConfigBlock("cached-repo", testrepo.ConfigWithRootTrust(testrepo.ConfigRootTrust{
			RawValue: fmt.Sprintf(`{ type = "bundled", path = %q }`, escapedPath),
		})),
	)

	// The first client fetches root.json from the bundled path and caches it.
	client := newClient(t, cfg)
	assert.Equal(t, []string{"cached-repo"}, clientRepoNames(t, client))

	// Remove the bundled file -- a fresh client sharing the same cache_dir
	// must still load the repository from the cached root.json, even though
	// the (fatal, non-remote) trust source is now broken.
	require.NoError(t, os.Remove(rootPath)) //nolint:forbidigo // test code removing a file inside a test tempdir
	client = newClient(t, cfg)
	assert.Equal(t, []string{"cached-repo"}, clientRepoNames(t, client))
}

//go:build insecure

// Copyright (C) 2026 Amutable GmbH

package tufclient_test

import (
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

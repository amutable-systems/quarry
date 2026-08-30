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

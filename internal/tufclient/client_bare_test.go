//go:build insecure

// Copyright (C) 2026 Amutable GmbH

package tufclient_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/testrepo"
)

// httpGet fetches a URL of the test server.
func httpGet(t *testing.T, url string) []byte {
	t.Helper()
	res, err := http.Get(url) //nolint:noctx // test code
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	require.Equal(t, http.StatusOK, res.StatusCode, url)
	data, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return data
}

// publishedTargetsURL returns the URL of the server's current signed
// targets.json.
func publishedTargetsURL(t *testing.T, srv *testrepo.Server) string {
	t.Helper()
	targets, err := srv.TxnStart(t).TargetsRoleData(t.Context(), tufmetadata.TARGETS)
	require.NoError(t, err)
	return fmt.Sprintf("%s/%d.targets.json", srv.MetaRootURL(), targets.Signed.Version)
}

// bareConfigBlock configures the server's repository as a bare targets file
// (the server's own signed targets.json, trusted through its root).
func bareConfigBlock(t *testing.T, srv *testrepo.Server, name, targetsURL string, opts ...testrepo.ConfigBlockOption) string {
	t.Helper()
	return srv.ConfigBlock(name, append([]testrepo.ConfigBlockOption{
		testrepo.ConfigWithRootTrust(srv.InlineTrust(t)),
		testrepo.ConfigWithExtraLines(fmt.Sprintf("targets_url = %q", targetsURL)),
	}, opts...)...)
}

// A bare targets repository lists and serves exactly what its signed
// targets.json says, without any snapshot or timestamp.
func TestBareTargets_ListAndFetch(t *testing.T) {
	targetData := []byte("hello bare targets")
	srv := testrepo.New(t)
	srv.Publish(t, srv.AddTarget(t, "foo/hello.txt", bytes.NewReader(targetData)))

	cfg := testrepo.Config(t, bareConfigBlock(t, srv, "bare", publishedTargetsURL(t, srv)))
	require.True(t, cfg.Repos["bare"].IsBareTargets())
	client := newClient(t, cfg)
	assert.Equal(t, []string{"bare"}, clientRepoNames(t, client))

	var paths []string
	for info, err := range client.IterTargetFiles(t.Context()) {
		require.NoError(t, err)
		assert.Equal(t, "bare", info.Repo.Name)
		paths = append(paths, info.Path)
	}
	assert.Equal(t, []string{"foo/hello.txt"}, paths)

	info, err := client.GetTargetInfo(t.Context(), "foo/hello.txt")
	require.NoError(t, err)
	assert.Equal(t, "foo/hello.txt", info.Path)
	assert.Equal(t, targetData, fetchAll(t, info))

	_, err = client.GetTargetInfo(t.Context(), "missing.txt")
	require.ErrorIs(t, err, fs.ErrNotExist)

	for _, repo := range client.IterRepos(t.Context()) {
		expiry, err := repo.Expiry(t.Context())
		require.NoError(t, err)
		assert.True(t, expiry.After(time.Now()), "targets.json expiry %s should lie ahead", expiry)
	}
}

// A targets file whose signature does not verify against the trusted root is
// rejected, as is one that has expired or cannot be found. The error is not
// masked by a later repository that has the target.
func TestBareTargets_Rejected(t *testing.T) {
	srv := testrepo.New(t)
	srv.Publish(t, srv.AddTarget(t, "foo/hello.txt", bytes.NewReader([]byte("x"))))
	targetsURL := publishedTargetsURL(t, srv)

	// In the tampered file the signed body changes but the signature does not.
	var tampered map[string]any
	require.NoError(t, json.Unmarshal(httpGet(t, targetsURL), &tampered))
	signed, ok := tampered["signed"].(map[string]any)
	require.True(t, ok, "targets.json has no signed object")
	signed["expires"] = "2999-01-01T00:00:00Z"
	tamperedJSON, err := json.Marshal(tampered)
	require.NoError(t, err)
	srv.Handle("/tampered/targets.json", http.HandlerFunc(func(wtr http.ResponseWriter, _ *http.Request) {
		_, _ = wtr.Write(tamperedJSON)
	}))

	for _, tc := range []struct {
		name, url, wantErr string
		notExist           bool
	}{
		{name: "Tampered", url: srv.URL + "/tampered/targets.json", wantErr: "not signed by the trusted root"},
		{name: "Missing", url: srv.URL + "/nowhere/targets.json", wantErr: "status code 404", notExist: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testrepo.Config(t,
				bareConfigBlock(t, srv, "bare", tc.url),
				srv.ConfigBlock("full", configWithOrderIndex(200)),
			)
			client := newClient(t, cfg)
			assert.Equal(t, []string{"bare", "full"}, clientRepoNames(t, client))
			_, err := client.GetTargetInfo(t.Context(), "foo/hello.txt")
			require.ErrorContains(t, err, "refresh repo bare")
			require.ErrorContains(t, err, tc.wantErr)
			if tc.notExist {
				require.ErrorIs(t, err, fs.ErrNotExist)
			}
		})
	}

	t.Run("Expired", func(t *testing.T) {
		cfg := testrepo.Config(t, bareConfigBlock(t, srv, "bare", targetsURL))
		client := newClient(t, cfg)
		client.SetRefTime(t.Context(), time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC))
		_, err := client.GetTargetInfo(t.Context(), "foo/hello.txt")
		require.ErrorContains(t, err, "expired")
	})
}

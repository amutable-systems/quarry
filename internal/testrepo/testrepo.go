//go:build insecure

// Copyright (C) 2026 Amutable GmbH

// Package testrepo provides helpers for constructing real TUF repositories
// served over HTTP, to test [go.amutable.dev/quarry/internal/tufclient]
// clients in an end-to-end fashion.
//
// Each server is backed by an actual [tufrepo.Repository], so tests can
// publish updates through regular [tufrepo.Transaction] operations and
// immediately observe them from the client side.
//
// As the repository metadata is signed using the insecure keystore driver,
// this package is only available when building with the "insecure" build tag.
package testrepo

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/keystore"
	_ "go.amutable.dev/quarry/internal/keystore/insecure" // register the insecure driver
	"go.amutable.dev/quarry/internal/tufclient/config"
	"go.amutable.dev/quarry/internal/tufext"
	"go.amutable.dev/quarry/internal/tufrepo"
	"go.amutable.dev/quarry/internal/tufrepo/localrepo"
)

// Server is a TUF repository served over HTTP for use in tests.
type Server struct {
	// URL is the base URL of the underlying HTTP server. By default the layout
	// is the standard TUF layout but [WithMetaSubdir] and [WithDataSubdir]
	// modify that -- see [MetaRootURL] and [DataRootURL].
	URL string

	// Repo is the repository whose metadata is served at the meta root.
	// Updates published to it (with [Server.Publish], or manually with
	// [Server.TxnStart] and [Server.TxnCommit]) are immediately visible to
	// clients.
	// It is nil for servers created with [NewBroken].
	Repo *tufrepo.Repository

	// Keys is the keystore containing the signing keys for all of the
	// repository roles.
	// It is nil for servers created with [NewBroken].
	Keys *keystore.Store

	// Root is the initial 1.root.json for the repository.
	// It is nil for servers created with [NewBroken].
	Root *tufext.SignedRoot

	mux *http.ServeMux

	// targetsDir is the directory containing the real target files, served
	// under the data root of the repository. It is a t.TempDir() and so will
	// disappear after the test completes.
	targetsDir string

	// metaPrefix is the URL subdirectory the TUF metadata is served under.
	metaPrefix string

	// dataPrefix is the URL subdirectory the target data is served under.
	dataPrefix string
}

// Option configures a [Server] created by [New].
type Option func(*Server)

// WithMetaSubdir serves the TUF metadata under the given subdirectory of the
// repository URL instead of at its root (the standard layout).
func WithMetaSubdir(dir string) Option {
	return func(srv *Server) { srv.metaPrefix = subdirPrefix(dir) }
}

// WithDataSubdir serves the target data under the given subdirectory of the
// repository URL instead of the standard "targets".
func WithDataSubdir(dir string) Option {
	return func(srv *Server) { srv.dataPrefix = subdirPrefix(dir) }
}

// subdirPrefix converts a subdirectory name into a cleaned URL prefix, with
// "" meaning the root of the repository URL.
func subdirPrefix(dir string) string {
	return strings.TrimSuffix(path.Join("/", dir), "/") //nolint:forbidigo // lexical path and test code
}

func newServer(t *testing.T) *Server {
	t.Helper()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &Server{URL: srv.URL, mux: mux}
}

// New creates a new [Server] with a brand-new empty TUF repository and a fresh
// HTTP server. Once the test completes the server is shut down and all data is
// cleared.
func New(t *testing.T, opts ...Option) *Server {
	t.Helper()
	ctx := t.Context()

	store, err := keystore.OpenStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	repoStore, err := localrepo.Open(t.TempDir())
	require.NoError(t, err)
	repo, err := tufrepo.Open(repoStore)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, repo.Close()) })

	// Generate all role keys implicitly, no need for key segregation.
	root, _, err := tufext.NewRootBuilder().Sign(ctx, store)
	require.NoError(t, err)

	// Include a dummy targets.json in the initial transaction so fetching the
	// repo will still succeed even if nothing has been added yet.
	tx := tufrepo.InitTxn(root)
	targets := tufext.DefaultTargets(tx.RefTime.Add(tufrepo.DefaultTargetsExpiry))
	require.NoError(t, tx.UpdateRoleData(tufmetadata.TARGETS, targets))

	newKeys, err := tx.Sign(ctx, store)
	require.NoError(t, err)
	require.Empty(t, newKeys,
		"Sign must never generate keys for an InitTxn (keys are only rotated for pre-existing roots)")
	_, err = repo.TxnCommit(ctx, tx)
	require.NoError(t, err)

	srv := newServer(t)
	srv.Repo = repo
	srv.Keys = store
	srv.Root = root
	srv.targetsDir = t.TempDir()
	srv.dataPrefix = "/targets"
	for _, opt := range opts {
		opt(srv)
	}
	// Registering two handlers on the same pattern panics with a cryptic
	// ServeMux error, so fail with a clearer message instead.
	// TODO: Our current update server has this setup, should we support it?
	require.NotEqualf(t, srv.metaPrefix, srv.dataPrefix,
		"metadata and target data cannot both be served at prefix %q", srv.metaPrefix+"/")
	srv.mux.HandleFunc(srv.metaPrefix+"/", srv.serveMeta)
	srv.mux.Handle(srv.dataPrefix+"/",
		http.StripPrefix(srv.dataPrefix+"/",
			http.FileServer(http.Dir(srv.targetsDir))))
	return srv
}

// NewBroken starts a HTTP server that responds with 404 to every request,
// making any repository served by it "skippable" by
// [go.amutable.dev/quarry/internal/tufclient.NewClient].
func NewBroken(t *testing.T) *Server {
	t.Helper()
	return newServer(t)
}

// serveMeta serves the current repository metadata blobs from the meta root.
func (srv *Server) serveMeta(wtr http.ResponseWriter, req *http.Request) {
	key := strings.TrimPrefix(req.URL.Path, srv.metaPrefix+"/")
	rdr, _, err := srv.Repo.GetBlob(req.Context(), key)
	if err != nil {
		http.NotFound(wtr, req)
		return
	}
	defer func() { _ = rdr.Close() }()
	_, _ = io.Copy(wtr, rdr)
}

// TxnStart creates a new transaction for the repository and is a convenience
// wrapper around srv.Repo.TxnStart. Commit the modified [tufrepo.Transaction]
// with [Server.TxnCommit] (or manually with srv.Repo.TxnCommit) to publish the
// changes. Most tests should use [Server.Publish] instead.
func (srv *Server) TxnStart(t *testing.T) *tufrepo.Transaction {
	t.Helper()
	tx, err := srv.Repo.TxnStart(t.Context())
	require.NoError(t, err)
	return tx
}

// TxnCommit signs the [tufrepo.Transaction] and commits it, making it a
// convenience wrapper for doing [tufrepo.Transaction.Sign] and
// srv.Repo.TxnCommit manually. The update is immediately visible to clients.
// The new timestamp.json of the repository is returned.
func (srv *Server) TxnCommit(t *testing.T, tx *tufrepo.Transaction) *tufext.SignedTimestamp {
	t.Helper()
	_, err := tx.Sign(t.Context(), srv.Keys)
	require.NoError(t, err)
	timestamp, err := srv.Repo.TxnCommit(t.Context(), tx)
	require.NoError(t, err)
	return timestamp
}

// Publish applies the given [tufrepo.TxnOp] operations to the repository in a
// single transaction, making the update immediately visible to clients. The
// new timestamp.json of the repository is returned.
func (srv *Server) Publish(t *testing.T, ops ...tufrepo.TxnOp) *tufext.SignedTimestamp {
	t.Helper()
	tx := srv.TxnStart(t)
	require.NoError(t, tx.Apply(t.Context(), ops...))
	return srv.TxnCommit(t, tx)
}

// WriteTarget writes a target file with the given contents into the server's
// target data directory (creating parent directories as needed) and returns
// the TUF metadata describing it. If the file already exists, this operation
// will clobber it *inatomically* (which may cause issues with some tests).
func (srv *Server) WriteTarget(t *testing.T, path string, data io.Reader) *tufmetadata.TargetFiles {
	t.Helper()
	// Make sure we have a place to store files.
	require.NotEmpty(t, srv.targetsDir,
		"cannot write targets to a server created with NewBroken")

	filePath := filepath.Join(srv.targetsDir, path)                //nolint:forbidigo // test code writing inside a test tempdir
	require.NoError(t, os.MkdirAll(filepath.Dir(filePath), 0o755)) //nolint:forbidigo // test code writing inside a test tempdir
	file, err := os.Create(filePath)                               //nolint:forbidigo // test code writing inside a test tempdir
	require.NoError(t, err)

	hasher := sha256.New()
	length, copyErr := io.Copy(file, io.TeeReader(data, hasher))
	closeErr := file.Close()
	require.NoError(t, copyErr)
	require.NoError(t, closeErr)

	return &tufmetadata.TargetFiles{
		Length: length,
		Hashes: tufmetadata.Hashes{"sha256": hasher.Sum(nil)},
		Path:   path,
	}
}

// AddTargetOp returns a [tufrepo.TxnOp] that adds (or replaces) the given
// target file metadata in the top-level targets role under the given path.
func AddTargetOp(path string, target *tufmetadata.TargetFiles) tufrepo.TxnOp {
	return tufrepo.NewTxnOp(fmt.Sprintf("testrepo: add target %q", path),
		func(ctx context.Context, tx *tufrepo.Transaction) error {
			targets, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
			if err != nil {
				return err
			}
			targets.Signed.Targets[path] = target
			return tx.UpdateRoleData(tufmetadata.TARGETS, targets)
		})
}

// AddTarget is a convenience wrapper around [Server.WriteTarget] and
// [AddTargetOp]. It writes the target file and returns a [tufrepo.TxnOp] to
// update a repository to reference the file. Note that the file's lifetime is
// independent of the operation and so failed operations will not clear the
// file.
func (srv *Server) AddTarget(t *testing.T, path string, data io.Reader) tufrepo.TxnOp {
	t.Helper()
	return AddTargetOp(path, srv.WriteTarget(t, path, data))
}

// MetaRootURL returns the meta_root_url of this repository (the repository
// root by default, or the given subdirectory with [WithMetaSubdir]).
func (srv *Server) MetaRootURL() string { return srv.URL + srv.metaPrefix }

// DataRootURL returns the data_root_url of this repository (the standard
// "targets" subdirectory by default, or the given subdirectory with
// [WithDataSubdir]).
func (srv *Server) DataRootURL() string { return srv.URL + srv.dataPrefix }

// Handle registers an additional handler on the repository server (to serve
// content outside the standard metadata and targets layout). Paths not
// registered by anything respond with 404.
func (srv *Server) Handle(pattern string, handler http.Handler) {
	srv.mux.Handle(pattern, handler)
}

// ConfigRootTrust is a pre-rendered TOML value for a repository's root_trust
// key. The zero value renders as "insecure-tofu"; use [Server.InlineTrust] or
// [Server.BundledTrust] to bootstrap trust from a server's root.json without
// TOFU, or set RawValue directly for anything else.
type ConfigRootTrust struct {
	// RawValue is the TOML value emitted verbatim for the root_trust key. An
	// empty RawValue is emitted as "insecure-tofu".
	RawValue string
}

// value returns the TOML value to emit for the root_trust key.
func (trust ConfigRootTrust) value() string {
	if trust.RawValue == "" {
		return `"insecure-tofu"`
	}
	return trust.RawValue
}

// InlineTrust returns a root_trust value embedding the server's root.json
// inline (root_trust = { type = "inline", "root.json" = '...' }).
func (srv *Server) InlineTrust(t *testing.T) ConfigRootTrust {
	t.Helper()
	require.NotNil(t, srv.Root, "cannot create an inline root trust for a server created with NewBroken")

	rootJSON, err := srv.Root.ToBytes(false)
	require.NoError(t, err)
	// TOML literal strings cannot contain single quotes or newlines, but
	// compact JSON output contains neither. Guard against that changing.
	require.NotContains(t, string(rootJSON), "'")
	require.NotContains(t, string(rootJSON), "\n")

	return ConfigRootTrust{
		RawValue: fmt.Sprintf(`{ type = "inline", "root.json" = '%s' }`, rootJSON),
	}
}

// BundledTrust writes the server's root.json to a file in a fresh test
// tempdir and returns a root_trust value referencing it
// (root_trust = { type = "bundled", path = "..." }).
func (srv *Server) BundledTrust(t *testing.T) ConfigRootTrust {
	t.Helper()
	require.NotNil(t, srv.Root, "cannot create a bundled root trust for a server created with NewBroken")

	rootJSON, err := srv.Root.ToBytes(false)
	require.NoError(t, err)
	rootPath := filepath.Join(t.TempDir(), "root.json")         //nolint:forbidigo // test code writing inside a test tempdir
	require.NoError(t, os.WriteFile(rootPath, rootJSON, 0o644)) //nolint:forbidigo // test code writing inside a test tempdir

	// bundled paths are %-expanded by config.Parse, and t.TempDir() embeds
	// the test name -- which may contain "%" for some subtests.
	escapedPath := strings.ReplaceAll(rootPath, "%", "%%")
	return ConfigRootTrust{
		RawValue: fmt.Sprintf(`{ type = "bundled", path = %q }`, escapedPath),
	}
}

// ConfigRepoBlock describes the TOML repository block emitted by
// [Server.ConfigBlock] and can be modified by [ConfigBlockOption] functions.
type ConfigRepoBlock struct {
	// RootTrust is the root_trust value for the repository.
	// By default this is "insecure-tofu".
	RootTrust ConfigRootTrust

	// ExtraLines are appended verbatim to the repository table.
	ExtraLines []string
}

// ConfigBlockOption modifies the [ConfigRepoBlock] emitted by
// [Server.ConfigBlock].
type ConfigBlockOption func(*ConfigRepoBlock)

// ConfigWithRootTrust sets the root_trust value of the repository block (such
// as [Server.InlineTrust] or [Server.BundledTrust]).
func ConfigWithRootTrust(trust ConfigRootTrust) ConfigBlockOption {
	return func(block *ConfigRepoBlock) { block.RootTrust = trust }
}

// ConfigWithExtraLines appends the given lines verbatim to the repository
// block.
func ConfigWithExtraLines(lines ...string) ConfigBlockOption {
	return func(block *ConfigRepoBlock) {
		block.ExtraLines = append(block.ExtraLines, lines...)
	}
}

// ConfigBlock returns a TOML fragment defining a repository called name that
// is served by this server, customised by the given [ConfigBlockOption]
// options.
func (srv *Server) ConfigBlock(name string, opts ...ConfigBlockOption) string {
	var cfg ConfigRepoBlock
	for _, opt := range opts {
		opt(&cfg)
	}

	var block strings.Builder
	block.WriteByte('\n')
	fmt.Fprintf(&block, "[repo.%q]\n", name)
	fmt.Fprintf(&block, "root_trust = %s\n", cfg.RootTrust.value())
	fmt.Fprintf(&block, "meta_root_url = %q\n", srv.MetaRootURL())
	fmt.Fprintf(&block, "data_root_url = %q\n", srv.DataRootURL())
	for _, line := range cfg.ExtraLines {
		fmt.Fprintln(&block, line)
	}
	return block.String()
}

// Config assembles and parses a quarry-client configuration from the given
// repository blocks (usually built with [Server.ConfigBlock]), with cache_dir
// set to a fresh test-scoped temporary directory.
func Config(t *testing.T, repoBlocks ...string) *config.Config {
	t.Helper()

	// cache_dir is %-expanded by config.Parse, and t.TempDir() embeds the
	// test name -- which may contain "%" for some subtests.
	cacheDir := strings.ReplaceAll(t.TempDir(), "%", "%%")

	var configFile strings.Builder
	fmt.Fprintln(&configFile, "config_version = 1")
	fmt.Fprintf(&configFile, "cache_dir = %q\n", cacheDir)
	for _, block := range repoBlocks {
		fmt.Fprintln(&configFile, block)
	}

	cfg, err := config.Parse(strings.NewReader(configFile.String()))
	require.NoError(t, err)
	return cfg
}

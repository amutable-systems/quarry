//go:build insecure

// Copyright (C) 2026 Amutable GmbH

package xsysupdate

import (
	"context"
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyphar.com/go-pathrs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/testrepo"
	"go.amutable.dev/quarry/internal/transferlayout"
	"go.amutable.dev/quarry/internal/tufclient"
	"go.amutable.dev/quarry/internal/tufclient/config"
	"go.amutable.dev/quarry/internal/tufext"
)

var testRepo = &config.Repository{Name: "test.example.com/repo"}

// testEnv's paths are EvalSymlinks'd so they match the canonicalised names
// that libpathrs caches on the corresponding [pathrs.Root] handles.
type testEnv struct {
	rootPath string
	etcPath  string
	storeDir string
}

func setupTestEnv(t *testing.T) (*testEnv, context.Context) {
	t.Helper()

	etc, err := filepath.EvalSymlinks(t.TempDir()) //nolint:forbidigo // test code
	require.NoError(t, err)
	origHostDir := hostDefinitionsDir
	hostDefinitionsDir = etc
	t.Cleanup(func() { hostDefinitionsDir = origHostDir })

	rootPath, err := filepath.EvalSymlinks(t.TempDir()) //nolint:forbidigo // test code
	require.NoError(t, err)
	root, err := pathrs.OpenRoot(rootPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = root.Close() })

	ctx := context.WithValue(context.Background(), RootDirCtxKey, root)

	return &testEnv{
		rootPath: rootPath,
		etcPath:  etc,
		storeDir: filepath.Join(rootPath, "transfers"), //nolint:forbidigo // test code
	}, ctx
}

func initExt(ctx context.Context, t *testing.T) *TransferFileExtension {
	t.Helper()
	ext := &TransferFileExtension{}
	_, err := ext.Init(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ext.Close() })
	return ext
}

// makeRepo returns the [config.Repository] backed by the given test
// repository server.
func makeRepo(t *testing.T, srv *testrepo.Server, name string) *config.Repository {
	t.Helper()
	cfg := testrepo.Config(t, srv.ConfigBlock(name))
	repo, ok := cfg.Repos[name]
	require.True(t, ok, "testrepo config did not yield repository %q", name)
	return repo
}

// inlineTarget returns a target whose data is embedded in its metadata, so
// that Fetch needs no repository server.
func inlineTarget(path string, data []byte) *tufclient.TargetInfo {
	sum := sha256.Sum256(data)
	target := &tufmetadata.TargetFiles{
		Path:   path,
		Length: int64(len(data)),
		Hashes: tufmetadata.Hashes{"sha256": sum[:]},
	}
	tufext.TargetFilesExt(target).WithInlineData(data)
	// Embedding round-trips the struct through JSON, which drops the
	// (json:"-") path a client otherwise takes from the metadata key.
	target.Path = path
	return &tufclient.TargetInfo{TargetFiles: target, Repo: testRepo}
}

func applyAll(ctx context.Context, t *testing.T, ext *TransferFileExtension, infos ...*tufclient.TargetInfo) {
	t.Helper()
	for _, info := range infos {
		applied, err := ext.ApplyTarget(ctx, info)
		require.NoError(t, err, "target %s", info.Path)
		require.True(t, applied, "target %s", info.Path)
	}
}

func TestParseTransferPath(t *testing.T) {
	for _, tc := range []struct {
		path                     string
		component, version, file string
		ok, wantErr              bool
	}{
		{path: "regular/target.bin"},
		{path: ".zzz-quarry-special/machine-tags/amutable.foo"},
		{path: ".zzz-quarry-special/sysupdate-other/x"}, // another extension, not claimed
		{path: ".zzz-quarry-special/sysupdate"},
		{path: ".zzz-quarry-special/sysupdate.d=1/10-usr.transfer", version: "1", file: "10-usr.transfer", ok: true},
		{path: ".zzz-quarry-special/sysupdate.d=1.2.3/10-usr.transfer", version: "1.2.3", file: "10-usr.transfer", ok: true},
		{path: ".zzz-quarry-special/sysupdate.k8s.d=1/ATTR", component: "k8s", version: "1", file: "ATTR", ok: true},
		{path: ".zzz-quarry-special/sysupdate.d=20260901.0/ATTR", version: "20260901.0", file: "ATTR", ok: true},
		{path: ".zzz-quarry-special/sysupdate.k8s.d=1.0~rc1/k8s.transfer", component: "k8s", version: "1.0~rc1", file: "k8s.transfer", ok: true},
		{path: ".zzz-quarry-special/sysupdate.k8s.d=1/k8s.transfer.d/10-x.conf", component: "k8s", version: "1", file: "k8s.transfer.d/10-x.conf", ok: true},
		// This is the unversioned layout of the transition period.
		{path: ".zzz-quarry-special/sysupdate.d/10-usr.transfer", file: "10-usr.transfer", ok: true},
		{path: ".zzz-quarry-special/sysupdate.k8s.d/k8s.transfer", component: "k8s", file: "k8s.transfer", ok: true},
		// These are malformed. They are part of the extension but rejected.
		{path: ".zzz-quarry-special/sysupdate.d=/10-usr.transfer", ok: true, wantErr: true},
		{path: ".zzz-quarry-special/sysupdate.d@1/10-usr.transfer", ok: true, wantErr: true},         // a version needs the "="
		{path: ".zzz-quarry-special/sysupdate.d=nightly@1/10-usr.transfer", ok: true, wantErr: true}, // "@" is reserved
		{path: ".zzz-quarry-special/sysupdate.d=1@nightly/10-usr.transfer", ok: true, wantErr: true},
		{path: ".zzz-quarry-special/sysupdate.d=a=b/10-usr.transfer", ok: true, wantErr: true},
		{path: ".zzz-quarry-special/sysupdate.d=1", ok: true, wantErr: true},
		{path: ".zzz-quarry-special/sysupdate.d=1/", ok: true, wantErr: true},
		{path: ".zzz-quarry-special/sysupdate.d=1/../x.transfer", ok: true, wantErr: true},
		{path: ".zzz-quarry-special/sysupdate.d=1/a//b", ok: true, wantErr: true},
		{path: ".zzz-quarry-special/sysupdate.d=1/./b", ok: true, wantErr: true},
		{path: ".zzz-quarry-special/sysupdate..d@1/x.transfer", ok: true, wantErr: true},
		{path: ".zzz-quarry-special/sysupdate.a.b.d@1/x.transfer", ok: true, wantErr: true},
		{path: ".zzz-quarry-special/sysupdate.foo@1/x.transfer", ok: true, wantErr: true},
		{path: ".zzz-quarry-special/sysupdate.default.d=1/x.transfer", ok: true, wantErr: true}, // reserved name
		{path: ".zzz-quarry-special/sysupdate@1/x.transfer", ok: true, wantErr: true},
		{path: ".zzz-quarry-special/sysupdate.transfer", ok: true, wantErr: true},
		{path: ".zzz-quarry-special/sysupdate.foo/x.transfer", ok: true, wantErr: true},
	} {
		component, version, file, ok, err := ParseTransferPath(tc.path)
		assert.Equal(t, tc.ok, ok, "path %q", tc.path)
		if tc.wantErr {
			require.Error(t, err, "path %q", tc.path)
			continue
		}
		require.NoError(t, err, "path %q", tc.path)
		assert.Equal(t, tc.component, component, "path %q", tc.path)
		assert.Equal(t, tc.version, version, "path %q", tc.path)
		assert.Equal(t, tc.file, file, "path %q", tc.path)
	}

	// What hardhat writes (transferlayout) parses back to the same values.
	for _, tc := range []struct{ component, version, file string }{
		{"", "26.09.05", "12-usr.transfer"},
		{"", "26.09.05", "docker.feature"},
		{"k8s", "1.0~rc1", "k8s.transfer.d/10-x.conf"},
		{"k8s", "1", transferlayout.AttrFileName},
	} {
		path, err := transferlayout.TargetPath(transferlayout.ComponentDir(tc.component), tc.version, tc.file)
		require.NoError(t, err)
		component, version, file, ok, err := ParseTransferPath(path)
		require.NoError(t, err, path)
		assert.True(t, ok, path)
		assert.Equal(t, tc.component, component, path)
		assert.Equal(t, tc.version, version, path)
		assert.Equal(t, tc.file, file, path)
	}
	tagPath, err := transferlayout.MachineTagPath("acp.x")
	require.NoError(t, err)
	assert.Equal(t, TagsPrefix+"acp.x", tagPath)
}

func TestInit_FreshStore(t *testing.T) {
	env, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	require.NotNil(t, ext.storeDir)
	entries, err := os.ReadDir(env.storeDir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

// Staging directories of earlier runs (kept on failure) are removed.
func TestInit_PrunesStaleRuns(t *testing.T) {
	env, ctx := setupTestEnv(t)
	stale := filepath.Join(env.storeDir, "sysupdate.foo.d", "sysupdate.foo.d")                 //nolint:forbidigo // test code
	require.NoError(t, os.MkdirAll(stale, 0o755))                                              //nolint:forbidigo // test code
	require.NoError(t, os.WriteFile(filepath.Join(stale, "foo.transfer"), []byte("x"), 0o644)) //nolint:forbidigo // test code

	initExt(ctx, t)

	_, err := os.Stat(filepath.Join(env.storeDir, "sysupdate.foo.d")) //nolint:forbidigo // test code
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

func TestApplyTarget_NotForUs(t *testing.T) {
	_, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	applied, err := ext.ApplyTarget(ctx, inlineTarget("regular/target.bin", []byte("x")))
	require.NoError(t, err)
	assert.False(t, applied)
	applied, err = ext.ApplyTarget(ctx, inlineTarget(".zzz-quarry-special/machine-tags/amutable.foo", nil))
	require.NoError(t, err)
	assert.False(t, applied)
	assert.Empty(t, ext.Transfers())
}

func TestApplyTarget_Collects(t *testing.T) {
	_, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	transfer := []byte("[Transfer]\nProtectVersion=%A\n")
	applyAll(ctx, t, ext,
		inlineTarget(".zzz-quarry-special/sysupdate.d=2/10-usr.transfer", transfer),
		inlineTarget(".zzz-quarry-special/sysupdate.d=2/docker.feature", []byte("[Feature]\n")),
		inlineTarget(".zzz-quarry-special/sysupdate.d=2/ATTR", []byte(`{"pre-enabled": true, "features": {"docker": {"tag": "amutable.ext.docker"}}, "future": 1}`)),
		inlineTarget(".zzz-quarry-special/sysupdate.d=10/10-usr.transfer", transfer),
		inlineTarget(".zzz-quarry-special/sysupdate.d=10/ATTR", []byte(`{"pre-enabled": true}`)),
		inlineTarget(".zzz-quarry-special/sysupdate.d=3/10-usr.transfer", transfer),
		inlineTarget(".zzz-quarry-special/sysupdate.d=3/ATTR", []byte(`{"pre-enabled": true, "validity": "stepping-stone"}`)),
		inlineTarget(".zzz-quarry-special/sysupdate.foo.d=1/foo.transfer", transfer),
		inlineTarget(".zzz-quarry-special/sysupdate.foo.d=1/ATTR", []byte(`{"tag": "amutable.foo"}`)),
		// For duplicates (e.g. from a second repository), the first one wins. This holds for ATTR too.
		inlineTarget(".zzz-quarry-special/sysupdate.d=2/10-usr.transfer", []byte("[Transfer]\nother=1\n")),
		inlineTarget(".zzz-quarry-special/sysupdate.d=2/ATTR", []byte(`{"tag": "amutable.later"}`)),
		// This is a pre-enabled component with a tag that only pins.
		inlineTarget(".zzz-quarry-special/sysupdate.bar.d=1/bar.transfer", transfer),
		inlineTarget(".zzz-quarry-special/sysupdate.bar.d=1/ATTR", []byte(`{"pre-enabled": true, "tag": "amutable.bar"}`)),
		// Unusable directories are collected but dropped by Transfers.
		inlineTarget(".zzz-quarry-special/sysupdate.d=4/ATTR", []byte(`{"pre-enabled": true}`)), // no definitions
		inlineTarget(".zzz-quarry-special/sysupdate.d=5/10-usr.transfer", transfer),
		inlineTarget(".zzz-quarry-special/sysupdate.d=5/ATTR", []byte(`not json`)),
		inlineTarget(".zzz-quarry-special/sysupdate.d=6/10-usr.transfer", transfer),
		inlineTarget(".zzz-quarry-special/sysupdate.d=6/ATTR", []byte(`{"pre-enabled": true, "validity": "sometime"}`)),
		inlineTarget(".zzz-quarry-special/sysupdate.d=7/10-usr.transfer", transfer),
		inlineTarget(".zzz-quarry-special/sysupdate.d=7/ATTR", []byte(`{"tag": "a=b"}`)), // a tag is a bare key
		inlineTarget(".zzz-quarry-special/sysupdate.d=8/10-usr.transfer", transfer),      // without ATTR, it is neither pre-enabled nor gated
		inlineTarget(".zzz-quarry-special/sysupdate.d=9/10-usr.transfer", transfer),
		inlineTarget(".zzz-quarry-special/sysupdate.d=9/ATTR", []byte(`{}`)),
		inlineTarget(".zzz-quarry-special/sysupdate.baz.d/baz.transfer", transfer), // unversioned stepping stone
		inlineTarget(".zzz-quarry-special/sysupdate.baz.d/ATTR", []byte(`{"tag": "amutable.baz", "validity": "stepping-stone"}`)),
		// The unversioned layout only counts while a component has no versioned directory.
		inlineTarget(".zzz-quarry-special/sysupdate.d/10-usr.transfer", transfer), // TODO(transition): no ATTR needed
		inlineTarget(".zzz-quarry-special/sysupdate.legacy.d/legacy.transfer", transfer),
		inlineTarget(".zzz-quarry-special/sysupdate.legacy.d/ATTR", []byte(`{"tag": "amutable.legacy"}`)),
		// Malformed paths are claimed (and ignored) rather than aborting.
		inlineTarget(".zzz-quarry-special/sysupdate.d=/10-usr.transfer", transfer),
	)

	transfers := ext.Transfers()
	require.Len(t, transfers, 4)
	require.Len(t, transfers["bar"], 1)
	assert.True(t, transfers["bar"][0].Attr.PreEnabled, "a pre-enabled component")
	assert.Equal(t, "amutable.bar", transfers["bar"][0].Attr.Tag)
	require.Len(t, transfers[""], 3)
	assert.Equal(t, "2", transfers[""][0].Version)
	assert.Equal(t, "3", transfers[""][1].Version)
	assert.Equal(t, "10", transfers[""][2].Version)
	assert.True(t, transfers[""][1].SteppingStone())
	assert.False(t, transfers[""][2].SteppingStone())
	assert.True(t, transfers[""][2].Attr.PreEnabled)
	assert.Empty(t, transfers[""][2].Attr.Tag)
	assert.Equal(t, []string{"10-usr.transfer", "docker.feature"}, transfers[""][0].Files())
	assert.Equal(t, map[string]transferlayout.FeatureAttr{"docker": {Tag: "amutable.ext.docker"}}, transfers[""][0].Attr.Features)
	assert.Empty(t, transfers[""][0].Attr.Tag, "the first ATTR wins")
	assert.Equal(t, ".zzz-quarry-special/sysupdate.d=2", transfers[""][0].String())
	require.Len(t, transfers["foo"], 1)
	assert.Equal(t, "amutable.foo", transfers["foo"][0].Attr.Tag)
	assert.False(t, transfers["foo"][0].Attr.PreEnabled)
	assert.Equal(t, ".zzz-quarry-special/sysupdate.foo.d=1", transfers["foo"][0].String())
	require.Len(t, transfers["legacy"], 1)
	assert.Empty(t, transfers["legacy"][0].Version)
	assert.True(t, transfers["legacy"][0].Attr.PreEnabled, "an unversioned directory counts as pre-enabled")
	assert.Equal(t, "amutable.legacy", transfers["legacy"][0].Attr.Tag)
	assert.Equal(t, ".zzz-quarry-special/sysupdate.legacy.d", transfers["legacy"][0].String())
}

func TestStage_DefaultComponent(t *testing.T) {
	env, ctx := setupTestEnv(t)
	proxyURL := "http://localhost:9999/"
	ext := &TransferFileExtension{OverrideSourcePathURL: &proxyURL}
	_, err := ext.Init(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ext.Close() })

	transfer := []byte(strings.TrimSpace(`
[Transfer]
MinVersion=2
MaxVersion=2

[Source]
Type=url-file
Path=https://upstream.example.com/orig/
MatchPattern=**/foo_@v.raw

[Target]
Type=partition
MatchPattern=foo_@v
`) + "\n")
	applyAll(ctx, t, ext,
		inlineTarget(".zzz-quarry-special/sysupdate.d=2/10-usr.transfer", transfer),
		inlineTarget(".zzz-quarry-special/sysupdate.d=2/docker.feature", []byte("[Feature]\nEnabled=false\nSuggestOnMachineTag=amutable.ext.docker\n")),
		inlineTarget(".zzz-quarry-special/sysupdate.d=2/containerd.feature", []byte("[Feature]\nSuggestOnMachineTag=amutable.ext.containerd\n")),
		inlineTarget(".zzz-quarry-special/sysupdate.d=2/10-usr.transfer.d/x.conf", []byte("[Transfer]\nVerify=no\n")),
		inlineTarget(".zzz-quarry-special/sysupdate.d=2/ATTR", []byte(`{"pre-enabled": true, "features": {"docker": {"tag": "amutable.ext.docker"}, "containerd": {"tag": "amutable.ext.containerd"}}}`)),
	)
	dir := ext.Transfers()[""][0]

	staged, err := ext.Stage(ctx, dir, StageOptions{MachineTags: []string{"amutable.ext.docker", "acp.x=1"}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = staged.Close() })

	stagePath := filepath.Join(env.storeDir, "sysupdate.d") //nolint:forbidigo // test code
	assert.Equal(t, stagePath, staged.Path())
	assert.Empty(t, staged.Component)
	assert.Equal(t, "2", staged.Version)
	assert.Equal(t, []string{"docker"}, staged.EnabledFeatures)
	assert.Equal(t, []string{stagePath + "/sysupdate.d:/run/sysupdate.d"}, staged.BindPaths())

	out, err := os.ReadFile(filepath.Join(stagePath, "sysupdate.d", "10-usr.transfer")) //nolint:forbidigo // test code
	require.NoError(t, err)
	cfg, err := loadINI(out)
	require.NoError(t, err)
	assert.Equal(t, proxyURL, cfg.Section("Source").Key("Path").String())
	assert.Equal(t, "**/foo_@v.raw", cfg.Section("Source").Key("MatchPattern").String())
	assert.Equal(t, "2", cfg.Section("Transfer").Key("MinVersion").String())
	assert.Equal(t, "2", cfg.Section("Transfer").Key("MaxVersion").String())

	out, err = os.ReadFile(filepath.Join(stagePath, "sysupdate.d", "docker.feature")) //nolint:forbidigo // test code
	require.NoError(t, err)
	cfg, err = loadINI(out)
	require.NoError(t, err)
	assert.Equal(t, "true", cfg.Section("Feature").Key("Enabled").String())

	// A feature the machine does not enable is left as shipped. Enabled= is
	// only ever set to true and never written as false.
	out, err = os.ReadFile(filepath.Join(stagePath, "sysupdate.d", "containerd.feature")) //nolint:forbidigo // test code
	require.NoError(t, err)
	cfg, err = loadINI(out)
	require.NoError(t, err)
	assert.False(t, cfg.Section("Feature").HasKey("Enabled"))

	// Other files are staged verbatim, nested paths included.
	out, err = os.ReadFile(filepath.Join(stagePath, "sysupdate.d", "10-usr.transfer.d", "x.conf")) //nolint:forbidigo // test code
	require.NoError(t, err)
	assert.Equal(t, "[Transfer]\nVerify=no\n", string(out))

	// ATTR is metadata, not a definition. The default component gets no
	// component file.
	_, err = os.Stat(filepath.Join(stagePath, "sysupdate.d", transferlayout.AttrFileName)) //nolint:forbidigo // test code
	require.ErrorIs(t, err, fs.ErrNotExist)
	entries, err := os.ReadDir(stagePath)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "sysupdate.d", entries[0].Name())

	// Remove deletes the component's staging directory.
	require.NoError(t, staged.Remove())
	_, err = os.Stat(stagePath)
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

func TestStage_Component(t *testing.T) {
	env, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	applyAll(ctx, t, ext,
		inlineTarget(".zzz-quarry-special/sysupdate.foo.d=1.0/foo.transfer", []byte("[Transfer]\n\n[Source]\nType=url-file\nPath=https://example.com/\n")),
		inlineTarget(".zzz-quarry-special/sysupdate.foo.d=1.0/foo.component", []byte("[Component]\nDescription=Foo\nEnabled=false\n")),
		inlineTarget(".zzz-quarry-special/sysupdate.foo.d=1.0/ATTR", []byte(`{"tag": "amutable.foo"}`)),
	)
	dir := ext.Transfers()["foo"][0]

	staged, err := ext.Stage(ctx, dir, StageOptions{MachineTags: []string{"amutable.foo"}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = staged.Close() })

	stagePath := filepath.Join(env.storeDir, "sysupdate.foo.d") //nolint:forbidigo // test code
	assert.Equal(t, []string{
		stagePath + "/sysupdate.foo.d:/run/sysupdate.foo.d",
		stagePath + "/sysupdate.foo.component:/run/sysupdate.foo.component",
	}, staged.BindPaths())

	// The shipped component file is the base of the sibling component file
	// and is not staged inside the definitions directory.
	out, err := os.ReadFile(filepath.Join(stagePath, "sysupdate.foo.component")) //nolint:forbidigo // test code
	require.NoError(t, err)
	cfg, err := loadINI(out)
	require.NoError(t, err)
	assert.Equal(t, "Foo", cfg.Section("Component").Key("Description").String())
	assert.Equal(t, "true", cfg.Section("Component").Key("Enabled").String())
	_, err = os.Stat(filepath.Join(stagePath, "sysupdate.foo.d", "foo.component")) //nolint:forbidigo // test code
	require.ErrorIs(t, err, fs.ErrNotExist)

	// Without a configured override URL, the source path is untouched.
	out, err = os.ReadFile(filepath.Join(stagePath, "sysupdate.foo.d", "foo.transfer")) //nolint:forbidigo // test code
	require.NoError(t, err)
	cfg, err = loadINI(out)
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/", cfg.Section("Source").Key("Path").String())

	// A failed run keeps the staging directory (Close only), which the next
	// run's Init prunes.
	require.NoError(t, staged.Close())
	require.NoError(t, ext.Close())
	_, err = os.Stat(stagePath)
	require.NoError(t, err)
	initExt(ctx, t)
	_, err = os.Stat(stagePath)
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

// Staging rewrites transfer, feature and component files and keeps the rest
// of each file as it is.
func TestStage_Rewrites(t *testing.T) {
	proxyURL := "http://proxy/"
	for _, tc := range []struct {
		name     string
		attr     string
		files    map[string]string // in sysupdate.foo.d=1/
		override *string
		tags     []string
		want     map[string]string // in the staging directory
	}{
		{
			name: "transfer keeps repeated keys",
			attr: `{"tag": "amutable.foo"}`,
			files: map[string]string{
				"foo.transfer": "[Transfer]\nProtectVersion=%A\n\n[Source]\nType=url-file\nPath=https://example.com/\nMatchPattern=foo_@v.raw\nMatchPattern=**/foo_@v.raw\n",
			},
			override: &proxyURL,
			want: map[string]string{
				"sysupdate.foo.d/foo.transfer": "[Transfer]\nProtectVersion=%A\n\n[Source]\nType=url-file\nMatchPattern=foo_@v.raw\nMatchPattern=**/foo_@v.raw\nPath=http://proxy/\n",
				// A component without a shipped component file gets a generated one.
				"sysupdate.foo.component": "[Component]\nEnabled=true\n",
			},
		},
		{
			name:     "transfer without source section",
			attr:     `{"tag": "amutable.foo"}`,
			files:    map[string]string{"foo.transfer": "[Target]\nType=partition\n"},
			override: &proxyURL,
			want:     map[string]string{"sysupdate.foo.d/foo.transfer": "[Target]\nType=partition\n\n[Source]\nPath=http://proxy/\n"},
		},
		{
			name: "features",
			attr: `{"tag": "amutable.foo", "features": {"docker": {"tag": "amutable.ext.docker"}, "containerd": {"tag": "amutable.ext.containerd"}}}`,
			files: map[string]string{
				"docker.feature":      "[Feature]\nDescription=Docker\nEnabled=false\n",
				"containerd.feature":  "[Feature]\nEnabled=false\n",
				"interactive.feature": "[Feature]\nEnabled=true\n",
			},
			tags: []string{"amutable.ext.docker=x", "amutable.ext.interactive"},
			want: map[string]string{
				"sysupdate.foo.d/docker.feature": "[Feature]\nDescription=Docker\nEnabled=true\n",
				// A feature whose tag is not set is left as shipped.
				"sysupdate.foo.d/containerd.feature": "[Feature]\nEnabled=false\n",
				// A feature ATTR does not list keeps its own settings.
				"sysupdate.foo.d/interactive.feature": "[Feature]\nEnabled=true\n",
			},
		},
		{
			name:  "tag-gated component",
			attr:  `{"tag": "amutable.foo"}`,
			files: map[string]string{"foo.component": "[Component]\nMinVersion=1\nMaxVersion=1\nDescription=Foo\nEnabled=false\n"},
			want:  map[string]string{"sysupdate.foo.component": "[Component]\nMinVersion=1\nMaxVersion=1\nDescription=Foo\nEnabled=true\n"},
		},
		{
			name:  "pre-enabled component",
			attr:  `{"pre-enabled": true}`,
			files: map[string]string{"foo.component": "[Component]\nMinVersion=1\nMaxVersion=1\nDescription=Foo\nEnabled=false\n"},
			want:  map[string]string{"sysupdate.foo.component": "[Component]\nMinVersion=1\nMaxVersion=1\nDescription=Foo\nEnabled=false\n"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ctx := setupTestEnv(t)
			ext := &TransferFileExtension{OverrideSourcePathURL: tc.override}
			_, err := ext.Init(ctx)
			require.NoError(t, err)
			t.Cleanup(func() { _ = ext.Close() })

			applyAll(ctx, t, ext, inlineTarget(".zzz-quarry-special/sysupdate.foo.d=1/ATTR", []byte(tc.attr)))
			for file, data := range tc.files {
				applyAll(ctx, t, ext, inlineTarget(".zzz-quarry-special/sysupdate.foo.d=1/"+file, []byte(data)))
			}
			staged, err := ext.Stage(ctx, ext.Transfers()["foo"][0], StageOptions{MachineTags: tc.tags})
			require.NoError(t, err)
			t.Cleanup(func() { _ = staged.Remove() })

			for file, want := range tc.want {
				out, err := os.ReadFile(filepath.Join(staged.Path(), file)) //nolint:forbidigo // test code
				require.NoError(t, err)
				assert.Equal(t, want, string(out), file)
			}
		})
	}
}

func TestBeforeUpdate_HostDefinitions(t *testing.T) {
	env, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	// Nothing on the host is fine.
	require.NoError(t, ext.BeforeUpdate(ctx))
	found, err := hostDefinitions()
	require.NoError(t, err)
	assert.Empty(t, found)

	// Host definitions only produce a warning, but are found.
	require.NoError(t, os.MkdirAll(filepath.Join(env.etcPath, "sysupdate.d"), 0o755))                             //nolint:forbidigo // test code
	require.NoError(t, os.WriteFile(filepath.Join(env.etcPath, "sysupdate.d", "x.transfer"), []byte("x"), 0o644)) //nolint:forbidigo // test code
	require.NoError(t, os.MkdirAll(filepath.Join(env.etcPath, "sysupdate.foo.d"), 0o755))                         //nolint:forbidigo // test code
	require.NoError(t, os.WriteFile(filepath.Join(env.etcPath, "sysupdate.foo.component"), []byte("x"), 0o644))   //nolint:forbidigo // test code
	require.NoError(t, ext.BeforeUpdate(ctx))
	found, err = hostDefinitions()
	require.NoError(t, err)
	assert.Equal(t, []string{
		filepath.Join(env.etcPath, "sysupdate.d", "x.transfer"), //nolint:forbidigo // test code
		filepath.Join(env.etcPath, "sysupdate.foo.component"),   //nolint:forbidigo // test code
		filepath.Join(env.etcPath, "sysupdate.foo.d"),           //nolint:forbidigo // test code
	}, found)
}

func TestAbort_RemovesStaged(t *testing.T) {
	env, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	applyAll(ctx, t, ext,
		inlineTarget(".zzz-quarry-special/sysupdate.d=1/x.transfer", []byte("[Transfer]\n")),
		inlineTarget(".zzz-quarry-special/sysupdate.d=1/ATTR", []byte(`{"pre-enabled": true}`)),
	)
	staged, err := ext.Stage(ctx, ext.Transfers()[""][0], StageOptions{})
	require.NoError(t, err)
	require.NoError(t, staged.Close())

	require.NoError(t, ext.Abort(ctx, errors.New("test")))

	_, err = os.Stat(filepath.Join(env.storeDir, "sysupdate.d")) //nolint:forbidigo // test code
	require.ErrorIs(t, err, fs.ErrNotExist)
	assert.Nil(t, ext.storeDir)

	// Abort is idempotent.
	require.NoError(t, ext.Abort(ctx, errors.New("second")))
}

func TestClose_Idempotent(t *testing.T) {
	_, ctx := setupTestEnv(t)
	ext := initExt(ctx, t)

	require.NoError(t, ext.Close())
	require.NoError(t, ext.Close())
}

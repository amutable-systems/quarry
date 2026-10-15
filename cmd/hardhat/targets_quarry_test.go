// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/tufext"
)

func writeDefinitions(t *testing.T, dir string, files map[string]string) string {
	t.Helper()
	for rel, content := range files {
		path := filepath.Join(dir, rel)                                //nolint:forbidigo // test code
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))     //nolint:forbidigo // test code
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644)) //nolint:forbidigo // test code
	}
	return dir
}

func inlineString(t *testing.T, builder *tufext.TargetsBuilder, path string) string {
	t.Helper()
	target := builder.TargetsType().Targets[path]
	require.NotNil(t, target, "target %s", path)
	data, err := tufext.TargetFilesExt(target).InlineData()
	require.NoError(t, err)
	return string(data)
}

func TestAddQuarryTargets(t *testing.T) {
	base := writeDefinitions(t, t.TempDir(), map[string]string{
		"10-usr.transfer":          "[Transfer]\nProtectVersion=%A\n\n[Source]\nType=url-file\n",
		"10-usr.transfer.d/x.conf": "[Transfer]\nVerify=no\n",
		"docker.feature":           "[Feature]\nSuggestOnMachineTag=amutable.ext.docker\n",
	})
	k8s := writeDefinitions(t, t.TempDir(), map[string]string{
		"k8s.transfer": "[Transfer]\n\n[Source]\nType=url-file\n",
	})
	shipped := writeDefinitions(t, t.TempDir(), map[string]string{
		"own.transfer":  "[Transfer]\n",
		"own.component": "[Component]\nDescription=Own\n",
	})
	spec := []*quarryTransferDir{
		{dir: "sysupdate.d", sources: []string{base}},
		{dir: "sysupdate.k8s.d", sources: []string{k8s}},
		{dir: "sysupdate.own.d", sources: []string{shipped}},
	}
	builder := tufext.NewTargetsBuilder()
	require.NoError(t, addQuarryTargets(builder, spec))

	// The files are published as they are.
	const baseDir = ".quarry/sysupdate.d/"
	assert.Equal(t, "[Transfer]\nProtectVersion=%A\n\n[Source]\nType=url-file\n", inlineString(t, builder, baseDir+"10-usr.transfer"))
	assert.Equal(t, "[Transfer]\nVerify=no\n", inlineString(t, builder, baseDir+"10-usr.transfer.d/x.conf"))
	assert.Equal(t, "[Feature]\nSuggestOnMachineTag=amutable.ext.docker\n", inlineString(t, builder, baseDir+"docker.feature"))

	const k8sDir = ".quarry/sysupdate.k8s.d/"
	assert.Equal(t, "[Component]\nDescription=k8s\n",
		inlineString(t, builder, k8sDir+"k8s.component"), "a missing component file is generated")
	assert.Equal(t, "[Component]\nDescription=Own\n", inlineString(t, builder, ".quarry/sysupdate.own.d/own.component"))

	targets := builder.TargetsType().Targets
	assert.Len(t, targets, 7)
	for path, target := range targets {
		assert.Nil(t, target.Custom, "%s: quarry metadata belongs to no version", path)
	}
}

func TestAddQuarryTargetsRejects(t *testing.T) {
	dir := writeDefinitions(t, t.TempDir(), map[string]string{})
	spec := []*quarryTransferDir{{dir: "sysupdate.d", sources: []string{dir}}}
	require.ErrorContains(t, addQuarryTargets(tufext.NewTargetsBuilder(), spec), "holds no definition files")

	// A path already in the targets is an error rather than a silent
	// replacement.
	dir = writeDefinitions(t, t.TempDir(), map[string]string{"x.transfer": "[Transfer]\n"})
	builder := tufext.NewTargetsBuilder()
	_, err := addInlineBytes(builder, ".quarry/sysupdate.d/x.transfer", nil)
	require.NoError(t, err)
	spec = []*quarryTransferDir{{dir: "sysupdate.d", sources: []string{dir}}}
	require.ErrorContains(t, addQuarryTargets(builder, spec), "given twice")
}

// A confext source generates the definitions. The transfer comes from
// hardhat's template, and the component file is generated as for any component
// directory without one.
func TestAddQuarryTargets_Confext(t *testing.T) {
	spec := []*quarryTransferDir{
		{dir: "sysupdate.edge-gw.d", sources: []string{"confext:edge-gw"}},
	}
	builder := tufext.NewTargetsBuilder()
	require.NoError(t, addQuarryTargets(builder, spec))

	const dir = ".quarry/sysupdate.edge-gw.d/"
	transfer := inlineString(t, builder, dir+"50-edge-gw.transfer")
	assert.True(t, strings.HasPrefix(transfer, "[Transfer]\nVerify=no\n"), transfer)
	for _, want := range []string{
		"MatchPattern=**/edge-gw_@v.confext.raw\n",
		"Path=/var/lib/confexts/edge-gw.raw.v\n",
		"MatchPattern=edge-gw_@v.raw\n",
	} {
		assert.Contains(t, transfer, want)
	}
	assert.Equal(t, "[Component]\nDescription=edge-gw\n", inlineString(t, builder, dir+"edge-gw.component"))

	// Several sources merge into one directory. A file in two of them is an error.
	extra := writeDefinitions(t, t.TempDir(), map[string]string{"60-extra.transfer": "[Transfer]\n"})
	spec = []*quarryTransferDir{
		{dir: "sysupdate.gw.d", sources: []string{"confext:gw", "confext:gw-certs", extra}},
	}
	builder = tufext.NewTargetsBuilder()
	require.NoError(t, addQuarryTargets(builder, spec))
	assert.Contains(t, inlineString(t, builder, ".quarry/sysupdate.gw.d/50-gw.transfer"), "MatchPattern=**/gw_@v.confext.raw\n")
	assert.Contains(t, inlineString(t, builder, ".quarry/sysupdate.gw.d/50-gw-certs.transfer"), "MatchPattern=**/gw-certs_@v.confext.raw\n")
	assert.Equal(t, "[Transfer]\n", inlineString(t, builder, ".quarry/sysupdate.gw.d/60-extra.transfer"))
	spec = []*quarryTransferDir{
		{dir: "sysupdate.gw.d", sources: []string{"confext:gw", extra, extra}},
	}
	require.ErrorContains(t, addQuarryTargets(tufext.NewTargetsBuilder(), spec), "also in another source")

	for _, name := range []string{"", "a_b", "a/b", "..", "a b", "a\nb"} {
		spec := []*quarryTransferDir{
			{dir: "sysupdate.x.d", sources: []string{"confext:" + name}},
		}
		require.Error(t, addQuarryTargets(tufext.NewTargetsBuilder(), spec), "confext name %q", name)
	}
}

func TestParseConfextFileName(t *testing.T) {
	for path, want := range map[string][2]string{
		"nodeconfig_20260814T154500Z.confext.raw":  {"nodeconfig", "20260814T154500Z"},
		"out/edge-gw_1.2+3.confext.raw":            {"edge-gw", "1.2+3"},
		"/abs/path/to/gw-certs_v1_rc1.confext.raw": {"gw-certs", "v1_rc1"},
	} {
		name, version, ok := parseConfextFileName(path)
		require.True(t, ok, path)
		assert.Equal(t, want[0], name, path)
		assert.Equal(t, want[1], version, path)
	}
	for _, path := range []string{
		"nodeconfig.confext.raw",       // no version
		"_1.confext.raw",               // no name
		"nodeconfig_.confext.raw",      // empty version
		"a+b_1.confext.raw",            // systemd would cut the name at "+"
		"a b_1.confext.raw",            // breaks a definition line
		"docker_1.sysext.raw",          // not a confext
		"nodeconfig_1.raw",             // not a confext
		"nodeconfig_1.confext.raw.sig", // not the image
		"nodeconfig_a/b.confext.raw",   // "/" in the version
	} {
		_, _, ok := parseConfextFileName(path)
		assert.False(t, ok, path)
	}
}

// A confext DDI among the files gets its component derived from its name,
// with the version from its file name on the image only.
func TestDeriveConfextDirs(t *testing.T) {
	none := func(string) bool { return false }
	dirs, versions := deriveConfextDirs(nil, []string{
		"nodeconfig_2.confext.raw",
		"AmutableOS_26.08.20_x86-64.efi",
		"nodeconfig_1.confext.raw",
		"sub/edge-gw_7.confext.raw",
	}, none)
	assert.Equal(t, []*quarryTransferDir{
		{dir: "sysupdate.edge-gw.d", sources: []string{"confext:edge-gw"}},
		{dir: "sysupdate.nodeconfig.d", sources: []string{"confext:nodeconfig"}},
	}, dirs, "one component per confext name, in name order")
	assert.Equal(t, map[string]string{
		"nodeconfig_1.confext.raw":  "1",
		"nodeconfig_2.confext.raw":  "2",
		"sub/edge-gw_7.confext.raw": "7",
	}, versions)

	// An explicit directory for the component wins over the derived one,
	// and the version is still recorded.
	explicit := []*quarryTransferDir{{dir: "sysupdate.nodeconfig.d", sources: []string{"/defs"}}}
	dirs, versions = deriveConfextDirs(explicit, []string{"nodeconfig_1.confext.raw"}, none)
	assert.Equal(t, explicit, dirs)
	assert.Equal(t, map[string]string{"nodeconfig_1.confext.raw": "1"}, versions)

	// Definitions merged in from an earlier targets.json are left alone.
	merged := func(target string) bool { return target == ".quarry/sysupdate.nodeconfig.d/50-nodeconfig.transfer" }
	dirs, _ = deriveConfextDirs(nil, []string{"nodeconfig_1.confext.raw"}, merged)
	assert.Empty(t, dirs)

	// Pass the derived directories through the real layout to be sure
	// the generated names are what quarry-sysupdate reads.
	dirs, _ = deriveConfextDirs(nil, []string{"nodeconfig_1.confext.raw"}, none)
	builder := tufext.NewTargetsBuilder()
	require.NoError(t, addQuarryTargets(builder, dirs))
	assert.Contains(t, inlineString(t, builder, ".quarry/sysupdate.nodeconfig.d/50-nodeconfig.transfer"),
		"MatchPattern=**/nodeconfig_@v.confext.raw\n")
	assert.Equal(t, "[Component]\nDescription=nodeconfig\n",
		inlineString(t, builder, ".quarry/sysupdate.nodeconfig.d/nodeconfig.component"))
}

func TestSetQuarryCustomVersion(t *testing.T) {
	builder := tufext.NewTargetsBuilder()
	target, err := addInlineBytes(builder, "x", []byte("x"))
	require.NoError(t, err)
	// Existing custom fields, inside and outside quarry, survive.
	existing := json.RawMessage(`{"quarry": {"update": true}, "other": 1}`)
	target.Custom = &existing
	require.NoError(t, setQuarryCustomVersion(target, "2"))
	assert.JSONEq(t, `{"quarry": {"update": true, "version": "2"}, "other": 1}`, string(*target.Custom))

	null := json.RawMessage(`{"quarry": null}`)
	target.Custom = &null
	require.NoError(t, setQuarryCustomVersion(target, "3"))
	assert.JSONEq(t, `{"quarry": {"version": "3"}}`, string(*target.Custom))
}

// quarrySpecFor runs quarrySpecFromFlags on a dummy command with the args.
func quarrySpecFor(t *testing.T, args ...string) ([]*quarryTransferDir, error) {
	t.Helper()
	var (
		spec    []*quarryTransferDir
		specErr error
	)
	cmd := &cli.Command{
		Name:  "targets",
		Flags: quarryTargetsFlags(),
		Action: func(_ context.Context, cmd *cli.Command) error {
			spec, specErr = quarrySpecFromFlags(cmd)
			return nil
		},
	}
	require.NoError(t, cmd.Run(t.Context(), append([]string{"targets"}, args...)))
	return spec, specErr
}

func TestQuarrySpecFromFlags(t *testing.T) {
	spec, err := quarrySpecFor(t,
		"--quarry-transfer-dir=sysupdate.gw.d=confext:gw",
		"--quarry-transfer-dir=sysupdate.d=/defs",
		"--quarry-transfer-dir=sysupdate.gw.d=confext:gw-certs",
		"--quarry-transfer-dir=sysupdate.k8s.d=/k8s",
	)
	require.NoError(t, err)
	assert.Equal(t, []*quarryTransferDir{
		{dir: "sysupdate.gw.d", sources: []string{"confext:gw", "confext:gw-certs"}},
		{dir: "sysupdate.d", sources: []string{"/defs"}},
		{dir: "sysupdate.k8s.d", sources: []string{"/k8s"}},
	}, spec)

	const dir = "--quarry-transfer-dir=sysupdate.x.d=/defs"
	for name, args := range map[string][]string{
		"invalid component dir": {"--quarry-transfer-dir=other.d=/defs"},
		"no source":             {"--quarry-transfer-dir=sysupdate.d="},
		"repeated source":       {dir, dir},
	} {
		_, err := quarrySpecFor(t, args...)
		require.Error(t, err, name)
	}
}

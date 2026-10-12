// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
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

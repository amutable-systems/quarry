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

	"go.amutable.dev/quarry/internal/jsonutils"
	"go.amutable.dev/quarry/internal/transferlayout"
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
	spec := &quarrySpec{
		version: "26.09.16",
		dirs: []*quarryTransferDir{
			{dir: "sysupdate.d", sources: []string{base}, attr: transferlayout.Attr{
				PreEnabled: true,
				Tag:        "amutable.os",
				Features:   map[string]transferlayout.FeatureAttr{"docker": {Tag: "amutable.ext.docker"}},
			}},
			{dir: "sysupdate.k8s.d", sources: []string{k8s}, attr: transferlayout.Attr{
				Tag:      "amutable.k8s",
				Validity: transferlayout.ValiditySteppingStone,
			}},
		},
		machineTags: []string{"acp.nodeconfig", "acp.site=berlin"},
	}
	builder := tufext.NewTargetsBuilder()
	require.NoError(t, addQuarryTargets(builder, spec))

	const baseDir = ".zzz-quarry-special/sysupdate.d=26.09.16/"
	assert.Equal(t, "[Transfer]\nMinVersion=26.09.16\nMaxVersion=26.09.16\nProtectVersion=%A\n\n[Source]\nType=url-file\n",
		inlineString(t, builder, baseDir+"10-usr.transfer"))
	assert.Equal(t, "[Transfer]\nVerify=no\n", inlineString(t, builder, baseDir+"10-usr.transfer.d/x.conf"),
		"drop-ins are shipped as they are")
	assert.Equal(t, "[Feature]\nSuggestOnMachineTag=amutable.ext.docker\n", inlineString(t, builder, baseDir+"docker.feature"))
	assert.JSONEq(t, `{"pre-enabled": true, "tag": "amutable.os", "features": {"docker": {"tag": "amutable.ext.docker"}}}`,
		inlineString(t, builder, baseDir+"ATTR"))
	_, hasComponent := builder.TargetsType().Targets[baseDir+"<default>.component"]
	assert.False(t, hasComponent, "the default component has no component file")

	const k8sDir = ".zzz-quarry-special/sysupdate.k8s.d=26.09.16/"
	assert.Equal(t, "[Component]\nMinVersion=26.09.16\nMaxVersion=26.09.16\nDescription=k8s\nEnabled=false\nSuggestOnMachineTag=amutable.k8s\n",
		inlineString(t, builder, k8sDir+"k8s.component"), "a missing component file is generated and bounded")
	assert.JSONEq(t, `{"tag": "amutable.k8s", "validity": "stepping-stone"}`, inlineString(t, builder, k8sDir+"ATTR"))

	assert.Empty(t, inlineString(t, builder, ".zzz-quarry-special/machine-tags/acp.nodeconfig"), "a sentinel tag is an empty file")
	assert.Equal(t, "berlin", inlineString(t, builder, ".zzz-quarry-special/machine-tags/acp.site"))

	for path, target := range builder.TargetsType().Targets {
		if strings.HasPrefix(path, ".zzz-quarry-special/machine-tags") {
			assert.Nil(t, target.Custom, "%s: a tag is part of no version", path)
			continue
		}
		require.NotNil(t, target.Custom, path)
		custom, err := jsonutils.Parse[map[string]map[string]string](*target.Custom)
		require.NoError(t, err, path)
		assert.Equal(t, "26.09.16", custom["quarry"]["version"], path)
	}
}

func TestAddQuarryTargetsRejects(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"an ATTR file in the source":   {"x.transfer": "[Transfer]\n", "ATTR": "{}"},
		"a version bound of its own":   {"x.transfer": "[Transfer]\nMinVersion=1\n"},
		"a transfer without a section": {"x.transfer": "[Source]\nType=url-file\n"},
		"an empty directory":           {},
	} {
		dir := writeDefinitions(t, t.TempDir(), files)
		spec := &quarrySpec{version: "1", dirs: []*quarryTransferDir{{dir: "sysupdate.d", sources: []string{dir}, attr: transferlayout.Attr{PreEnabled: true}}}}
		require.Error(t, addQuarryTargets(tufext.NewTargetsBuilder(), spec), name)
	}

	// A feature named in the ATTR must exist beside it.
	dir := writeDefinitions(t, t.TempDir(), map[string]string{"x.transfer": "[Transfer]\n"})
	spec := &quarrySpec{version: "1", dirs: []*quarryTransferDir{{dir: "sysupdate.d", sources: []string{dir}, attr: transferlayout.Attr{
		PreEnabled: true,
		Features:   map[string]transferlayout.FeatureAttr{"docker": {Tag: "amutable.ext.docker"}},
	}}}}
	require.ErrorContains(t, addQuarryTargets(tufext.NewTargetsBuilder(), spec), "docker.feature")

	// A drop-in may not undo the bounds. A repeated machine tag or a path
	// already in the targets is an error rather than a silent replacement.
	dir = writeDefinitions(t, t.TempDir(), map[string]string{"x.transfer": "[Transfer]\n", "x.transfer.d/v.conf": "[Transfer]\nMaxVersion=9\n"})
	spec = &quarrySpec{version: "1", dirs: []*quarryTransferDir{{dir: "sysupdate.d", sources: []string{dir}, attr: transferlayout.Attr{PreEnabled: true}}}}
	require.ErrorContains(t, addQuarryTargets(tufext.NewTargetsBuilder(), spec), "MaxVersion=")
	spec = &quarrySpec{machineTags: []string{"acp.a=1", "acp.a=2"}}
	require.ErrorContains(t, addQuarryTargets(tufext.NewTargetsBuilder(), spec), "given twice")
	builder := tufext.NewTargetsBuilder()
	_, err := addInlineBytes(builder, ".zzz-quarry-special/machine-tags/acp.a", nil)
	require.NoError(t, err)
	spec = &quarrySpec{machineTags: []string{"acp.a"}}
	require.ErrorContains(t, addQuarryTargets(builder, spec), "given twice")
}

// A confext source generates the definitions. The transfer comes from
// hardhat's template, and the component file is generated as for any component
// directory without one.
func TestAddQuarryTargets_Confext(t *testing.T) {
	spec := &quarrySpec{version: "20260813T154500Z", dirs: []*quarryTransferDir{
		{dir: "sysupdate.edge-gw.d", sources: []string{"confext:edge-gw"}, attr: transferlayout.Attr{PreEnabled: true}},
	}}
	builder := tufext.NewTargetsBuilder()
	require.NoError(t, addQuarryTargets(builder, spec))

	const dir = ".zzz-quarry-special/sysupdate.edge-gw.d=20260813T154500Z/"
	transfer := inlineString(t, builder, dir+"50-edge-gw.transfer")
	assert.True(t, strings.HasPrefix(transfer, "[Transfer]\nMinVersion=20260813T154500Z\nMaxVersion=20260813T154500Z\nVerify=no\n"), transfer)
	for _, want := range []string{
		"MatchPattern=**/edge-gw_@v.confext.raw\n",
		"Path=/var/lib/confexts/edge-gw.raw.v\n",
		"MatchPattern=edge-gw_@v.raw\n",
	} {
		assert.Contains(t, transfer, want)
	}
	assert.Equal(t, "[Component]\nMinVersion=20260813T154500Z\nMaxVersion=20260813T154500Z\nDescription=edge-gw\nEnabled=true\n",
		inlineString(t, builder, dir+"edge-gw.component"))
	assert.JSONEq(t, `{"pre-enabled": true}`, inlineString(t, builder, dir+"ATTR"))

	// Several sources merge into one directory. A file in two of them is an error.
	extra := writeDefinitions(t, t.TempDir(), map[string]string{"60-extra.transfer": "[Transfer]\n"})
	spec = &quarrySpec{version: "2", dirs: []*quarryTransferDir{
		{dir: "sysupdate.gw.d", sources: []string{"confext:gw", "confext:gw-certs", extra}, attr: transferlayout.Attr{PreEnabled: true}},
	}}
	builder = tufext.NewTargetsBuilder()
	require.NoError(t, addQuarryTargets(builder, spec))
	assert.Contains(t, inlineString(t, builder, ".zzz-quarry-special/sysupdate.gw.d=2/50-gw.transfer"), "MatchPattern=**/gw_@v.confext.raw\n")
	assert.Contains(t, inlineString(t, builder, ".zzz-quarry-special/sysupdate.gw.d=2/50-gw-certs.transfer"), "MatchPattern=**/gw-certs_@v.confext.raw\n")
	assert.Equal(t, "[Transfer]\nMinVersion=2\nMaxVersion=2\n", inlineString(t, builder, ".zzz-quarry-special/sysupdate.gw.d=2/60-extra.transfer"))
	spec = &quarrySpec{version: "2", dirs: []*quarryTransferDir{
		{dir: "sysupdate.gw.d", sources: []string{"confext:gw", extra, extra}, attr: transferlayout.Attr{PreEnabled: true}},
	}}
	require.ErrorContains(t, addQuarryTargets(tufext.NewTargetsBuilder(), spec), "also in another source")

	for _, name := range []string{"", "a_b", "a/b", "a@b", "a=b", "..", "a b", "a\nb"} {
		spec := &quarrySpec{version: "1", dirs: []*quarryTransferDir{
			{dir: "sysupdate.x.d", sources: []string{"confext:" + name}, attr: transferlayout.Attr{PreEnabled: true}},
		}}
		require.Error(t, addQuarryTargets(tufext.NewTargetsBuilder(), spec), "confext name %q", name)
	}
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
func quarrySpecFor(t *testing.T, args ...string) (*quarrySpec, error) {
	t.Helper()
	var (
		spec    *quarrySpec
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
		"--quarry-transfer-version=2",
		"--quarry-transfer-dir=sysupdate.gw.d=confext:gw",
		"--quarry-transfer-dir=sysupdate.d=/defs",
		"--quarry-transfer-dir=sysupdate.gw.d=confext:gw-certs",
		"--quarry-transfer-tag=sysupdate.gw.d=amutable.gw",
		"--quarry-transfer-feature=sysupdate.gw.d=debug=amutable.gw.debug",
		"--quarry-transfer-stepping-stone=sysupdate.gw.d",
		"--quarry-transfer-pre-enabled=sysupdate.d",
		"--quarry-machine-tag=acp.site=berlin",
	)
	require.NoError(t, err)
	assert.Equal(t, &quarrySpec{
		version: "2",
		dirs: []*quarryTransferDir{
			{dir: "sysupdate.gw.d", sources: []string{"confext:gw", "confext:gw-certs"}, attr: transferlayout.Attr{
				Validity: transferlayout.ValiditySteppingStone,
				Tag:      "amutable.gw",
				Features: map[string]transferlayout.FeatureAttr{"debug": {Tag: "amutable.gw.debug"}},
			}},
			{dir: "sysupdate.d", sources: []string{"/defs"}, attr: transferlayout.Attr{PreEnabled: true}},
		},
		machineTags: []string{"acp.site=berlin"},
	}, spec)

	const version, dir, pre = "--quarry-transfer-version=1", "--quarry-transfer-dir=sysupdate.d=/defs", "--quarry-transfer-pre-enabled=sysupdate.d"
	for name, args := range map[string][]string{
		"no version":                     {dir, pre},
		"version without dir":            {version},
		"reserved version char":          {"--quarry-transfer-version=nightly@1", dir, pre},
		"space in version":               {"--quarry-transfer-version=1 2", dir, pre},
		"invalid component dir":          {version, "--quarry-transfer-dir=other.d=/defs"},
		"no source":                      {version, "--quarry-transfer-dir=sysupdate.d="},
		"repeated source":                {version, dir, dir, pre},
		"neither pre-enabled nor tagged": {version, dir},
		"unknown component dir":          {version, dir, pre, "--quarry-transfer-stepping-stone=sysupdate.x.d"},
		"two tags":                       {version, dir, "--quarry-transfer-tag=sysupdate.d=a", "--quarry-transfer-tag=sysupdate.d=b"},
		"tag with value":                 {version, dir, "--quarry-transfer-tag=sysupdate.d=a=b"},
		"repeated feature":               {version, dir, pre, "--quarry-transfer-feature=sysupdate.d=x=a", "--quarry-transfer-feature=sysupdate.d=x=b"},
		"invalid feature name":           {version, dir, pre, "--quarry-transfer-feature=sysupdate.d=x.feature=a"},
		"invalid machine tag":            {"--quarry-machine-tag=acp/x"},
	} {
		_, err := quarrySpecFor(t, args...)
		require.Error(t, err, name)
	}
}

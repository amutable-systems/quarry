// Copyright (C) 2026 Amutable GmbH

package transferlayout

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTargetPath(t *testing.T) {
	path, err := TargetPath("sysupdate.d", "26.09.05", "12-usr.transfer")
	require.NoError(t, err)
	assert.Equal(t, ".zzz-quarry-special/sysupdate.d=26.09.05/12-usr.transfer", path)

	path, err = TargetPath("sysupdate.k8s.d", "1", "k8s.transfer.d/10-x.conf")
	require.NoError(t, err)
	assert.Equal(t, ".zzz-quarry-special/sysupdate.k8s.d=1/k8s.transfer.d/10-x.conf", path)

	for _, tc := range []struct{ dir, version, file string }{
		{"other.d", "1", "x.transfer"},
		{"sysupdate.a.b.d", "1", "x.transfer"},
		{"sysupdate.d@1", "1", "x.transfer"},
		{"sysupdate.d", "", "x.transfer"},
		{"sysupdate.d", "1=2", "x.transfer"},
		{"sysupdate.d", "nightly@1", "x.transfer"}, // reserved for a later qualifier
		{"sysupdate.d", "1", ""},
		{"sysupdate.d", "1", "a/../b"},
	} {
		_, err := TargetPath(tc.dir, tc.version, tc.file)
		require.Error(t, err, "%v", tc)
	}
}

func TestComponentDir(t *testing.T) {
	assert.Equal(t, "sysupdate.d", ComponentDir(""))
	assert.Equal(t, "sysupdate.k8s.d", ComponentDir("k8s"))
	for _, dir := range []string{"sysupdate.default.d", "sysupdate.a.b.d", "sysupdate.a=b.d", "sysupdate..d"} {
		_, err := ParseComponentDir(dir)
		require.Error(t, err, dir)
	}
	for _, dir := range []string{"sysupdate.d", "sysupdate.k8s.d"} {
		component, err := ParseComponentDir(dir)
		require.NoError(t, err)
		assert.Equal(t, dir, ComponentDir(component))
	}
}

func TestMachineTagPath(t *testing.T) {
	path, err := MachineTagPath("acp.nodeconfig")
	require.NoError(t, err)
	assert.Equal(t, ".zzz-quarry-special/machine-tags/acp.nodeconfig", path)
	for _, name := range []string{"", "acp.x=y", "acp/x", "acp@x"} {
		_, err = MachineTagPath(name)
		require.Error(t, err, name)
	}
}

func TestInjectVersionBounds(t *testing.T) {
	out, err := InjectVersionBounds([]byte("[Transfer]\nProtectVersion=%A\n\n[Source]\nType=url-file\n"), TransferSection, "26.09.05")
	require.NoError(t, err)
	assert.Equal(t, "[Transfer]\nMinVersion=26.09.05\nMaxVersion=26.09.05\nProtectVersion=%A\n\n[Source]\nType=url-file\n", string(out))

	out, err = InjectVersionBounds([]byte("[Component]\nDescription=k8s"), ComponentSection, "1")
	require.NoError(t, err)
	assert.Equal(t, "[Component]\nMinVersion=1\nMaxVersion=1\nDescription=k8s\n", string(out))

	for _, text := range []string{
		"[Transfer]\nMinVersion=1\n",
		"[Transfer]\n MaxVersion = 1\n",
		"[Source]\nType=url-file\n",
		"[Transfer]\n[Transfer]\n",
	} {
		_, err := InjectVersionBounds([]byte(text), TransferSection, "2")
		require.Error(t, err, text)
	}
	require.NoError(t, CheckNoVersionBounds([]byte("[Transfer]\nVerify=no\n")))
	require.Error(t, CheckNoVersionBounds([]byte("[Transfer]\nMaxVersion=3\n")))
}

func TestAttr(t *testing.T) {
	for _, bad := range []*Attr{
		{},
		{Tag: "a=b=c"},
		{Tag: "a="},
		{Tag: "amutable.os=nightly"}, // a bare key
		{PreEnabled: true, Validity: "sometime"},
		{PreEnabled: true, Features: map[string]FeatureAttr{"docker.feature": {Tag: "x"}}},
		{PreEnabled: true, Features: map[string]FeatureAttr{"docker": {}}},
	} {
		require.Error(t, bad.Validate(), "%+v", bad)
	}
}

func TestComponentFile(t *testing.T) {
	assert.Equal(t, "[Component]\nDescription=k8s\nEnabled=false\nSuggestOnMachineTag=amutable.k8s\n", string(ComponentFile("k8s", &Attr{Tag: "amutable.k8s"})))
	assert.Equal(t, "[Component]\nDescription=on\nEnabled=true\n", string(ComponentFile("on", &Attr{PreEnabled: true})))
	assert.Equal(t, "[Component]\nDescription=on\nEnabled=true\n", string(ComponentFile("on", &Attr{PreEnabled: true, Tag: "amutable.on"})), "the tag only pins")
}

// Copyright (C) 2026 Amutable GmbH

package transferlayout

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTargetPath(t *testing.T) {
	path, err := TargetPath("sysupdate.d", "12-usr.transfer")
	require.NoError(t, err)
	assert.Equal(t, ".quarry/sysupdate.d/12-usr.transfer", path)

	path, err = TargetPath("sysupdate.k8s.d", "k8s.transfer.d/10-x.conf")
	require.NoError(t, err)
	assert.Equal(t, ".quarry/sysupdate.k8s.d/k8s.transfer.d/10-x.conf", path)

	for _, tc := range []struct{ dir, file string }{
		{"other.d", "x.transfer"},
		{"sysupdate.a.b.d", "x.transfer"},
		{"sysupdate.d", ""},
		{"sysupdate.d", "a/../b"},
	} {
		_, err := TargetPath(tc.dir, tc.file)
		require.Error(t, err, "%v", tc)
	}
}

func TestComponentDir(t *testing.T) {
	assert.Equal(t, "sysupdate.d", ComponentDir(""))
	assert.Equal(t, "sysupdate.k8s.d", ComponentDir("k8s"))
	for _, dir := range []string{"sysupdate.a.b.d", "sysupdate..d"} {
		_, err := ParseComponentDir(dir)
		require.Error(t, err, dir)
	}
	for _, dir := range []string{"sysupdate.d", "sysupdate.k8s.d"} {
		component, err := ParseComponentDir(dir)
		require.NoError(t, err)
		assert.Equal(t, dir, ComponentDir(component))
	}
}

func TestComponentFile(t *testing.T) {
	assert.Equal(t, "[Component]\nDescription=k8s\n", string(ComponentFile("k8s")))
}

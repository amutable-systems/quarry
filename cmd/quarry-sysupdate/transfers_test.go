// Copyright (C) 2026 Amutable GmbH

package sysupdate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.amutable.dev/quarry/internal/systemdcmd"
	"go.amutable.dev/quarry/internal/transferlayout"
	"go.amutable.dev/quarry/internal/xsysupdate"
)

func TestTagSelection(t *testing.T) {
	current := []string{
		"amutable.a",
		"amutable.b=nightly",
		"amutable.c=nightly", "amutable.c.version=3",
		"amutable.d", "amutable.d=stable", "amutable.d.version=2.0",
		"acp.e.version=1", "acp.e.version=1",
		"amutable.f=",
	}
	for _, tc := range []struct {
		tag     string
		enabled bool
		pinned  string
	}{
		{tag: "amutable.a", enabled: true},
		{tag: "amutable.b", enabled: true}, // a value does not matter
		{tag: "amutable.c", enabled: true, pinned: "3"},
		{tag: "amutable.d", enabled: true, pinned: "2.0"}, // plain and valued tag together
		{tag: "acp.e", pinned: "1"},                       // pin without enablement, same pin twice is fine
		{tag: "amutable.f", enabled: true},
		{tag: "nope"},
		{tag: "amutable"},                          // no prefix matching
		{tag: "amutable.b="},                       // keys only
		{tag: "amutable.b=nightly"},                // the value is not part of the key
		{tag: "amutable.c.version", enabled: true}, // the pin tag is a tag like any other
	} {
		enabled, pinned, err := tagSelection(current, tc.tag)
		require.NoError(t, err, "tag %q", tc.tag)
		assert.Equal(t, tc.enabled, enabled, "tag %q", tc.tag)
		assert.Equal(t, tc.pinned, pinned, "tag %q", tc.tag)
	}

	_, _, err := tagSelection([]string{"amutable.x.version=1", "amutable.x.version=2"}, "amutable.x")
	require.Error(t, err, "conflicting pins")
	_, _, err = tagSelection([]string{"amutable.x.version="}, "amutable.x")
	require.Error(t, err, "empty pin")

	enabled, pinned, err := tagSelection(nil, "amutable.a")
	require.NoError(t, err)
	assert.False(t, enabled)
	assert.Empty(t, pinned)
}

// testCandidates returns versions 1 < 2 (stepping stone) < 3 < 4 (stepping
// stone) < 5 of the component foo.
func testCandidates() []*xsysupdate.TransferDir {
	versions := []string{"1", "2", "3", "4", "5"}
	candidates := make([]*xsysupdate.TransferDir, 0, len(versions))
	for _, version := range versions {
		dir := &xsysupdate.TransferDir{Component: "foo", Version: version}
		if version == "2" || version == "4" {
			dir.Attr.Validity = transferlayout.ValiditySteppingStone
		}
		candidates = append(candidates, dir)
	}
	return candidates
}

func TestComponentEnabled(t *testing.T) {
	tags := []string{"amutable.foo", "amutable.bar.version=2"}
	for _, tc := range []struct {
		name    string
		attr    transferlayout.Attr
		enabled bool
		pinned  string
	}{
		{name: "pre-enabled", attr: transferlayout.Attr{PreEnabled: true}, enabled: true},
		{name: "pre-enabled, tag pins", attr: transferlayout.Attr{PreEnabled: true, Tag: "amutable.bar"}, enabled: true, pinned: "2"},
		{name: "tagged, tag set", attr: transferlayout.Attr{Tag: "amutable.foo"}, enabled: true},
		{name: "tagged, tag missing", attr: transferlayout.Attr{Tag: "amutable.bar"}, pinned: "2"},
	} {
		enabled, pinned, err := componentEnabled(&xsysupdate.TransferDir{Version: "1", Attr: tc.attr}, tags)
		require.NoError(t, err, tc.name)
		assert.Equal(t, tc.enabled, enabled, tc.name)
		assert.Equal(t, tc.pinned, pinned, tc.name)
	}
	_, _, err := componentEnabled(&xsysupdate.TransferDir{Version: "1", Attr: transferlayout.Attr{Tag: "amutable.x"}}, []string{"amutable.x.version=1", "amutable.x.version=2"})
	require.Error(t, err, "conflicting pins")
}

func TestSelectVersion(t *testing.T) {
	candidates := testCandidates()

	for _, tc := range []struct {
		current, pinned, want string
	}{
		// If the running version is unknown, go straight to the goal.
		{current: "", want: "5"},
		{current: "", pinned: "3", want: "3"},
		// Stepping stones between the running version and the goal are
		// taken first, oldest first. A stepping stone that is installed but
		// not booted yet is picked again, as the running version is older.
		{current: "1", want: "2"},
		{current: "2", want: "4"},
		{current: "3", want: "4"},
		{current: "4", want: "5"},
		{current: "5", want: "5"},
		// The running version need not be a known candidate.
		{current: "0", want: "2"},
		{current: "2.5", want: "4"},
		{current: "6", want: "5"},
		// A pinned version is the goal. Stepping stones before it still apply,
		// but stepping stones after it do not.
		{current: "1", pinned: "3", want: "2"},
		{current: "2", pinned: "3", want: "3"},
		{current: "1", pinned: "2", want: "2"},
		{current: "3", pinned: "3", want: "3"},
		{current: "5", pinned: "3", want: "3"}, // a downgrade request is left to sysupdate (a no-op)
	} {
		got, err := selectVersion(candidates, tc.current, tc.pinned)
		require.NoError(t, err, "current %q pinned %q", tc.current, tc.pinned)
		assert.Equal(t, tc.want, got.Version, "current %q pinned %q", tc.current, tc.pinned)
	}

	_, err := selectVersion(candidates, "1", "7")
	require.Error(t, err, "pinned version without transfer definitions")
}

func TestSysupdateRunArgs(t *testing.T) {
	binds := []string{
		"/var/lib/quarry-sysupdate/xsysupdate/transfers/sysupdate.foo.d/sysupdate.foo.d:/run/sysupdate.foo.d",
		"/var/lib/quarry-sysupdate/xsysupdate/transfers/sysupdate.foo.d/sysupdate.foo.component:/run/sysupdate.foo.component",
	}
	sysupdate := systemdcmd.FindCmd("sysupdate")
	assert.Equal(t, []string{
		"--collect", "--pipe",
		"-p", "BindReadOnlyPaths=" + binds[0],
		"-p", "BindReadOnlyPaths=" + binds[1],
		sysupdate, "--component-all", "update",
	}, sysupdateRunArgs(binds, "--component-all", "update"))

	// There are no -p arguments at all without bind paths.
	assert.Equal(t, []string{"--collect", "--pipe", sysupdate, "update"}, sysupdateRunArgs(nil, "update"))
}

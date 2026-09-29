// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package uapi6conf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// touch creates the (possibly nested) file at subPath inside root.
func touch(t *testing.T, root, subPath string) string {
	t.Helper()
	path := filepath.Join(root, subPath)                       //nolint:forbidigo // test code
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755)) //nolint:forbidigo // test code
	require.NoError(t, os.WriteFile(path, nil, 0o644))         //nolint:forbidigo // test code
	return path
}

// filePaths returns the paths of the given files, closing them when the test
// ends.
func filePaths(t *testing.T, files Files) []string {
	t.Helper()
	t.Cleanup(func() { assert.NoError(t, files.Close()) })

	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, file.Name())
	}
	return paths
}

// mainFilePath returns the path of the main configuration file called name, or
// "" if there is none, closing it when the test ends.
func mainFilePath(t *testing.T, s SearchPaths, name string) string {
	t.Helper()
	file, err := s.mainFile(name)
	require.NoError(t, err)
	if file == nil {
		return ""
	}
	t.Cleanup(func() { assert.NoError(t, file.Close()) })
	return file.Name()
}

func TestStandard(t *testing.T) {
	assert.Equal(t, SearchPaths{
		"/usr/lib/quarry-client",
		"/usr/local/lib/quarry-client",
		"/run/quarry-client",
		"/etc/quarry-client",
	}, Standard("", "quarry-client"))

	root := t.TempDir()
	assert.Equal(t, SearchPaths{
		root + "/usr/lib/foo",
		root + "/usr/local/lib/foo",
		root + "/run/foo",
		root + "/etc/foo",
	}, Standard(root, "foo"))
}

func TestMainFile_HighestPriorityWins(t *testing.T) {
	root := t.TempDir()
	paths := Standard(root, "quarry-client")

	assert.Empty(t, mainFilePath(t, paths, "config.toml"), "no config anywhere")

	usrConfig := touch(t, root, "usr/lib/quarry-client/config.toml")
	assert.Equal(t, usrConfig, mainFilePath(t, paths, "config.toml"))

	etcConfig := touch(t, root, "etc/quarry-client/config.toml")
	assert.Equal(t, etcConfig, mainFilePath(t, paths, "config.toml"), "/etc must override /usr/lib")
}

func TestMainFile_InaccessibleIsAnError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores the directory permissions this test relies on")
	}

	root := t.TempDir()
	touch(t, root, "etc/quarry-client/config.toml")
	dir := filepath.Join(root, "etc/quarry-client")                //nolint:forbidigo // test code
	require.NoError(t, os.Chmod(dir, 0o000))                       //nolint:forbidigo // test code
	t.Cleanup(func() { require.NoError(t, os.Chmod(dir, 0o755)) }) //nolint:forbidigo // test code

	_, err := Standard(root, "quarry-client").mainFile("config.toml")
	assert.ErrorIs(t, err, os.ErrPermission, "an unreadable config must not be silently ignored")
}

func TestDropIns_SortedByName(t *testing.T) {
	root := t.TempDir()
	paths := Standard(root, "quarry-client")

	dropIns, err := paths.dropIns("config.toml")
	require.NoError(t, err)
	assert.Empty(t, filePaths(t, dropIns), "no drop-in directories at all")

	// Drop-ins apply in file name order regardless of the prefix they are in.
	etc50 := touch(t, root, "etc/quarry-client/config.toml.d/50-machine.toml")
	usr10 := touch(t, root, "usr/lib/quarry-client/config.toml.d/10-base-os.toml")
	run90 := touch(t, root, "run/quarry-client/config.toml.d/90-runtime.toml")

	// Files with a different extension and subdirectories are ignored.
	touch(t, root, "etc/quarry-client/config.toml.d/99-ignored.conf")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "etc/quarry-client/config.toml.d/60-dir.toml"), 0o755)) //nolint:forbidigo // test code

	dropIns, err = paths.dropIns("config.toml")
	require.NoError(t, err)
	assert.Equal(t, []string{usr10, etc50, run90}, filePaths(t, dropIns))
}

func TestDropIns_HigherPriorityMasks(t *testing.T) {
	root := t.TempDir()
	paths := Standard(root, "quarry-client")

	touch(t, root, "usr/lib/quarry-client/config.toml.d/10-base-os.toml")
	etc10 := touch(t, root, "etc/quarry-client/config.toml.d/10-base-os.toml")

	before := openFdCount(t)
	dropIns, err := paths.dropIns("config.toml")
	require.NoError(t, err)
	assert.Equal(t, []string{etc10}, filePaths(t, dropIns), "same-name drop-in in /etc must hide the one in /usr/lib")
	assert.Equal(t, before+len(dropIns), openFdCount(t), "the masked drop-in must not stay open")
}

// openFdCount returns how many file descriptors the test process has open.
func openFdCount(t *testing.T) int {
	t.Helper()
	fds, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)
	return len(fds)
}

func TestDropIns_ClosesFilesOnError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores the file permissions this test relies on")
	}

	root := t.TempDir()
	touch(t, root, "etc/quarry-client/config.toml.d/10-first.toml")
	unreadable := touch(t, root, "etc/quarry-client/config.toml.d/20-second.toml")
	require.NoError(t, os.Chmod(unreadable, 0o000)) //nolint:forbidigo // test code

	before := openFdCount(t)
	_, err := Standard(root, "quarry-client").dropIns("config.toml")
	require.ErrorIs(t, err, os.ErrPermission)
	assert.Equal(t, before, openFdCount(t), "the drop-ins opened before the failure must be closed again")
}

func TestResolve(t *testing.T) {
	root := t.TempDir()
	paths := Standard(root, "quarry-client")

	resolved, err := paths.Resolve("config.toml")
	require.NoError(t, err)
	assert.Empty(t, filePaths(t, resolved))

	dropIn := touch(t, root, "etc/quarry-client/config.toml.d/10-extra.toml")
	resolved, err = paths.Resolve("config.toml")
	require.NoError(t, err)
	assert.Equal(t, []string{dropIn}, filePaths(t, resolved), "drop-ins apply even without a main config file")

	main := touch(t, root, "usr/lib/quarry-client/config.toml")
	resolved, err = paths.Resolve("config.toml")
	require.NoError(t, err)
	assert.Equal(t, []string{main, dropIn}, filePaths(t, resolved), "the main config file always applies first")
}

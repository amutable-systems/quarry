// Copyright (C) 2026 Amutable GmbH

package localrepo

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.amutable.dev/quarry/internal/third_party/fdutils"
)

// openXattrFile returns a non-O_PATH fd, which is what get/setFileAttrs require.
func openXattrFile(t *testing.T) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "xattrs")              //nolint:forbidigo // test code
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644) //nolint:forbidigo // test code
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// skipIfNoUserXattrs skips when the backing filesystem rejects user.* xattrs.
func skipIfNoUserXattrs(t *testing.T, f *os.File) {
	t.Helper()
	err := fdutils.WithFileFd(f, func(fd uintptr) error {
		return unix.Fsetxattr(int(fd), "user.quarry-repo-probe", []byte("x"), 0)
	})
	if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
		t.Skipf("filesystem does not support user xattrs: %v", err)
	}
	require.NoError(t, err)
}

func TestXattrs_GetEmpty(t *testing.T) {
	f := openXattrFile(t)

	got, err := getFileAttrs(f)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestXattrs_SetGetRoundTrip(t *testing.T) {
	f := openXattrFile(t)
	skipIfNoUserXattrs(t, f)

	want := map[string]string{
		"role":    "root",
		"version": "7",
	}
	require.NoError(t, setFileAttrs(f, want))

	got, err := getFileAttrs(f)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestXattrs_GetIgnoresForeignXattrs(t *testing.T) {
	f := openXattrFile(t)
	skipIfNoUserXattrs(t, f)

	err := fdutils.WithFileFd(f, func(fd uintptr) error {
		return unix.Fsetxattr(int(fd), "user.not-quarry-repo.foreign", []byte("value"), 0)
	})
	require.NoError(t, err)
	require.NoError(t, setFileAttrs(f, map[string]string{"kept": "yes"}))

	got, err := getFileAttrs(f)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"kept": "yes"}, got)
}

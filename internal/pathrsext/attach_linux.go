// Copyright (C) 2026 Amutable GmbH

// Package pathrsext provides some extensions for go-pathrs, some of which
// should eventually be added to the upstream libpathrs project.
package pathrsext

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"cyphar.com/go-pathrs"
	"cyphar.com/go-pathrs/procfs"
	"golang.org/x/sys/unix"

	"go.amutable.dev/quarry/internal/linux"
	"go.amutable.dev/quarry/internal/third_party/fdutils"
	"go.amutable.dev/quarry/internal/third_party/funchelpers"
)

// AttachIntoRoot attachs the given file (which may be unlinked but *must* be
// from the same filesystem mount as the given root) into the root at the given
// path.
//
// TODO: This should be provided by libpathrs directly, see
// <https://github.com/cyphar/libpathrs/issues/355>.
func AttachIntoRoot(root *pathrs.Root, unsafePath string, oldFile *os.File) (Err error) {
	unsafeDir, unsafeFilename := filepath.Split(unsafePath)
	if unsafeFilename == "" {
		return fmt.Errorf("target path %q is invalid as a linkname: trailing slash or empty", unsafePath)
	}
	if unsafeDir == "" {
		unsafeDir = "."
	}
	if strings.Contains(unsafeFilename, string(filepath.Separator)) {
		// Should never happen.
		return fmt.Errorf("[internal error] filepath.Split(%q) returned (%q, %q) -- filename contains slash", unsafePath, unsafeDir, unsafeFilename)
	}

	procRoot, err := procfs.Open()
	if err != nil {
		return fmt.Errorf("open procfs root: %w", err)
	}
	defer funchelpers.VerifyClose(&Err, procRoot)

	fdDir, err := procRoot.OpenSelf("fd/", unix.O_DIRECTORY)
	if err != nil {
		return fmt.Errorf("failed to open /proc/self/fd: %w", err)
	}
	defer funchelpers.VerifyClose(&Err, fdDir)

	rootDir, err := root.OpenFile(unsafeDir, unix.O_DIRECTORY)
	if err != nil {
		return fmt.Errorf("failed to open directory for linkname %q: resolve %q: %w", unsafePath, unsafeDir, err)
	}
	defer funchelpers.VerifyClose(&Err, rootDir)

	// NOTE: At this point, libpathrs would do a mount-id check for the
	// magic-link but it would be too annoying to implement here. quarry is not
	// running in the kind of context where those attacks matter much anyway...

	return fdutils.WithFileFd(oldFile, func(targetFd uintptr) error {
		targetFdStr := strconv.FormatUint(uint64(targetFd), 10)
		// NOTE: We need AT_SYMLINK_FOLLOW to follow the target magic-link.
		//
		// It is safe to use unsafeFilename here directly -- it doesn't contain
		// any slashes and linkat(2) doesn't follow target symlinks even with
		// AT_SYMLINK_FOLLOW. If unsafeFilename exists we will just get EEXIST.
		err := linux.Linkat(fdDir, targetFdStr, rootDir, unsafeFilename, unix.AT_SYMLINK_FOLLOW)
		if err != nil {
			err = fmt.Errorf("failed to link fd %d to target path %q: %w", targetFd, unsafePath, err)
		}
		return err
	})
}

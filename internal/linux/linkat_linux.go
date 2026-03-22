//go:build linux

// Copyright (C) 2026 Amutable GmbH

package linux

import (
	"os"

	"golang.org/x/sys/unix"

	"go.amutable.dev/quarry/internal/third_party/fdutils"
)

// Linkat is a wrapper around [unix.Linkat] that accepts [*os.File] arguments.
func Linkat(oldDir *os.File, oldPath string, newDir *os.File, newPath string, flags int) error {
	return fdutils.WithFileFd(oldDir, func(oldDirFd uintptr) error {
		return fdutils.WithFileFd(newDir, func(newDirFd uintptr) error {
			return retryOnEINTR(func() error {
				err := unix.Linkat(int(oldDirFd), oldPath, int(newDirFd), newPath, flags)
				if err != nil {
					err = &os.LinkError{
						Op:  "linkat",
						Old: oldDir.Name() + "/" + oldPath,
						New: newDir.Name() + "/" + newPath,
						Err: err,
					}
				}
				return err
			})
		})
	})
}

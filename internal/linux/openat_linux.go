// Copyright (C) 2026 Amutable GmbH

package linux

import (
	"os"

	"golang.org/x/sys/unix"

	"go.amutable.dev/quarry/internal/third_party/fdutils"
)

// Openat is a slightly more ergonomic wrapper around [unix.Openat].
func Openat(dirFile *os.File, path string, flags int, mode ...uint32) (*os.File, error) {
	if len(mode) > 1 {
		panic("invalid mode argument to Openat") // programmer error
	}
	return fdutils.WithFileFd2(dirFile, func(dirFd uintptr) (*os.File, error) {
		var fileMode uint32
		if len(mode) > 0 {
			fileMode = mode[0]
		}
		fd, err := unix.Openat(int(dirFd), path, flags|unix.O_CLOEXEC, fileMode) //nolint:forbidigo // caller guarantees that the path is safe to open
		fileName := dirFile.Name() + "/" + path
		if err != nil {
			err = &os.PathError{Op: "openat", Path: fileName, Err: err}
		}
		return os.NewFile(uintptr(fd), fileName), err
	})
}

// Copyright (C) 2026 Amutable GmbH

package localrepo

import (
	"bytes"
	"fmt"
	"iter"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"go.amutable.dev/quarry/internal/generics"
	"go.amutable.dev/quarry/internal/third_party/fdutils"
)

const xattrPrefix = "user.quarry-repo."

func flistxattrs(fd uintptr) (iter.Seq[string], error) {
	buf := make([]byte, 512)
	for {
		sz, err := unix.Flistxattr(int(fd), buf)
		if err != nil {
			return nil, os.NewSyscallError("flistxattr", err)
		}
		if sz < len(buf) {
			buf = buf[:sz]
			break
		}
		if sz >= 4096 {
			return nil, fmt.Errorf("xattr list too large: %d bytes", sz)
		}
		buf = make([]byte, sz+len(buf))
	}
	return generics.MapSeq(
		bytes.SplitSeq(buf, []byte{0x00}),
		func(xattr []byte) string {
			return string(xattr)
		},
	), nil
}

func fgetxattr(fd uintptr, xattr string) ([]byte, error) {
	buf := make([]byte, 512)
	for {
		sz, err := unix.Fgetxattr(int(fd), xattr, buf)
		if err != nil {
			return nil, fmt.Errorf("fgetxattr %s: %w", xattr, err)
		}
		if sz < len(buf) {
			return buf[:sz], nil
		}
		if sz >= 4096 {
			return nil, fmt.Errorf("xattr %s value too large: %d bytes", xattr, sz)
		}
		buf = make([]byte, sz+len(buf))
	}
}

// getFileAttrs takes the set of xattrs associated with the file and returns
// the [RepoStore]-specific attributes. The passed [os.File] must not be an
// O_PATH file descriptor.
func getFileAttrs(file *os.File) (map[string]string, error) {
	return fdutils.WithFileFd2(file, func(fd uintptr) (map[string]string, error) {
		xattrSeq, err := flistxattrs(fd)
		if err != nil {
			return nil, err
		}
		attrs := make(map[string]string, 32)
		for xattr := range xattrSeq {
			name, hasPrefix := strings.CutPrefix(xattr, xattrPrefix)
			if !hasPrefix {
				continue
			}
			value, err := fgetxattr(fd, xattr)
			if err != nil {
				return nil, err
			}
			attrs[name] = string(value)
		}
		return attrs, nil
	})
}

// setFileAttrs takes the set of [RepoStore] attributes and sets them as xattrs
// on the given file The passed [os.File] must not be an O_PATH file
// descriptor.
func setFileAttrs(file *os.File, attrs map[string]string) error {
	return fdutils.WithFileFd(file, func(fd uintptr) error {
		// TODO: We should clear the existing set of xattrs that match the
		// prefix.
		for key, val := range attrs {
			xattr := xattrPrefix + key
			if err := unix.Fsetxattr(int(fd), xattr, []byte(val), 0); err != nil {
				return fmt.Errorf("fsetxattr %s %s = %q: %w", file.Name(), xattr, val, err)
			}
		}
		return nil
	})
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package localrepo

import (
	_ "crypto/sha256" // for digest.SHA256
	"fmt"
	"os"

	"github.com/opencontainers/go-digest"
	"golang.org/x/sys/unix"

	"go.amutable.dev/quarry/internal/third_party/fdutils"
	storeopts "go.amutable.dev/quarry/internal/tufrepo/opts"
)

// Copied from <linux/fcntl.h>. See <https://github.com/golang/sys/pull/269>
// for the upstream PR to add this to sys/unix.
const _AT_HANDLE_FID = 0x200 //nolint:revive // C constant

// fhandleETag returns the file handle portion of an ETag for a file (which is
// a sha256 hash of the file handle data returned by [unix.NameToHandleAt]).
//
// TODO: This currently requires Linux 6.5 -- we should probably hash the
// contents of the file if AT_HANDLE_FID is not supported and the filesystem
// doesn't support standard file handles at all?
func fhandleETag(file *os.File) (storeopts.ETag, error) {
	fhandle, err := fdutils.WithFileFd2(file, func(fd uintptr) (unix.FileHandle, error) {
		fhandle, _, err := unix.NameToHandleAt(int(fd), "", unix.AT_EMPTY_PATH|_AT_HANDLE_FID)
		if err != nil {
			err = &os.PathError{Op: "name_to_handle_at", Path: file.Name(), Err: err}
		}
		return fhandle, err
	})
	if err != nil {
		return "", err
	}
	// TODO: Maybe this should be made configurable?
	hash := digest.SHA256.FromBytes(fhandle.Bytes())
	return storeopts.ETag(hash), nil
}

// fileEtag computes the ETag for a file.
func fileEtag(file *os.File) (storeopts.ETag, error) {
	// For now we just use file handles for ETags.
	return fhandleETag(file)
}

// etagMatches returns whether the given [storeopts.ETag] matches the policy
// (nil indicates to use the default policy, which is no clobber).
func etagMatches(etag storeopts.ETag, policy *storeopts.ETag) error {
	if policy == nil || (*policy != storeopts.WildcardETag && *policy != etag) {
		return fmt.Errorf("etag %q does not match policy %s: %w", etag, describePolicy(policy), storeopts.ErrETagMismatch)
	}
	return nil
}

// describePolicy returns a textual description of a policy for use in
// diagnostic log and error messages.
func describePolicy(policy *storeopts.ETag) string {
	if policy == nil {
		return "no-clobber [default]"
	}
	switch *policy {
	case "":
		return "no-clobber"
	case storeopts.WildcardETag:
		return "clobber-all"
	default:
		return "if-matches-" + string(*policy)
	}
}

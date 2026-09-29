// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package tufext

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/umoci/pkg/hardening"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
)

// ErrNoSupportedHashTypes is returned by [HashesToDigest] if none of the hash
// types in a [tufmetadata.Hashes] map are supported by go-digest.
var ErrNoSupportedHashTypes = errors.New("no supported hash types in metadata")

// HashesToDigest takes a set of TUF-represented hash and returns the
// equivalent [digest.Digest]s with an equivalent value (in order of
// preference).
func HashesToDigest(hashes tufmetadata.Hashes) ([]digest.Digest, error) {
	digests := make([]digest.Digest, 0, len(hashes))
	// Always put sha256 first, if applicable.
	if hashBytes, ok := hashes["sha256"]; ok {
		digests = append(digests, digest.NewDigestFromBytes(digest.SHA256, hashBytes))
	}
	for algoName, hashBytes := range hashes {
		algo := digest.Algorithm(algoName)
		if !algo.Available() || algo == digest.SHA256 {
			continue
		}
		digests = append(digests, digest.NewDigestFromBytes(algo, hashBytes))
	}
	if len(digests) < 1 {
		return nil, ErrNoSupportedHashTypes
	}
	return digests, nil
}

// VerifiedReadCloser wraps the given reader so that the data read from it is
// verified against the given TUF-represented size and hashes. Verification is
// only complete once the stream has been fully consumed and the error return
// of [io.ReadCloser.Close] has been checked.
func VerifiedReadCloser(rdr io.ReadCloser, size int64, hashes tufmetadata.Hashes) (io.ReadCloser, error) {
	digests, err := HashesToDigest(hashes)
	if err != nil {
		return nil, fmt.Errorf("convert TUF hashes to digests: %w", err)
	}
	for _, digest := range digests {
		// Wrap the reader with a stack of VerifiedReadClosers for each digest.
		rdr = &hardening.VerifiedReadCloser{
			Reader:         rdr,
			ExpectedDigest: digest,
			ExpectedSize:   size,
		}
	}
	return rdr, nil
}

// VerifyData verifies that the given in-memory data matches the given
// TUF-represented size and hashes.
func VerifyData(data []byte, size int64, hashes tufmetadata.Hashes) error {
	rdr, err := VerifiedReadCloser(io.NopCloser(bytes.NewReader(data)), size, hashes)
	if err != nil {
		return err
	}
	if _, err := io.Copy(io.Discard, rdr); err != nil {
		return err
	}
	return rdr.Close()
}

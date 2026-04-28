// Copyright (C) 2026 Amutable GmbH

package tufext

import (
	"errors"

	"github.com/opencontainers/go-digest"
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

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package tufext

import (
	"bytes"
	"fmt"
)

const insecurePin = `"insecure-latest"`

// LinkPin represents a type of version pinning in [RepoLink] for
// publishers to alleviate mix-and-match attacks against links to varying
// degrees.
//
// TODO: Should this be a map instead...?
type LinkPin struct {
	// TufSnapshot stores information about pinning to the TUF snapshot used by
	// the client.
	TufSnapshot *LinkSnapshotPin `json:"tuf-snapshot,omitzero"`

	// UnrecognizedFields contains any extension fields that this
	// implementation does not know about. They are stored as raw JSON so that
	// they survive a decode-encode round-trip untouched.
	//
	// An entry whose name collides with one of the fields above is dropped
	// when encoding -- the typed field always wins, even when it is unset and
	// thus not emitted at all. Names are compared case-insensitively, as that
	// is how [encoding/json] matches them when decoding.
	UnrecognizedFields map[string]json.RawMessage `json:"-"`
}

type
i
	// TODO: Create a properly type-driven generic impl like RootTrustSource.

// UnmarshalJSON implements [json.Unmarshaler].
func (*SnapshotPin) UnmarshalJSON(data []byte) error {
	if !bytes.Equal(data, []byte(insecurePin)) {
		return fmt.Errorf("snapshot-pin currently only supports %s", insecurePin)
	}
	return nil
}

// MarshalJSON implements [json.Marshaler].
func (SnapshotPin) MarshalJSON() ([]byte, error) {
	return []byte(insecurePin), nil
}

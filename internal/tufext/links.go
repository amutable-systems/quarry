// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package tufext

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"

	"go.amutable.dev/quarry/internal/jsonutils"
)

/*
	{
		"name": "updates.example.com/foobar",
		"root.json": {...},
		"snapshot-pin": "insecure-latest",
		"snapshot-pin": {"type": "insecure-latest"},
		"snapshot-pin": {"type": "version", "want": "exact", version: ...},
		"snapshot-pin": {"type": "version", "want": "at-least", version: ...},
		"snapshot-pin": {"type": "hash", "version": ..., "hashes": {}, "length": ...},
		"snapshot-pin": {"type": "inline", "snapshot.json": {...}},
		"urls": [
			{},
		],
	}
*/

// SnapshotPin represents a type of version pinning in [RepoLink] for
// publishers to alleviate mix-and-match attacks against links to varying
// degrees.
type SnapshotPin struct {
	// TODO: Create a properly type-driven generic impl like RootTrustSource.
}

const insecurePin = `"insecure-latest"`

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

// RepoLink is a representation of a cross-repository link, a TUF extension
// used by Quarry to allow for linking disparate repositories together.
type RepoLink struct {
	// Name is the logical name of the repository. For public repositories, it
	// is the base URL where the repository metafiles can be located. This is
	// primarily used by clients to identify their local cached copy of the
	// repository metadata to avoid rollback attacks when repository links are
	// added or removed.
	Name string `json:"repo"`

	// SnapshotPin specifies the mechanism and strictness of pinning the link
	// based on the target repo's snapshot.
	//
	// Clients that have a local cache of this repository and have seen a newer
	// snapshot version must still reject downgrades, despite the existence of
	// this link.
	SnapshotPin SnapshotPin `json:"snapshot-pin"`

	// Root is an embedded copy of the latest root role data for the repository
	// at the time the link was created.
	//
	// Clients that have a local cache of this repository should still follow
	// the TUF specification's algorithm for updating their local root state.
	// This field is only intended for bootstrapping trust for clients that
	// have never seen this repository before (and do not otherwise have some
	// more authoritative source for the repo's root trust data), though
	// clients should verify that the root role data embedded here matches
	// their local copy if they upgrade to it.
	RootJSON json.RawMessage `json:"root.json"`

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

// AsRepository maps a [RepoLink] to a [Repository] so it can be used for other
// purposes.
func (link RepoLink) AsRepository() *Repository {
	return &Repository{
		Name:      link.Name,
		RootTrust: InlineRootTrust{RootJSON: link.RootJSON},
	}
}

// MarshalJSON implements [json.Marshaler], emitting [RepoLink.UnrecognizedFields]
// alongside the fields this implementation knows about.
func (link RepoLink) MarshalJSON() ([]byte, error) {
	type knownFields RepoLink // shed the methods to avoid recursing forever
	return jsonutils.MarshalExtensible(knownFields(link), link.UnrecognizedFields)
}

// UnmarshalJSON implements [json.Unmarshaler], collecting every field this
// implementation does not know about into [RepoLink.UnrecognizedFields].
func (link *RepoLink) UnmarshalJSON(data []byte) error {
	type knownFields RepoLink // shed the methods to avoid recursing forever
	known, extensions, err := jsonutils.UnmarshalExtensible[knownFields](data)
	if err != nil {
		return err
	}
	*link = RepoLink(known)
	link.UnrecognizedFields = extensions
	return nil
}

type targetsExt struct {
	*SignedTargets
}

// RepoLinks is the extension data type for [RepoLinkField], stored in
// [tufmetadata.TargetsType] (see [targetsExt.RepoLinks]).
type RepoLinks []RepoLink

// RepoLinkField is the cross-repository link extension field that holds the
// [RepoLinks] information in [tufmetadata.TargetsType] role data (see
// [targetsExt.RepoLinks]).
const RepoLinkField = "x-quarry-links"

// WithRepoLinks replaces the list of RepoLinks for the target role with the
// given slice.
func (t targetsExt) WithRepoLinks(links RepoLinks) targetsExt {
	_, err := jsonutils.SetExtensionJSON(&t.SignedTargets.Signed, RepoLinkField, links)
	if err != nil {
		panic(err) // programmer error
	}
	return t
}

// RepoLinks returns the list of [RepoLink]s for this target role, or nil if
// none was set.
func (t targetsExt) RepoLinks() (*RepoLinks, error) {
	// TODO: Cache this....?
	return jsonutils.GetExtensionJSON[RepoLinks](t.SignedTargets.Signed, RepoLinkField)
}

// WithRepoLink appends a [RepoLink] to the target role, and is shorthand for
// [targetsExt.WithRepoLinks].
func (t targetsExt) WithRepoLink(link RepoLink) targetsExt {
	var links RepoLinks
	if oldLinks, err := t.RepoLinks(); err == nil && oldLinks != nil {
		links = slices.Clone(*oldLinks)
	}
	return t.WithRepoLinks(append(links, link))
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package uapi16ext

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/opencontainers/go-digest"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/generics"
	"go.amutable.dev/quarry/internal/jsonutils"
	"go.amutable.dev/quarry/internal/tufext"
	"go.amutable.dev/quarry/internal/uapi16"
)

const (
	// QuarryField is a UAPI.16 extension that stores the "custom.quarry" data
	// associated with a TUF target file, which is the primary "official"
	// mechanism of using quarry extensions.
	QuarryField = "xAmutableQuarry"

	// TUFExtField is a UAPI.16 extension that stores any additional extension
	// fields not covered by [QuarryField] and is mostly included for the
	// purposes of completeness. It contains any other "custom" TUF data as
	// well as any raw extension fields for a TUF target file.
	TUFExtField = "xAmutableTufExt"

	// tufExtCustomField is the sub-object of [TUFExtField] that the non-Quarry
	// parts of the TUF "custom" field are stored in.
	tufExtCustomField = "custom"
)

// knownTUFExtFields is the set of TUF extension fields that [FromTargetFile]
// understands and already expresses through other UAPI.16 fields. These fields
// are thus excluded from the [TUFExtField] fallback.
var knownTUFExtFields = map[string]struct{}{
	tufext.OverrideURLField: {},
	tufext.InlineDataField:  {},
}

// tufCustom is the part of a TUF target's "custom" field that Quarry cares
// about; everything else in there comes back as the extension fields of this
// struct (see [jsonutils.UnmarshalExtensible]).
type tufCustom struct {
	// Quarry is Quarry's own target metadata, stored verbatim.
	Quarry json.RawMessage `json:"quarry"`
}

// targetExtensions returns the UAPI.16 extension fields carrying all of the
// TUF metadata of the given target file that a UAPI.16 file object has no
// field of its own for. Nil is returned if the target has no such metadata.
func targetExtensions(target *tufmetadata.TargetFiles) (map[string]json.RawMessage, error) {
	extensions := make(map[string]json.RawMessage, 2)

	// Map any unknown TUF fields into xAmutableTufExt.
	tufExt := make(map[string]json.RawMessage, len(target.UnrecognizedFields)+1)
	for name, value := range target.UnrecognizedFields {
		if _, ok := knownTUFExtFields[name]; ok {
			continue
		}
		encoded, err := jsonutils.MarshalNoEscapeHTML(value)
		if err != nil {
			return nil, fmt.Errorf("encode unrecognised tuf target field %q: %w", name, err)
		}
		tufExt[name] = encoded
	}

	// Split the TUF "custom" extension field into xAmutableQuarry (for
	// "custom.quarry") and xAmutableTufExt (for everything else), if present.
	if target.Custom != nil {
		custom, rest, err := jsonutils.UnmarshalExtensible[tufCustom](*target.Custom)
		if err != nil {
			// If "custom" is not an object, just add it directly to
			// xAmutableTufExt.
			encoded, err := jsonutils.MarshalNoEscapeHTML(*target.Custom)
			if err != nil {
				return nil, fmt.Errorf("encode tuf custom metadata: %w", err)
			}
			tufExt[tufExtCustomField] = encoded
		} else {
			// Copy "custom.quarry" verbatim to xAmutableQuarry.
			if custom.Quarry != nil {
				encoded, err := jsonutils.MarshalNoEscapeHTML(custom.Quarry)
				if err != nil {
					return nil, fmt.Errorf("encode tuf custom.quarry metadata: %w", err)
				}
				extensions[QuarryField] = encoded
			}
			// Any remaining custom bits get included in xAmutableTufExt.
			if len(rest) > 0 {
				encoded, err := jsonutils.MarshalNoEscapeHTML(rest)
				if err != nil {
					return nil, fmt.Errorf("encode remaining tuf custom metadata: %w", err)
				}
				tufExt[tufExtCustomField] = encoded
			}
		}
	}
	if len(tufExt) > 0 {
		encoded, err := jsonutils.MarshalNoEscapeHTML(tufExt)
		if err != nil {
			return nil, fmt.Errorf("encode %s extension: %w", TUFExtField, err)
		}
		extensions[TUFExtField] = encoded
	}
	if len(extensions) == 0 {
		extensions = nil
	}
	return extensions, nil
}

// FromTargetFile converts a TUF target file into the equivalent UAPI.16 file
// object, with all of the TUF metadata that UAPI.16 cannot express stored in
// the [QuarryField] and [TUFExtField] extension fields.
//
// The candidate download URLs of the file object are those of the target file
// (see [tufext.TargetFilesExt.FetchURLs]), relative to the given base URLs.
func FromTargetFile(target *tufmetadata.TargetFiles, baseURLs ...*url.URL) (*uapi16.File, error) {
	// The target file might not provide a sha256 hash, in which case we must
	// abort loudly since UAPI.16 only supports sha256 and the alternatives are
	// worse (missing files or clients using unverified files).
	hashBytes, ok := target.Hashes["sha256"]
	if !ok {
		return nil, errors.New("target has no sha256 hash, which uapi.16 cannot express")
	}
	hash := digest.SHA256.Encode(hashBytes)
	if err := digest.SHA256.Validate(hash); err != nil {
		return nil, fmt.Errorf("target has invalid sha256 hash: %w", err)
	}
	if target.Length < 0 {
		return nil, fmt.Errorf("target has invalid negative length %d", target.Length)
	}

	targetExt := tufext.TargetFilesExt(target)

	var contents []*uapi16.Contents
	// x-quarry-inline-data becomes a UAPI.16 literal contents entry.
	if data, err := targetExt.InlineData(); err != nil {
		return nil, fmt.Errorf("get target inline data: %w", err)
	} else if data != nil {
		contents = append(contents, &uapi16.Contents{
			Literal: generics.Ptr(base64.StdEncoding.EncodeToString(data)),
		})
	}
	// All other fetch URLs become UAPI.16 url contents entries.
	for url, err := range targetExt.FetchURLs(baseURLs...) {
		if err != nil {
			return nil, fmt.Errorf("get target candidate url: %w", err)
		}
		contents = append(contents, &uapi16.Contents{URL: url.String()})
	}

	extensions, err := targetExtensions(target)
	if err != nil {
		return nil, fmt.Errorf("collect tuf metadata extensions: %w", err)
	}

	return &uapi16.File{
		Name:               target.Path,
		Size:               generics.Ptr(uint64(target.Length)),
		SHA256:             hash,
		Contents:           contents,
		UnrecognizedFields: extensions,
	}, nil
}

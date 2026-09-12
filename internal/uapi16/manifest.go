// Copyright (C) 2026 Amutable GmbH

package uapi16

import (
	"encoding/json"

	"go.amutable.dev/quarry/internal/jsonutils"
)

// MediaType is the MIME media-type for the UAPI.16 manifest, which is
// identified by this mediaType being stored in the root file object of a
// manifest.
const MediaType = "application/vnd.uapi.16.manifest"

// Filename is the name a UAPI.16 manifest is expected to have when it is
// stored in a directory alongside the files it describes.
const Filename = "Uapi16Manifest"

// Contents describes a single source that the data of a [File] can be acquired
// from. At most one of [Contents.File], [Contents.URL] and [Contents.Literal]
// may be set -- if none of them are set, the data is expected to be found in a
// file named [File.Name] stored next to the manifest itself.
type Contents struct {
	// File is the name of a file stored in the same location as the manifest.
	File string `json:"file,omitzero"`

	// URL is a full http:// or https:// URL to fetch the data from.
	URL string `json:"url,omitzero"`

	// Literal is the data itself, in (possibly URL-safe) base64 form. Unlike
	// the other sources (where an empty value could never be fetched anyway),
	// an empty literal is a perfectly good source -- the data of an empty file
	// -- so it is a pointer to tell "set but empty" apart from "unset", and
	// has to be emitted as such rather than being dropped and turning the
	// entry into an implied file next to the manifest.
	Literal *string `json:"literal,omitzero"`

	// Encoding is the encoding that the source data is stored in, using the
	// same specifiers as HTTP's Content-Encoding (i.e. "gzip" or "zstd"). If
	// unset, the source data is not encoded.
	Encoding string `json:"encoding,omitzero"`

	// EncodedSize is the size of the full encoded source data, and may only be
	// set if Encoding is set. If unset, consumers cannot check the size of the
	// encoded data before decoding it.
	EncodedSize *uint64 `json:"encodedSize,omitzero"`

	// OriginalSize is the size of the full decoded source data. If unset,
	// consumers cannot check the size of the decoded data.
	OriginalSize *uint64 `json:"originalSize,omitzero"`

	// Offset is the offset within the decoded source data at which the data of
	// the [File] starts. The slice extends over [File.Size] bytes, so Offset
	// plus [File.Size] may not exceed OriginalSize. Unlike the sizes, an unset
	// offset is defined to mean an offset of zero, so there is no need to tell
	// the two apart.
	Offset uint64 `json:"offset,omitzero"`

	// UnrecognizedFields contains any extension fields (named in the
	// "x<Vendor>Foobar" style described by the specification) that this
	// implementation does not know about. They are stored as raw JSON so that
	// they survive a decode-encode round-trip untouched.
	//
	// An entry whose name collides with one of the fields above is dropped
	// when encoding -- the typed field always wins, even when it is unset and
	// thus not emitted at all. Names are compared case-insensitively, as that
	// is how [encoding/json] matches them when decoding.
	UnrecognizedFields map[string]json.RawMessage `json:"-"`
}

// MarshalJSON implements [json.Marshaler], emitting [Contents.UnrecognizedFields]
// alongside the fields this implementation knows about.
func (contents Contents) MarshalJSON() ([]byte, error) {
	type knownFields Contents // shed the methods to avoid recursing forever
	return jsonutils.MarshalExtensible(knownFields(contents), contents.UnrecognizedFields)
}

// UnmarshalJSON implements [json.Unmarshaler], collecting every field this
// implementation does not know about into [Contents.UnrecognizedFields].
func (contents *Contents) UnmarshalJSON(data []byte) error {
	type knownFields Contents // shed the methods to avoid recursing forever
	known, extensions, err := jsonutils.UnmarshalExtensible[knownFields](data)
	if err != nil {
		return err
	}
	*contents = Contents(known)
	contents.UnrecognizedFields = extensions
	return nil
}

// File represents a single file object in a UAPI.16 manifest.
//
// The first file object of a manifest is the root file object, which describes
// the directory the manifest as a whole is for -- it has [File.MediaType] set
// and [File.Name] unset, while every subsequent file object is the other way
// around.
//
// TODO: Support slices, GPT partition metadata, and all the rest of it.
type File struct {
	// MediaType must be [MediaType], and may only be set for the root file
	// object (which has an empty Name field).
	MediaType string `json:"mediaType,omitzero"`

	// Name is the normalised relative path of the file within the directory
	// described by the manifest and must be a valid name according to
	// [ValidateName].
	Name string `json:"name,omitzero"`

	// Size is the size of the file contents in bytes (i.e. the size of the
	// slice of decoded data referenced by Contents). An unset (nil) size means
	// "the remainder of the source data" to consumers when using offsets.
	Size *uint64 `json:"size,omitzero"`

	// SHA256 is the hex-encoded sha256 digest of the file contents.
	SHA256 string `json:"sha256,omitzero"`

	// Contents is the set of alternative sources that the file contents may be
	// acquired from. Consumers are free to pick whichever source suits them
	// best, so every entry must describe the exact same data.
	Contents []*Contents `json:"contents,omitzero"`

	// ValidBeforeUSec is the point in time at which the file object expires,
	// in microseconds since the UNIX epoch. If unset, the file object never
	// expires -- the exact opposite of an expiry of zero (i.e. expired since
	// the UNIX epoch), so the two must not be conflated. Setting this on the
	// root file object expires the manifest as a whole.
	ValidBeforeUSec *uint64 `json:"validBeforeUSec,omitzero"`

	// UnrecognizedFields contains any extension fields (named in the
	// "x<Vendor>Foobar" style described by the specification) that this
	// implementation does not know about. They are stored as raw JSON so that
	// they survive a decode-encode round-trip untouched.
	//
	// An entry whose name collides with one of the fields above is dropped
	// when encoding -- the typed field always wins, even when it is unset and
	// thus not emitted at all. Names are compared case-insensitively, as that
	// is how [encoding/json] matches them when decoding.
	UnrecognizedFields map[string]json.RawMessage `json:"-"`
}

// MarshalJSON implements [json.Marshaler], emitting [File.UnrecognizedFields]
// alongside the fields this implementation knows about.
func (file File) MarshalJSON() ([]byte, error) {
	type knownFields File // shed the methods to avoid recursing forever
	return jsonutils.MarshalExtensible(knownFields(file), file.UnrecognizedFields)
}

// UnmarshalJSON implements [json.Unmarshaler], collecting every field this
// implementation does not know about into [File.UnrecognizedFields].
func (file *File) UnmarshalJSON(data []byte) error {
	type knownFields File // shed the methods to avoid recursing forever
	known, extensions, err := jsonutils.UnmarshalExtensible[knownFields](data)
	if err != nil {
		return err
	}
	*file = File(known)
	file.UnrecognizedFields = extensions
	return nil
}

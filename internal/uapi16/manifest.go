// Copyright (C) 2026 Amutable GmbH

package uapi16

// MediaType is the MIME media-type for the UAPI.16 manifest.
const MediaType = "application/vnd.uapi.16.file.manifest"

// File represents a single file from a quarry repository.
type File struct {
	// Name is the logical name of the file.
	Name string `json:"name"`

	// DataURL is a URL where the data can be retreived.
	DataURL string `json:"dataUrl"`

	// DataSize is the size of the decompressed data.
	DataSize uint64 `json:"dataSize"`

	// SHA256 is the sha256 digest of the data slice.
	SHA256 string `json:"sha256"`

	// TODO: Support slices and all the rest of it.
}

// Manifest is a representation of the minimal parts of the draft [UAPI.16
// manifest format] we need to represent our binary blobs.
//
// TODO: We will eventually want to stuff the slice information into the repo
// metadata.
//
// [UAPI.16 manifest format] <https://github.com/uapi-group/specifications/pull/213>
type Manifest struct {
	// MediaType must be "application/vnd.uapi.16.file.manifest".
	MediaType string `json:"mediaType"`

	// Files is the list of files in the manifest.
	Files []*File `json:"files"`
}

// New returns a new Manifest prefilled with sane defaults.
func New() *Manifest {
	return &Manifest{
		MediaType: MediaType,
	}
}

// Copyright (C) 2026 Amutable GmbH

package tufext

import (
	"net/url"

	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/jsonutils"
)

// TargetFilesExt is a wrapper around [tufmetadata.TargetFiles] to allow for
// full-typed access to Quarry-specific JSON extensions.
func TargetFilesExt(target *tufmetadata.TargetFiles) targetFilesExt { //nolint:revive // return unexported struct for now
	return targetFilesExt{
		TargetFiles: target,
	}
}

type targetFilesExt struct {
	*tufmetadata.TargetFiles
}

const overrideURLField = "x-quarry-override-url"

// WithOverrideURL adds and override URL for the given target file. See
// [OverrideURL] for more information around what override URLs are.
func (t targetFilesExt) WithOverrideURL(u *url.URL) targetFilesExt {
	_, err := jsonutils.SetExtensionJSON(t.TargetFiles, overrideURLField, u.String())
	if err != nil {
		panic(err) // programmer error
	}
	return t
}

// OverrideURL returns the override URL for this target file. If there is no
// override URL then nil, nil is returned.
//
// Override URLs are used to indicate that the data for this particular target
// file is not available from the main repository but is available from a
// different source. Clients are free to try their default URL, but they should
// also attempt to use the provided URL (unless there is some privacy concern
// or the machine is meant to operate offline).
func (t targetFilesExt) OverrideURL() (*url.URL, error) {
	urlStr, err := jsonutils.GetExtensionJSON[string](t.TargetFiles, overrideURLField)
	if err != nil {
		return nil, err
	}
	if urlStr == nil {
		return nil, nil //nolint:nilnil // nil indicates no override found
	}
	return url.Parse(*urlStr)
}

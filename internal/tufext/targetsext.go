// Copyright (C) 2026 Amutable GmbH

package tufext

import (
	"fmt"
	"iter"
	"net/url"

	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/generics"
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
	// TODO: Cache this....
	urlStr, err := jsonutils.GetExtensionJSON[string](t.TargetFiles, overrideURLField)
	if err != nil {
		return nil, err
	}
	if urlStr == nil {
		return nil, nil //nolint:nilnil // nil indicates no override found
	}
	return url.Parse(*urlStr)
}

// FetchURL returns the set of URLs that can be used to fetch this resource. If
// more than one URL is given, the target file being unavailable at one URL
// does not mean it is not available at a later URL.
func (t targetFilesExt) FetchURLs(baseURLs ...*url.URL) iter.Seq2[*url.URL, error] {
	return generics.ErrorIter(func(yield func(*url.URL) bool) error {
		if len(baseURLs) < 1 {
			// Programmer error.
			return fmt.Errorf("target %s FetchURLs called with no baseURLs", t.Path)
		}

		// Prefer override URLs over alternatives.
		if overrideURL, err := t.OverrideURL(); err != nil {
			return fmt.Errorf("invalid override url: %w", err)
		} else if overrideURL != nil {
			if !yield(overrideURL) {
				return nil
			}
		}
		// Finally, yield the default URLs.
		for _, url := range baseURLs {
			if !yield(url.JoinPath(t.Path)) {
				return nil
			}
		}
		return nil
	})
}

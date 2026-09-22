// Copyright (C) 2026 Amutable GmbH

package tufext

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"slices"

	"go.amutable.dev/quarry/internal/serde"
	"go.amutable.dev/quarry/internal/third_party/funchelpers"
)

// TODO: Make these more configurable.
const (
	MaxRootBytes = 512_000 // 512k
)

// RootTrustSource represents a source of trust for the initial state of a
// client's locally cached root.json.
type RootTrustSource interface {
	// Type returns the self-defining string used when generically parsing
	// [RootTrustSource] from formats like JSON and TOML.
	Type() string
	fmt.Stringer

	// FromMap is a helper method called from parsers to fill [RootTrustSource]
	// based on a pre-parsed map[string]any.
	//
	// We do not implement generic unmarshallers because when parsing a
	// [RootTrustSource] you invariably need a wrapper structure to select the
	// right underlying implementation. Types that wish to permit
	// name-only definitions in configuration files need to accept empty maps
	// to [FromMap].
	//
	// Unfortunately, we cannot do this generically (i.e., there doesn't appear
	// to be a way to have a generic requirement to operate on a type whose
	// pointer implements an interface) so we need to return a
	// [RootTrustSource] (which is a copy of the object itself).
	//
	// TODO: Move this to internal/serde and make it more generic.
	FromMap(data map[string]any) (RootTrustSource, error)

	// TODO: We should have a ToMap that can be used to do somewhat generic
	// serialisation in internal/serde?

	// IsRemote indicates whether the root source is to be fetched from a
	// remote resource. Callers can use this as a hint for whether some errors
	// from [FetchRoot] should be skipped.
	IsRemote() bool

	// FetchRoot fetches the initial root.json for the given [Repository],
	// based on the internal policy of this [RootTrustSource].
	FetchRoot(ctx context.Context, repo *Repository) ([]byte, error)
}

// TofuRootTrust fetches the root.json directly from the repository with a
// trust-on-first-use policy. *This is inherently insecure*.
type TofuRootTrust struct {
	// TODO: UnrecognizedFields?
}

var _ RootTrustSource = &TofuRootTrust{}

// Type returns the self-defining string used when generically parsing
// [RootTrustSource] from formats like JSON and TOML.
func (TofuRootTrust) Type() string { return "insecure-tofu" }

func (t TofuRootTrust) String() string { return t.Type() }

// FromMap is a helper method called from parsers to fill [RootTrustSource]
// based on a pre-parsed map[string]any.
func (t TofuRootTrust) FromMap(data map[string]any) (RootTrustSource, error) {
	if len(data) > 0 {
		return nil, fmt.Errorf("unsupported fields: %v", slices.Collect(maps.Keys(data)))
	}
	return t, nil
}

// IsRemote indicates whether the root source is to be fetched from a remote
// resource. It is always true for [TofuRootTrust].
func (TofuRootTrust) IsRemote() bool { return true }

// FetchRoot for [TofuRootTrust] fetches the initial root.json directly from
// the given repository without any validation.
func (TofuRootTrust) FetchRoot(ctx context.Context, repo *Repository) (_ []byte, Err error) {
	// The updater will bump the root.json to the latest version afterwards.
	rootURL, err := repo.RootURL("1.root.json")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", rootURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create http request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	client := http.DefaultClient
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", rootURL, err)
	}
	if res.StatusCode >= 300 {
		if res.Body != nil {
			_ = res.Body.Close()
		}
		err := fmt.Errorf("fetch %s failed with status code %.3d", rootURL, res.StatusCode)
		if res.StatusCode == http.StatusNotFound {
			// Emulate ENOENT for 404.
			err = fmt.Errorf("%w: %w", err, fs.ErrNotExist)
		}
		return nil, err
	}
	rdr := http.MaxBytesReader(nil, res.Body, MaxRootBytes) // use same max as client
	defer funchelpers.VerifyClose(&Err, rdr)

	return io.ReadAll(rdr)
}

// InlineRootTrust is used for cases where it makes sense to embed the
// root.json directly inside some structure or configuration rather than
// referencing some external value.
type InlineRootTrust struct {
	RootJSON json.RawMessage `json:"root.json"`
	// TODO: UnrecognizedFields?
}

var _ RootTrustSource = InlineRootTrust{}

// Type returns the self-defining string used when generically parsing
// [RootTrustSource] from formats like JSON and TOML.
func (t InlineRootTrust) Type() string { return "inline" }

func (t InlineRootTrust) String() string { return fmt.Sprintf("%s:%q", t.Type(), t.RootJSON) }

// IsRemote indicates whether the root source is to be fetched from a remote
// resource. It is always false for [InlineRootTrust].
func (InlineRootTrust) IsRemote() bool { return false }

// FromMap is a helper method called from parsers to fill [RootTrustSource]
// based on a pre-parsed map[string]any.
func (t InlineRootTrust) FromMap(data map[string]any) (RootTrustSource, error) {
	if err := serde.ParseMapKey(data, "root.json", &t.RootJSON); err != nil {
		return nil, err
	}
	if len(data) > 0 {
		return nil, fmt.Errorf("unsupported fields: %v", slices.Collect(maps.Keys(data)))
	}
	return t, nil
}

// FetchRoot for [InlineRootTrust] returns the inlined root.json data and
// cannot return an error.
func (t InlineRootTrust) FetchRoot(_ context.Context, _ *Repository) ([]byte, error) {
	return []byte(t.RootJSON), nil
}

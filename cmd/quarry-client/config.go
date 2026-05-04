// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"slices"

	"github.com/BurntSushi/toml"

	"go.amutable.dev/quarry/internal/expand"
	"go.amutable.dev/quarry/internal/third_party/funchelpers"
)

// TODO: Make these more configurable.
const (
	maxRootBytes = 512_000 // 512k
)

// RootTrustSource represents a source of trust for the initial state of a
// client's locally cached root.json.
type RootTrustSource interface {
	Type() string
	fmt.Stringer

	// This is a helper method called from [parseTomlRootTrust] to fill the
	// structure based on the pre-parsed TOML table. Unfortunately, we cannot
	// do this generically (i.e., there doesn't appear to be a way to have a
	// generic requirement to operate on a type whose pointer implements an
	// interface) so we need to return a [RootTrustSource] (which is a copy of
	// the object itself).
	//
	// We do not implement [encoding.TextUnmarshaler] or [toml.Unmarshaler]
	// here because there are multiple types of root trust and you need to
	// unmarshal [tomlRootTrust] for this to work generically.
	fromTomlMap(table map[string]any) (RootTrustSource, error)

	// FetchRoot fetches the initial root.json for the given [Repository],
	// based on the internal policy of this [RootTrustSource].
	FetchRoot(ctx context.Context, repo *Repository) ([]byte, error)
}

// tomlRootTrust is a wrapper around [RootTrustSource] that allows for a
// generic parsing of [RootTrustSource] implementations.
type tomlRootTrust struct {
	RootTrustSource
}

// errWrongType is a sentinel error returned from [parseTomlRootTrust] if the
// generic type does not match the type of the TOML object.
var errWrongType = errors.New("[internal error] wrong type")

func parseTomlRootTrust[T RootTrustSource](data any) (RootTrustSource, error) {
	rootTrust := *new(T)
	trustType := rootTrust.Type()

	// First see if the TOML data is a pure-name definition of a root type.
	if name, ok := data.(string); ok {
		if name != trustType {
			// Not valid for this type.
			return nil, errWrongType
		}
		// Name-based specifications are only valid for types which also accept
		// empty TOML tables (usually empty structs but also structs with no
		// required fields).
		rootTrust, err := rootTrust.fromTomlMap(map[string]any{})
		if err != nil {
			return nil, fmt.Errorf("root trust %q cannot be instantiated using a plain string: %w", trustType, err)
		}
		return rootTrust, nil
	}

	if table, ok := data.(map[string]any); ok {
		if nameVal, ok := table["type"]; !ok {
			return nil, fmt.Errorf(`invalid table value: must contain "type" field`)
		} else if name, ok := nameVal.(string); !ok {
			return nil, fmt.Errorf(`invalid table value: "type" must be string not %v (%T)`, nameVal, nameVal)
		} else if name != trustType {
			// Not valid for this type.
			return nil, errWrongType
		}

		// We need to make a shallow copy of the table because toml.Decoder
		// internally will loop through the map after UnmarshalTOML is called
		// to decide which keys were undecoded and so modifying the key will
		// result in those keys being left marked as undecoded.
		table = maps.Clone(table)

		// Let the RootTrustSource parse the rest of the options.
		delete(table, "type") // strip to avoid errors in fromTomlMap
		rootTrust, err := rootTrust.fromTomlMap(table)
		if err != nil {
			return nil, fmt.Errorf("root trust %q could not be parsed: %w", trustType, err)
		}
		return rootTrust, nil
	}

	return nil, fmt.Errorf("unsupported toml type %T for root_trust", data)
}

func (t *tomlRootTrust) UnmarshalTOML(data any) error {
	for _, parser := range []func(any) (RootTrustSource, error){
		parseTomlRootTrust[tofuRootTrust],
		parseTomlRootTrust[bundledRootTrust],
	} {
		rootTrust, err := parser(data)
		if errors.Is(err, errWrongType) {
			continue
		}
		if err != nil {
			return fmt.Errorf("parse root_trust: %w", err)
		}
		t.RootTrustSource = rootTrust
		return nil
	}
	if table, ok := data.(map[string]any); ok && table["type"] != "" {
		return fmt.Errorf("unsupported root_trust type %q", table["type"])
	}
	return fmt.Errorf("invalid root_trust value: %v (%T)", data, data)
}

// Expand applies the given [expand.Expansions] to the underlying
// [RootTrustSource].
func (t *tomlRootTrust) Expand(exp *expand.Expansions) error {
	var newRootTrust RootTrustSource
	switch rootTrust := t.RootTrustSource.(type) {
	case tofuRootTrust:
		// nothing to expand
		newRootTrust = rootTrust
	case bundledRootTrust:
		path, err := exp.ExpandString(rootTrust.Path)
		if err != nil {
			return fmt.Errorf("cannot %%-expand path %q: %w", rootTrust.Path, err)
		}
		rootTrust.Path = path
		newRootTrust = rootTrust
	default:
		// Programmer error.
		panic(fmt.Sprintf("missing type switch to expand type %T", rootTrust))
	}
	// We need to re-assign here because tomlRootTrust.RootTrustSource is not a
	// pointer (and cannot be).
	t.RootTrustSource = newRootTrust
	return nil
}

// tofuRootTrust indicates that makeUpdater should fetch the root.json
// directly from the repository with a trust-on-first-use policy.
// *This is inherently insecure*.
type tofuRootTrust struct{}

var _ RootTrustSource = &tofuRootTrust{}

func (tofuRootTrust) Type() string { return "insecure-tofu" }

func (t tofuRootTrust) String() string { return t.Type() }

func (t tofuRootTrust) fromTomlMap(data map[string]any) (RootTrustSource, error) {
	if len(data) > 0 {
		return nil, fmt.Errorf("unsupported fields: %v", slices.Collect(maps.Keys(data)))
	}
	return t, nil
}

func (tofuRootTrust) FetchRoot(ctx context.Context, repo *Repository) (_ []byte, Err error) {
	// The updater will bump the root.json to the latest version afterwards.
	rootURL := repo.MetaRootURL.JoinPath("1.root.json")

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
	rdr := http.MaxBytesReader(nil, res.Body, maxRootBytes) // use same max as client
	defer funchelpers.VerifyClose(&Err, rdr)

	return io.ReadAll(rdr)
}

// bundledRootTrust indicates that the root.json for this makeUpdater should be
// sourced from a particular on-disk file (usually distributed as part of the
// base OS image).
type bundledRootTrust struct {
	Path string `toml:"path"`
}

var _ RootTrustSource = bundledRootTrust{}

func (t bundledRootTrust) Type() string { return "bundled" }

func (t bundledRootTrust) String() string { return t.Type() + ":" + t.Path }

func (t bundledRootTrust) fromTomlMap(data map[string]any) (RootTrustSource, error) {
	if pathVal, ok := data["path"]; !ok {
		return nil, fmt.Errorf(`missing required field "path"`)
	} else if path, ok := pathVal.(string); !ok {
		return nil, fmt.Errorf(`field "path" has unsupported value type: %v (%T)`, pathVal, pathVal)
	} else { //nolint:revive // variable chaining makes this uglier vis-a-vis indent-error-flow
		t.Path = path
		delete(data, "path")
	}
	if len(data) > 0 {
		return nil, fmt.Errorf("unsupported fields: %v", slices.Collect(maps.Keys(data)))
	}
	return t, nil
}

func (t bundledRootTrust) FetchRoot(_ context.Context, _ *Repository) ([]byte, error) {
	return os.ReadFile(t.Path) //nolint:forbidigo // user-controlled host path
}

// tomlURL provides a wrapper around [url.URL] which can be parsed and
// serialised as a TOML string.
type tomlURL struct {
	url.URL
	rawString string
}

// UnmarshalText is implemented because we need to post-process the URL later.
//
// Also, the Go stdlib does not provide this method because of concerns around
// compatibility, so we need to work around this. <https://go.dev/issue/25705>
func (u *tomlURL) UnmarshalText(data []byte) error { //nolint:unparam // encoding.TextUnmarshaler interface
	u.rawString = string(data)
	return nil
}

// Expand applies the given [expand.Expansions] to a URL.
func (u *tomlURL) Expand(exp *expand.Expansions) error {
	str := u.rawString
	expanded, err := exp.ExpandString(str)
	if err != nil {
		return fmt.Errorf("cannot %%-expand %q: %w", str, err)
	}
	rootURL, err := url.Parse(expanded)
	if err != nil {
		return fmt.Errorf("expanded url %q is invalid: %w", expanded, err)
	}
	u.URL = *rootURL
	return nil
}

// Repository represents a single TUF repository.
type Repository struct {
	// Name is the "logical" name of the repository, which uniquely identifies
	// the repository and thus must remain unchanged for the life of the
	// repository. In the TOML file, it is generated based on the
	// map[string]... key in the top-level configuration.
	Name string `toml:"-"`

	// RootTrust indicates the source of trust for the initial root.json of
	// this repository (if the local cache already has a root.json, this source
	// is ignored).
	RootTrust *tomlRootTrust `toml:"root_trust"`

	// MetaRootURL is the base URL for the directory containing TUF metadata.
	MetaRootURL *tomlURL `toml:"meta_root_url"`

	// DataRootURL is the base URL for the directory containing target data
	// files.
	DataRootURL *tomlURL `toml:"data_root_url"`
}

// Config is the top-level configuration object for quarry-client.
type Config struct {
	// TODO: Add --cache-dir to this config.

	// Repos is the set of repositories configured for the client.
	//
	// The following %-expansions are supported for the repository name:
	//
	//    %m -- app-specific machine id (in UUID form)
	//    %e[x] -- "systemd-escape --path" the expando %[x]
	//    %NN -- HTTP-style percent encoding (output is unexpanded)
	//
	// The following additioanl %-expansions are supported for certain fields
	// within each repository specification:
	//
	//    %R -- repository name
	Repos map[string]*Repository `toml:"repo"`
}

func parseConfig(rdr io.Reader) (*Config, error) {
	var cfg Config
	meta, err := toml.NewDecoder(rdr).Decode(&cfg)
	if err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	if unknown := meta.Undecoded(); len(unknown) > 0 {
		return nil, fmt.Errorf("invalid config: unknown toml keys: %v", unknown)
	}
	expander := expand.NewExpansions()
	repos := make(map[string]*Repository)
	for oldName, repo := range cfg.Repos {
		var err error
		repo.Name, err = expander.ExpandString(oldName)
		if err != nil {
			return nil, fmt.Errorf("repository %s has invalid %%-expansion: %w", oldName, err)
		}
		// Save with the updated repo name.
		if _, ok := repos[repo.Name]; ok {
			return nil, fmt.Errorf("repository %s clobbers existing repository %s", oldName, repo.Name)
		}
		repos[repo.Name] = repo

		// Add repo name expansion for repo config options URLs.
		subExpander := expander.Clone().WithSource('R', func(_ *[]any) (string, error) {
			return repo.Name, nil
		})

		if repo.RootTrust == nil {
			return nil, fmt.Errorf("repository %s is missing root_trust specification", oldName)
		}
		if err := repo.RootTrust.Expand(subExpander); err != nil {
			return nil, fmt.Errorf("repository %s has invalid root_trust value: %w", oldName, err)
		}

		if repo.MetaRootURL == nil {
			// If unspecified, assume that the metadata URL is the same as the
			// repository name.
			repo.MetaRootURL = &tomlURL{rawString: "https://" + repo.Name}
		}
		if err := repo.MetaRootURL.Expand(subExpander); err != nil {
			return nil, fmt.Errorf("repository %s has invalid meta_root_url value: %w", oldName, err)
		}

		if repo.DataRootURL == nil {
			// If unspecified, assume that the targets URL is a subdirectory of
			// the metadata URL (this matches the stock go-tuf client
			// behaviour).
			rootURL := repo.MetaRootURL.JoinPath("targets")
			repo.DataRootURL = &tomlURL{rawString: rootURL.String()}
		}
		if err := repo.DataRootURL.Expand(subExpander); err != nil {
			return nil, fmt.Errorf("repository %s has invalid data_root_url value: %w", oldName, err)
		}
	}
	cfg.Repos = repos
	return &cfg, nil
}

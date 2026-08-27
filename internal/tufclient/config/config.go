// Copyright (C) 2026 Amutable GmbH

// Package config provides helpers to parse the TOML configuration format used
// by Quarry clients.
package config

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"

	"github.com/BurntSushi/toml"
	"golang.org/x/sys/unix"

	"go.amutable.dev/quarry/internal/expand"
	"go.amutable.dev/quarry/internal/third_party/funchelpers"
)

// TODO: Make these more configurable.
const (
	MaxRootBytes = 512_000 // 512k
)

var defaultConfigCandidates = [...]string{
	"/etc/quarry-client/config.toml",
	"/run/quarry-client/config.toml",
	"/usr/local/lib/quarry-client/config.toml",
	"/usr/lib/quarry-client/config.toml",
}

// DefaultConfigPath returns the recommended default config path.
func DefaultConfigPath() string {
	for _, path := range defaultConfigCandidates {
		if err := unix.Access(path, unix.F_OK); err == nil {
			return path
		}
	}
	// If none of the candidates are available, just show the first one.
	return defaultConfigCandidates[0]
}

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

// parseTomlKey takes the value from the map with the given key, parses it into
// the given slot, and drops it from the original map. This is quite handy for
// detecting unsupported fields in an ergonomic way when parsing TOML maps.
func parseTomlKey[T any](data map[string]any, key string, slot *T) error {
	if valAny, ok := data[key]; !ok {
		return fmt.Errorf("missing required field %q", key)
	} else if val, ok := valAny.(T); !ok {
		return fmt.Errorf("field %q has incorrect value type: %v (%T) is not a %T", key, valAny, valAny, *new(T))
	} else { //nolint:revive // variable chaining makes this uglier vis-a-vis indent-error-flow
		*slot = val
		delete(data, key)
		return nil
	}
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
		// We need to make a shallow copy of the table because toml.Decoder
		// internally will loop through the map after UnmarshalTOML is called
		// to decide which keys were undecoded and so modifying the key will
		// result in those keys being left marked as undecoded.
		table = maps.Clone(table)

		var gotType string
		if err := parseTomlKey(table, "type", &gotType); err != nil {
			return nil, err
		}
		if gotType != trustType {
			// Not valid for this type.
			return nil, errWrongType
		}

		// Let the RootTrustSource parse the rest of the options.
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
		parseTomlRootTrust[inlineRootTrust],
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
	case tofuRootTrust, inlineRootTrust:
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
	if err := parseTomlKey(data, "path", &t.Path); err != nil {
		return nil, err
	}
	if len(data) > 0 {
		return nil, fmt.Errorf("unsupported fields: %v", slices.Collect(maps.Keys(data)))
	}
	return t, nil
}

func (t bundledRootTrust) FetchRoot(_ context.Context, _ *Repository) ([]byte, error) {
	return os.ReadFile(t.Path) //nolint:forbidigo // user-controlled host path
}

// inlineRootTrust is like [bundledRootTrust] except the root.json is embedded
// directly into the configuration file as a string, which is much easier to
// manage than [bundledRootTrust] when dealing with drop-in files.
type inlineRootTrust struct {
	RootJSON string `toml:"root.json"`
}

var _ RootTrustSource = inlineRootTrust{}

func (t inlineRootTrust) Type() string { return "inline" }

func (t inlineRootTrust) String() string { return fmt.Sprintf("%s:%q", t.Type(), t.RootJSON) }

func (t inlineRootTrust) fromTomlMap(data map[string]any) (RootTrustSource, error) {
	if err := parseTomlKey[string](data, "root.json", &t.RootJSON); err != nil {
		return nil, err
	}
	if len(data) > 0 {
		return nil, fmt.Errorf("unsupported fields: %v", slices.Collect(maps.Keys(data)))
	}
	return t, nil
}

func (t inlineRootTrust) FetchRoot(_ context.Context, _ *Repository) ([]byte, error) {
	return []byte(t.RootJSON), nil
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
func (u *tomlURL) UnmarshalText(data []byte) error {
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

// ConfigVersion is the current version of the configuration file format.
const ConfigVersion = 1

// Config is the top-level configuration object for quarry-client.
type Config struct {
	// Version is the format version of this configuration file.
	Version int64 `toml:"config_version"`

	// CacheDir is a path to the root of the local client cache directory,
	// which stores local copies of the latest repository metadata.
	//
	// The following %-expansions are supported for the cache dir:
	//
	//    %m -- app-specific machine id (in UUID form)
	//    %e[x] -- "systemd-escape --path" the expando %[x]
	//    %NN -- HTTP-style percent encoding (output is unexpanded)
	CacheDir string `toml:"cache_dir"`

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

// ErrUnsupportedVersion is returned by [Parse] if the given configuration file
// is newer than the one supported by this version of quarry.
var ErrUnsupportedVersion = errors.New("unsupported config_version")

// Parse parses the TOML form of [Config].
func Parse(rdr io.Reader) (*Config, error) {
	cfg, err := parseToml(rdr)
	if err != nil {
		return nil, err
	}
	if err := cfg.expandAndValidate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// parseToml parses a single configuration fragment. The repository names are
// expanded here so that fragments merge on the final name, the rest of the
// validation and %-expansion is left to [Config.expandAndValidate], as it
// needs the merged configuration.
func parseToml(rdr io.Reader) (*Config, error) {
	var cfg Config
	meta, err := toml.NewDecoder(rdr).Decode(&cfg)
	if err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	if v := cfg.Version; v != ConfigVersion {
		return nil, fmt.Errorf("%w %d: only version %d is supported", ErrUnsupportedVersion, v, ConfigVersion)
	}
	if unknown := meta.Undecoded(); len(unknown) > 0 {
		return nil, fmt.Errorf("invalid config: unknown toml keys: %v", unknown)
	}

	expander := expand.NewExpansions()
	repos := make(map[string]*Repository, len(cfg.Repos))
	for oldName, repo := range cfg.Repos {
		repo.Name, err = expander.ExpandString(oldName)
		if err != nil {
			return nil, fmt.Errorf("repository %s has invalid %%-expansion: %w", oldName, err)
		}
		if _, ok := repos[repo.Name]; ok {
			return nil, fmt.Errorf("repository %s clobbers existing repository %s", oldName, repo.Name)
		}
		repos[repo.Name] = repo
	}
	cfg.Repos = repos
	return &cfg, nil
}

// expandAndValidate applies the %-expansions, fills in the URL fields derived
// from the repository name, and validates the result.
func (cfg *Config) expandAndValidate() error {
	var err error

	expander := expand.NewExpansions()

	cfg.CacheDir, err = expander.ExpandString(cfg.CacheDir)
	if err != nil {
		return fmt.Errorf("config cache_dir an invalid %%-expansion: %w", err)
	}
	if cfg.CacheDir != "" && !filepath.IsAbs(cfg.CacheDir) {
		return fmt.Errorf("config cache_dir invalid value: %q must be an absolute path", cfg.CacheDir)
	}

	for _, repo := range cfg.Repos {
		// Add repo name expansion for repo config options URLs.
		subExpander := expander.Clone().WithSource('R', func(_ *[]any) (string, error) {
			return repo.Name, nil
		})

		if repo.RootTrust == nil {
			return fmt.Errorf("repository %s is missing root_trust specification", repo.Name)
		}
		if err := repo.RootTrust.Expand(subExpander); err != nil {
			return fmt.Errorf("repository %s has invalid root_trust value: %w", repo.Name, err)
		}

		if repo.MetaRootURL == nil {
			// If unspecified, assume that the metadata URL is the same as the
			// repository name.
			repo.MetaRootURL = &tomlURL{rawString: "https://" + repo.Name}
		}
		if err := repo.MetaRootURL.Expand(subExpander); err != nil {
			return fmt.Errorf("repository %s has invalid meta_root_url value: %w", repo.Name, err)
		}

		if repo.DataRootURL == nil {
			// If unspecified, assume that the targets URL is a subdirectory of
			// the metadata URL (this matches the stock go-tuf client
			// behaviour).
			rootURL := repo.MetaRootURL.JoinPath("targets")
			repo.DataRootURL = &tomlURL{rawString: rootURL.String()}
		}
		if err := repo.DataRootURL.Expand(subExpander); err != nil {
			return fmt.Errorf("repository %s has invalid data_root_url value: %w", repo.Name, err)
		}
	}
	return nil
}

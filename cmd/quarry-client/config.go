// Copyright (C) 2026 Amutable GmbH

package main

import (
	"fmt"
	"io"
	"net/url"

	"github.com/pelletier/go-toml/v2"
)

// tomlURL provides a wrapper around [url.URL] which can be parsed and
// serialised as a TOML string.
type tomlURL struct {
	*url.URL
}

// The Go stdlib does not provide this method because of concerns around
// compatibility, so we need to work around this. <https://go.dev/issue/25705>
func (u *tomlURL) MarshalText() ([]byte, error) {
	// TODO: What to do about a nil url?
	return u.MarshalBinary() // implements string-based unmarshalling
}

// The Go stdlib does not provide this method because of concerns around
// compatibility, so we need to work around this. <https://go.dev/issue/25705>
func (u *tomlURL) UnmarshalText(data []byte) error {
	if u.URL == nil {
		u.URL = new(url.URL)
	}
	return u.UnmarshalBinary(data) // implements string-based unmarshalling
}

// Repository represents a single TUF repository.
type Repository struct {
	// Name is the "logical" name of the repository, which uniquely identifies
	// the repository and thus must remain unchanged for the life of the
	// repository. In the TOML file, it is generated based on the
	// map[string]... key in the top-level configuration.
	Name string `toml:"-"`

	// MetaRootURL is the base URL for the directory containing TUF metadata.
	MetaRootURL *tomlURL `toml:"meta_root_url"`

	// DataRootURL is the base URL for the directory containing target data
	// files.
	DataRootURL *tomlURL `toml:"data_root_url"`
}

// Config is the top-level configuration object for quarry-client.
type Config struct {
	// Repos is the set of repositories configured for the client.
	Repos map[string]*Repository `toml:"repo"`
}

func parseConfig(rdr io.Reader) (*Config, error) {
	var conf Config
	if err := toml.NewDecoder(rdr).DisallowUnknownFields().Decode(&conf); err != nil {
		// TODO: Should we output warnings about unknown fields and allow them?
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	for name, repo := range conf.Repos {
		repo.Name = name
	}
	return &conf, nil
}

func writeConfig(wtr io.Writer, conf *Config) error {
	if err := toml.NewEncoder(wtr).Encode(conf); err != nil {
		return fmt.Errorf("failed to encode config: %w", err)
	}
	return nil
}

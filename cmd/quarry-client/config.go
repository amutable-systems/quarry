// Copyright (C) 2026 Amutable GmbH

package main

import (
	"fmt"
	"io"
	"net/url"

	"github.com/pelletier/go-toml/v2"
)

// Repository represents a single TUF repository.
type Repository struct {
	// Name is the "logical" name of the repository, which uniquely identifies
	// the repository and thus must remain unchanged for the life of the
	// repository. In the TOML file, it is generated based on the
	// map[string]... key in the top-level configuration.
	Name string

	// BaseURL is the base URL for the directory containing TUF metadata.
	BaseURL *url.URL

	// DataBaseURL is the base URL for the directory containing target data
	// files.
	DataBaseURL *url.URL
}

// Config is the top-level configuration object for quarry-client.
type Config struct {
	// Repos is the set of repositories configured for the client.
	Repos map[string]Repository
}

type tomlRepoConfig struct {
	BaseURL     string `toml:"base_url"`
	DataBaseURL string `toml:"data_base_url"`
}

type tomlConfig struct {
	Repos map[string]tomlRepoConfig `toml:"repo"`
}

func parseConfig(rdr io.Reader) (*Config, error) {
	var tomlConf tomlConfig
	if err := toml.NewDecoder(rdr).DisallowUnknownFields().Decode(&tomlConf); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	conf := Config{
		Repos: make(map[string]Repository, len(tomlConf.Repos)),
	}
	for name, repo := range tomlConf.Repos {
		baseURL, err := url.Parse(repo.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("repo %q base_url invalid: %w", name, err)
		}
		dataBaseURL, err := url.Parse(repo.DataBaseURL)
		if err != nil {
			return nil, fmt.Errorf("repo %q data_base_url invalid: %w", name, err)
		}
		conf.Repos[name] = Repository{
			Name:        name,
			BaseURL:     baseURL,
			DataBaseURL: dataBaseURL,
		}
	}
	return &conf, nil
}

func writeConfig(wtr io.Writer, conf *Config) error {
	tomlConf := tomlConfig{
		Repos: make(map[string]tomlRepoConfig, len(conf.Repos)),
	}
	for name, repo := range conf.Repos {
		tomlConf.Repos[name] = tomlRepoConfig{
			BaseURL:     repo.BaseURL.String(),
			DataBaseURL: repo.DataBaseURL.String(),
		}
	}
	if err := toml.NewEncoder(wtr).Encode(tomlConf); err != nil {
		return fmt.Errorf("failed to encode config: %w", err)
	}
	return nil
}

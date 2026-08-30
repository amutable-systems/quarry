// Copyright (C) 2026 Amutable GmbH

package config

import (
	"fmt"
	"io/fs"
	"os"
	"strings"

	"go.amutable.dev/quarry/internal/third_party/funchelpers"
	"go.amutable.dev/quarry/internal/uapi6conf"
)

// Load loads the configuration from the UAPI.6 search paths, with the drop-ins
// from the "config.toml.d" directories applied on top of it.
func Load() (cfg *Config, Err error) {
	searchPaths := uapi6conf.Standard("", "quarry-client")
	configFileName := "config.toml"

	files, err := searchPaths.Resolve(configFileName)
	if err != nil {
		return nil, err
	}
	defer funchelpers.VerifyClose(&Err, &files)

	if len(files) == 0 {
		return nil, fmt.Errorf("no %s found in %s: %w", configFileName, strings.Join(searchPaths, ", "), fs.ErrNotExist)
	}
	return loadFiles(files)
}

// LoadPath loads a single explicitly requested configuration file. Drop-ins
// are deliberately not applied, as a caller asking for a specific file wants
// that file and nothing else.
func LoadPath(path string) (cfg *Config, Err error) {
	file, err := os.Open(path) //nolint:forbidigo // user-controlled host path
	if err != nil {
		return nil, err
	}
	files := uapi6conf.Files{file}
	defer funchelpers.VerifyClose(&Err, &files)

	return loadFiles(files)
}

// loadFiles merges the given fragments, in increasing order of priority.
func loadFiles(files uapi6conf.Files) (*Config, error) {
	cfg := &Config{Version: ConfigVersion, Repos: make(map[string]*Repository)}
	for _, file := range files {
		fragment, err := parseToml(file)
		if err != nil {
			return nil, fmt.Errorf("config %s: %w", file.Name(), err)
		}
		if err := cfg.merge(fragment); err != nil {
			return nil, fmt.Errorf("config %s merge: %w", file.Name(), err)
		}
	}
	if err := cfg.expandAndValidate(); err != nil {
		names := make([]string, 0, len(files))
		for _, file := range files {
			names = append(names, file.Name())
		}
		return nil, fmt.Errorf("config %s: %w", strings.Join(names, ", "), err)
	}
	return cfg, nil
}

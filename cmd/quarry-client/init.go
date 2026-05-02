// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"cyphar.com/go-pathrs"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/urfave/cli/v3"
	"golang.org/x/sys/unix"

	"go.amutable.dev/quarry/cmd/internal/cliext"
	"go.amutable.dev/quarry/internal/pathrsext"
	"go.amutable.dev/quarry/internal/third_party/funchelpers"
)

const (
	dataRootURLCtxKey ctxKey = "--base-url"
	metaRootURLCtxKey ctxKey = "--data-base-url"
)

var initCommand = &cli.Command{
	Name:  "init",
	Usage: "define a repository and add it to the config",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "root",
			Usage: "use the given root as the initial source of trust (otherwise it will be trust-on-first-use)",
		},
		&cli.StringFlag{
			Name:  "base-url",
			Usage: "base URL for TUF metadata (and target data if --data-base-url unspecified)",
		},
		&cli.StringFlag{
			Name:  "data-base-url",
			Usage: "base URL for TUF target data",
		},
		&cli.BoolFlag{
			Name:  "force",
			Usage: "forcefully replace any repository in the cache or config with the same name",
		},
	},
	Arguments: []cli.Argument{
		&cli.StringArg{
			Name: "repo-name",
		},
	},
	Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
		if urlStr := cmd.String("base-url"); urlStr != "" {
			dataRootURL, err := url.Parse(urlStr)
			if err != nil {
				return nil, fmt.Errorf("invalid --base-url: %w", err)
			}
			ctx = context.WithValue(ctx, dataRootURLCtxKey, dataRootURL)
		}
		if urlStr := cmd.String("data-base-url"); urlStr != "" {
			metaRootURL, err := url.Parse(urlStr)
			if err != nil {
				return nil, fmt.Errorf("invalid --data-base-url: %w", err)
			}
			ctx = context.WithValue(ctx, metaRootURLCtxKey, metaRootURL)
		}
		return ctx, nil
	},
	Action: func(ctx context.Context, cmd *cli.Command) (Err error) {
		config := ctxConfig(ctx)
		cacheDir := ctxCacheDir(ctx)

		name := cmd.StringArg("repo-name")
		if name == "" {
			// TODO: Check that the name is valid.
			return fmt.Errorf("repo-name argument is required")
		}

		dataRootURL := cliext.CtxValue[*url.URL](ctx, dataRootURLCtxKey)
		if dataRootURL == nil {
			var err error
			dataRootURL, err = url.Parse("https://" + name)
			if err != nil {
				return fmt.Errorf("repo name %q is not a valid domain + path URL: %w", name, err)
			}
		}
		metaRootURL := cliext.CtxValue[*url.URL](ctx, metaRootURLCtxKey)
		if metaRootURL == nil {
			metaRootURL = dataRootURL.JoinPath("targets")
		}

		var rootData io.ReadCloser
		if path := cmd.String("root"); path != "" {
			var err error
			rootData, err = os.Open(cmd.String("root")) //nolint:forbidigo // user-controlled host path
			if err != nil {
				return fmt.Errorf("invalid --root: %w", err)
			}
			defer funchelpers.VerifyClose(&Err, rootData)
		}

		// Check that the repo is not in the config already.
		if _, ok := config.Repos[name]; ok && !cmd.Bool("force") {
			return fmt.Errorf("repo %q is already in config %s", name, cmd.String("config"))
		}
		config.Repos[name] = &Repository{
			Name:        name,
			MetaRootURL: &tomlURL{dataRootURL},
			DataRootURL: &tomlURL{metaRootURL},
		}

		// TODO(tmpl): If we add template support, we need to expand it here.

		if cmd.Bool("force") {
			if err := cacheDir.RemoveAll(name); err != nil {
				return fmt.Errorf("wipe repo %q from cache dir %s: %w", name, cmd.String("cache-dir"), err)
			}
		}
		// Make sure the cache path doesn't exist either.
		if handle, err := cacheDir.Resolve(name); err == nil {
			_ = handle.Close()
			return fmt.Errorf("repo %q already exists in cache dir %s", name, cmd.String("cache-dir"))
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("check if repo %q already exists in cache dir %s: %w", name, cmd.String("cache-dir"), err)
		}

		// TODO: This initialisation should be delayed until we actually use
		// the repo, to allow you to configure repositories without needing
		// internet access.

		if rootData == nil {
			rootURL := dataRootURL.JoinPath("1.root.json")

			req, err := http.NewRequestWithContext(ctx, "GET", rootURL.String(), nil)
			if err != nil {
				return fmt.Errorf("create http request: %w", err)
			}
			req.Header.Set("Accept", "application/json")

			client := http.DefaultClient
			res, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("fetch %s: %w", rootURL, err)
			}

			rootData = http.MaxBytesReader(nil, res.Body, 512_000) // use same max as client
			defer funchelpers.VerifyClose(&Err, rootData)
		}

		rootBytes, err := io.ReadAll(rootData)
		if err != nil {
			return fmt.Errorf("read root.json: %w", err)
		}

		// Make sure the root.json is actually valid JSON and self-signed.
		root, err := tufmetadata.Root().FromBytes(rootBytes)
		if err != nil {
			return fmt.Errorf("root.json is invalid: %w", err)
		}
		if err := root.VerifyDelegate(tufmetadata.ROOT, root); err != nil {
			return fmt.Errorf("root.json is not self-signed: %w", err)
		}

		repoCacheHandle, err := cacheDir.MkdirAll(name, 0o755)
		if err != nil {
			return fmt.Errorf("make cache for repo %q in cache dir %s: %w", name, cmd.String("cache-dir"), err)
		}
		defer funchelpers.VerifyClose(&Err, repoCacheHandle)

		repoCacheDir, err := pathrs.RootFromFile(repoCacheHandle.IntoFile())
		if err != nil {
			return fmt.Errorf("convert repo cache to root: %w", err)
		}
		defer funchelpers.VerifyClose(&Err, repoCacheDir)

		tmpRootFile, err := repoCacheDir.Create(".", unix.O_TMPFILE|unix.O_NOFOLLOW|unix.O_RDWR, 0o644)
		if err != nil {
			return fmt.Errorf("create tmpfile for root.json: %w", err)
		}
		defer funchelpers.VerifyClose(&Err, tmpRootFile)
		if _, err := tmpRootFile.Write(rootBytes); err != nil {
			return fmt.Errorf("write root.json: %w", err)
		}
		if err := tmpRootFile.Sync(); err != nil {
			return fmt.Errorf("flush root.json: %w", err)
		}
		if err := pathrsext.AttachIntoRoot(repoCacheDir, "root.json", tmpRootFile); err != nil {
			return fmt.Errorf("attach root.json: %w", err)
		}

		configPath := cmd.String("config")
		configDirPath := filepath.Dir(configPath)
		tmpConfigFile, err := os.CreateTemp(configDirPath, ".config.toml.*")
		if err != nil {
			return fmt.Errorf("create temporary config.toml: %w", err)
		}
		defer os.RemoveAll(tmpConfigFile.Name()) //nolint:forbidigo,errcheck // user-controlled host path // intentionally ignore errors

		if err := writeConfig(tmpConfigFile, config); err != nil {
			return err
		}
		if err := tmpConfigFile.Sync(); err != nil {
			return fmt.Errorf("flush config.toml: %w", err)
		}
		if err := os.Rename(tmpConfigFile.Name(), configPath); err != nil {
			return fmt.Errorf("overwrite config %s: %w", configPath, err)
		}
		return nil
	},
}

// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"cyphar.com/go-pathrs"
	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/cmd/internal/cliext"
	"go.amutable.dev/quarry/internal/third_party/funchelpers"
)

type ctxKey string

const (
	configCtxKey   ctxKey = "--config"
	cacheDirCtxKey ctxKey = "--cache-dir"
)

func withConfigFlag(cmd *cli.Command) *cli.Command {
	cmd.Flags = append(cmd.Flags,
		&cli.StringFlag{
			Name:      "config",
			Usage:     "path to the quarry-client configuration file",
			TakesFile: true,
			Value:     findDefaultConfigPath(),
			Sources:   cli.EnvVars("QUARRY_CLIENT_CONFIG"),
		},
		&cli.StringFlag{
			Name:      "cache-dir",
			Usage:     "local cache directory for TUF metadata",
			TakesFile: true,
			Value:     "/var/lib/quarry-client/latest-metadata",
			Sources:   cli.EnvVars("QUARRY_CLIENT_CACHEDIR"),
		})

	cmd.Before = cliext.WrapBeforeFuncs(cmd.Before, func(ctx context.Context, cmd *cli.Command) (_ context.Context, Err error) {
		configPath := cmd.String("config")

		configFile, err := os.Open(configPath) //nolint:forbidigo // user-controlled host path
		if err != nil {
			return nil, fmt.Errorf("open config: %w", err)
		}
		defer funchelpers.VerifyClose(&Err, configFile)

		config, err := parseConfig(configFile)
		if err != nil {
			return nil, fmt.Errorf("invalid config %s: %w", configPath, err)
		}
		ctx = context.WithValue(ctx, configCtxKey, config)

		if config.CacheDir == "" || cmd.IsSet("cache-dir") {
			config.CacheDir = cmd.String("cache-dir")
		}
		if err := os.MkdirAll(config.CacheDir, 0o755); err != nil { //nolint:forbidigo // user-controlled host path
			return nil, err
		}
		cacheDir, err := pathrs.OpenRoot(config.CacheDir)
		if err != nil {
			return nil, err
		}
		ctx = context.WithValue(ctx, cacheDirCtxKey, cacheDir)

		return ctx, nil
	})

	cmd.After = cliext.WrapAfterFuncs(cmd.After, func(ctx context.Context, _ *cli.Command) error {
		cacheDir := ctxCacheDir(ctx)
		if cacheDir != nil {
			return cacheDir.Close()
		}
		return nil
	})

	return cmd
}

func ctxCacheDir(ctx context.Context) *pathrs.Root {
	return cliext.CtxValue[*pathrs.Root](ctx, cacheDirCtxKey)
}

func ctxConfig(ctx context.Context) *Config {
	return cliext.CtxValue[*Config](ctx, configCtxKey)
}

const refTimeCtxKey ctxKey = "--ref-time"

func withRefTimeFlag(cmd *cli.Command) *cli.Command {
	cmd.Flags = append(cmd.Flags,
		&cli.TimestampFlag{
			Name:  "ref-time",
			Usage: "reference time to use rather than wall clock (WARNING: UNSAFE)",
		})

	cmd.Before = cliext.WrapBeforeFuncs(cmd.Before, func(ctx context.Context, cmd *cli.Command) (_ context.Context, Err error) {
		refTime := cmd.Timestamp("ref-time")
		ctx = context.WithValue(ctx, refTimeCtxKey, refTime)
		return ctx, nil
	})

	return cmd
}

func ctxRefTime(ctx context.Context) time.Time {
	return cliext.CtxValue[time.Time](ctx, refTimeCtxKey)
}

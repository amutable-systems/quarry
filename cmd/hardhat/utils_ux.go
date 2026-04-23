// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/keystore"
	"go.amutable.dev/quarry/internal/third_party/funchelpers"
	"go.amutable.dev/quarry/internal/tufrepo"
	"go.amutable.dev/quarry/internal/tufrepo/localrepo"
)

func wrapBeforeFuncs(beforeFns ...cli.BeforeFunc) cli.BeforeFunc {
	return func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
		for _, fn := range beforeFns {
			if fn != nil {
				newCtx, err := fn(ctx, cmd)
				if err != nil {
					return newCtx, err
				}
				ctx = newCtx
			}
		}
		return ctx, nil
	}
}

func wrapAfterFuncs(afterFns ...cli.AfterFunc) cli.AfterFunc {
	return func(ctx context.Context, cmd *cli.Command) error {
		for _, fn := range afterFns {
			if fn != nil {
				if err := fn(ctx, cmd); err != nil {
					return err
				}
			}
		}
		return nil
	}
}

type ctxKey string

const keystoreCtxKey ctxKey = "--keystore"

func withKeystoreFlag(cmd *cli.Command) *cli.Command {
	cmd.Flags = append(cmd.Flags,
		&cli.StringFlag{
			Name:      "keystore",
			Usage:     "path to the key store of signing keys",
			Required:  true,
			TakesFile: true,
			Value:     "/var/lib/quarry/keystore",
			Sources:   cli.EnvVars("QUARRY_KEYSTORE"),
		})
	cmd.Before = wrapBeforeFuncs(cmd.Before, func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
		keystorePath := cmd.String("keystore")
		if err := os.MkdirAll(keystorePath, 0o700); err != nil { //nolint:forbidigo // user-controlled host path
			return nil, fmt.Errorf("invalid keystore: could not create directory: %w", err)
		}
		keystore, err := keystore.OpenStore(keystorePath)
		if err != nil {
			return nil, fmt.Errorf("invalid keystore: %w", err)
		}
		ctx = context.WithValue(ctx, keystoreCtxKey, keystore)
		return ctx, err
	})
	cmd.After = wrapAfterFuncs(cmd.After, func(ctx context.Context, _ *cli.Command) error {
		store := ctxKeystore(ctx)
		if store != nil {
			return store.Close()
		}
		return nil
	})
	return cmd
}

func ctxKeystore(ctx context.Context) *keystore.Store {
	v := ctx.Value(keystoreCtxKey)
	if v != nil {
		return v.(*keystore.Store) //nolint:forcetypeassert // guaranteed to be true
	}
	return nil
}

const repoCtxKey ctxKey = "--repo-metadir"

func withRepoFlag(cmd *cli.Command) *cli.Command {
	cmd.Flags = append(cmd.Flags,
		&cli.StringFlag{
			Name:      "repo-metadir",
			Usage:     "path to the repository metadata directory",
			Required:  true,
			TakesFile: true,
			Value:     "/var/lib/quarry/metadata",
			Sources:   cli.EnvVars("QUARRY_REPO_METADIR"),
		})
	cmd.Before = wrapBeforeFuncs(cmd.Before, func(ctx context.Context, cmd *cli.Command) (_ context.Context, Err error) {
		repoPath := cmd.String("repo-metadir")
		if err := os.MkdirAll(repoPath, 0o755); err != nil { //nolint:forbidigo // user-controlled host path
			return nil, fmt.Errorf("invalid repo metadata directory: could not create directory: %w", err)
		}
		repoStore, err := localrepo.Open(repoPath)
		if err != nil {
			return nil, fmt.Errorf("open repo metadata store: %w", err)
		}
		defer funchelpers.CloseOnError(Err, repoStore)

		repo, err := tufrepo.Open(repoStore)
		if err != nil {
			return nil, fmt.Errorf("wrap repo metadata store: %w", err)
		}
		defer funchelpers.CloseOnError(Err, repo)

		ctx = context.WithValue(ctx, repoCtxKey, repo)
		return ctx, err
	})
	cmd.After = wrapAfterFuncs(cmd.After, func(ctx context.Context, _ *cli.Command) error {
		repo := ctxRepo(ctx)
		if repo != nil {
			return repo.Close()
		}
		return nil
	})
	return cmd
}

func ctxRepo(ctx context.Context) *tufrepo.Repository {
	v := ctx.Value(repoCtxKey)
	if v != nil {
		return v.(*tufrepo.Repository) //nolint:forcetypeassert // guaranteed to be true
	}
	return nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/cmd/internal/cliext"
	"go.amutable.dev/quarry/internal/ctxext"
	"go.amutable.dev/quarry/internal/keystore"
	"go.amutable.dev/quarry/internal/third_party/funchelpers"
	"go.amutable.dev/quarry/internal/tufrepo"
	"go.amutable.dev/quarry/internal/tufrepo/localrepo"
)

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
	cmd.Before = cliext.WrapBeforeFuncs(cmd.Before, func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
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
	cmd.After = cliext.WrapAfterFuncs(cmd.After, func(ctx context.Context, _ *cli.Command) error {
		store := ctxKeystore(ctx)
		if store != nil {
			return store.Close()
		}
		return nil
	})
	return cmd
}

func ctxKeystore(ctx context.Context) *keystore.Store {
	return ctxext.Value[*keystore.Store](ctx, keystoreCtxKey)
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
	cmd.Before = cliext.WrapBeforeFuncs(cmd.Before, func(ctx context.Context, cmd *cli.Command) (_ context.Context, Err error) {
		repoPath := cmd.String("repo-metadir")
		if err := os.MkdirAll(repoPath, 0o755); err != nil { //nolint:forbidigo // user-controlled host path
			return nil, fmt.Errorf("invalid repo metadata directory: could not create directory: %w", err)
		}
		repoStore, err := localrepo.Open(repoPath)
		if err != nil {
			return nil, fmt.Errorf("open repo metadata store: %w", err)
		}
		defer funchelpers.CloseOnError(&Err, repoStore)

		repo, err := tufrepo.Open(repoStore)
		if err != nil {
			return nil, fmt.Errorf("wrap repo metadata store: %w", err)
		}
		defer funchelpers.CloseOnError(&Err, repo)

		ctx = context.WithValue(ctx, repoCtxKey, repo)
		return ctx, err
	})
	cmd.After = cliext.WrapAfterFuncs(cmd.After, func(ctx context.Context, _ *cli.Command) error {
		repo := ctxRepo(ctx)
		if repo != nil {
			return repo.Close()
		}
		return nil
	})
	return cmd
}

func ctxRepo(ctx context.Context) *tufrepo.Repository {
	return ctxext.Value[*tufrepo.Repository](ctx, repoCtxKey)
}

// parseTxExpireAfter parses a single --expire-after argument for use with
// [tufrepo.Transaction.SetExpiresAfter].
func parseTxExpireAfter(spec string) (roleName string, after time.Duration, _ error) {
	durStr := spec
	if role, rest, ok := strings.Cut(spec, "="); ok {
		if role == "" {
			return "", 0, errors.New("role name must not be empty (use a bare <duration> to configure all roles)")
		}
		roleName, durStr = role, rest
	}
	after, err := time.ParseDuration(durStr)
	if err != nil {
		return "", 0, fmt.Errorf(`must be in the form "[<role>=]<duration>": %w`, err)
	}
	return roleName, after, nil
}

func txExpireAfterOp(specs []string) (tufrepo.TxnOp, error) {
	type roleExpiry struct {
		spec  string
		name  string
		after time.Duration
	}
	roleExpiries := make([]roleExpiry, 0, len(specs))
	for _, spec := range specs {
		name, after, err := parseTxExpireAfter(spec)
		if err != nil {
			return nil, fmt.Errorf("invalid --expire-after=%q: %w", spec, err)
		}
		roleExpiries = append(roleExpiries,
			roleExpiry{
				spec:  spec,
				name:  name,
				after: after,
			})
	}
	return tufrepo.NewTxnOp("--expire-after", func(_ context.Context, tx *tufrepo.Transaction) error {
		for _, expiry := range roleExpiries {
			if err := tx.SetExpiresAfter(expiry.name, expiry.after); err != nil {
				return fmt.Errorf("invalid --expire-after=%q: %w", expiry.spec, err)
			}
		}
		return nil
	}), nil
}

const txExpireAfterCtxKey ctxKey = "--expire-after"

func withTxExpireAfterFlag(cmd *cli.Command) *cli.Command {
	cmd.Flags = append(cmd.Flags,
		&cli.StringSliceFlag{
			Name:  "expire-after",
			Usage: "set the expiry of all roles (<duration>) or one role (<role>=<duration>), relative to --ref-time (only applies to roles which will be bumped and re-signed)",
		})
	cmd.Before = cliext.WrapBeforeFuncs(cmd.Before, func(ctx context.Context, cmd *cli.Command) (_ context.Context, Err error) {
		if cmd.IsSet("expire-after") {
			txnOp, err := txExpireAfterOp(cmd.StringSlice("expire-after"))
			if err != nil {
				return nil, err
			}
			ctx = context.WithValue(ctx, txExpireAfterCtxKey, txnOp)
		}
		return ctx, nil
	})
	return cmd
}

func ctxTxExpireAfter(ctx context.Context) tufrepo.TxnOp {
	return ctxext.Value[tufrepo.TxnOp](ctx, txExpireAfterCtxKey)
}

func applyTxExpireAfter(ctx context.Context, tx *tufrepo.Transaction) error {
	return tx.Apply(ctx, ctxTxExpireAfter(ctx))
}

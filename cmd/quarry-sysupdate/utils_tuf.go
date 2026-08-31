// Copyright (C) 2026 Amutable GmbH

package sysupdate

import (
	"context"
	"fmt"
	"iter"

	"go.amutable.dev/quarry/cmd/internal/cliext"
	"go.amutable.dev/quarry/internal/ctxext"
	"go.amutable.dev/quarry/internal/generics"
	"go.amutable.dev/quarry/internal/runas"
	"go.amutable.dev/quarry/internal/third_party/funchelpers"
	"go.amutable.dev/quarry/internal/tufclient"
)

// getClient constructs a [tufclient.Client] from the configuration state,
// optionally restricted to the given subset of repositories. Any error
// loading an explicitly-requested repository is fatal rather than causing the
// repository to be silently skipped.
// TODO: Unify this with quarry-client helper...
func getClient(ctx context.Context, repoNames ...string) (_ *tufclient.Client, Err error) {
	cfg := cliext.CtxConfig(ctx)

	client, err := tufclient.NewClient(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer funchelpers.CloseOnError(&Err, client)

	if err := client.WithRepos(repoNames...); err != nil {
		return nil, err
	}
	if refTime, ok := ctxext.RefTime(ctx); ok {
		client.SetRefTime(ctx, refTime)
	}
	return client, nil
}

// unprivIterTargetFiles is a wrapper around [tufclient.Client.IterTargetFiles]
// but spawned as the "quarry" user from a separate goroutine to make sure that
// the ownership of quarry-client files is correct.
func unprivIterTargetFiles(ctx context.Context) iter.Seq2[*tufclient.TargetInfo, error] {
	user := ctxQuarryUser(ctx)
	return generics.ErrorIter(func(yield func(*tufclient.TargetInfo) bool) error {
		quitCh := make(chan struct{})
		defer close(quitCh)

		infoCh := make(chan *tufclient.TargetInfo)
		doneCh := make(chan error, 1)

		// Fetch the target info in a goroutine with lower privileges.
		go func(ctx context.Context) {
			err := runas.User(ctx, user, func() (Err error) {
				client, err := getClient(ctx)
				if err != nil {
					return fmt.Errorf("get tuf client: %w", err)
				}
				defer funchelpers.VerifyClose(&Err, client)

				for info, err := range client.IterTargetFiles(ctx) {
					if err != nil {
						return err
					}
					select {
					case infoCh <- info:
					case <-quitCh:
						return nil
					}
				}
				return nil
			})
			if err != nil {
				doneCh <- err
			}
			close(doneCh)
		}(ctx)

		// Actually yield the values outside of the unprivileged goroutine.
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case info := <-infoCh:
				if !yield(info) {
					// will close quitCh
					return nil
				}
			case err := <-doneCh:
				return err // if nil, runner completed
			}
		}
	})
}

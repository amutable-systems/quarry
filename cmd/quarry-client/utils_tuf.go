// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package client

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/cmd/internal/cliext"
	"go.amutable.dev/quarry/cmd/internal/pprint"
	"go.amutable.dev/quarry/internal/ctxext"
	"go.amutable.dev/quarry/internal/expand"
	"go.amutable.dev/quarry/internal/third_party/funchelpers"
	"go.amutable.dev/quarry/internal/tufclient"
	"go.amutable.dev/quarry/internal/tufext"
)

// getClient constructs a [tufclient.Client] from the configuration state,
// optionally restricted to the given subset of repositories. Any error
// loading an explicitly-requested repository is fatal rather than causing the
// repository to be silently skipped.
// TODO: Unify this with quarry-sysupdate helper...
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

// earliestTimestampExpiry returns the earliest timestamp.json expiry of any of
// the repositories in the client, which bounds how long any listing generated
// from those repositories can be trusted for. The zero time is returned if the
// client has no repositories.
func earliestTimestampExpiry(ctx context.Context, client *tufclient.Client) (time.Time, error) {
	var (
		errs   []error
		expiry time.Time
	)
	for repoName, updater := range client.IterRepos(ctx) {
		meta := updater.GetTrustedMetadataSet()
		if meta.Timestamp == nil {
			// FIXME: The local client TrustedMetadata state does not get filled
			// until we do a refresh but go-tuf's client does not allow Refresh
			// on the same updater more than once(?!). So we do a refresh here
			// opportunistically.
			// TODO: Add a (*Client).Refresh helper to make this much less
			// fragile.
			if err := updater.Refresh(); err != nil {
				errs = append(errs, fmt.Errorf("refresh repo %s: %w", repoName, err))
				continue
			}
			meta = updater.GetTrustedMetadataSet()
		}
		timestampExpiry := meta.Timestamp.Signed.Expires
		if expiry.IsZero() || expiry.After(timestampExpiry) {
			expiry = timestampExpiry
		}
	}
	return expiry, errors.Join(errs...)
}

func pprintHashes(wtr io.Writer, prefix string, hashes tufmetadata.Hashes) {
	mustFprintf(wtr, "%sHashes:\n", prefix)
	for algoName, hashBytes := range hashes {
		mustFprintf(wtr, "%s - %s:%s\n", prefix, algoName, hashBytes)
	}
}

func pprintTargetFile(wtr io.Writer, prefix string, repo *tufext.Repository, target *tufmetadata.TargetFiles) {
	targetExt := tufext.TargetFilesExt(target)

	mustFprintf(wtr, "%s%s:\n", prefix, target.Path)
	prefix += "\t"
	// Inline data takes priority over the fetch URLs, so mention it first.
	if data, err := targetExt.InlineData(); err != nil {
		mustFprintf(wtr, "%sInline data: <invalid: %v>\n", prefix, err)
	} else if data != nil {
		mustFprintf(wtr, "%sInline data: %d bytes\n", prefix, len(data))
	}
	mustFprintf(wtr, "%sURL(s):\n", prefix)
	if dataRootURL, err := repo.DataURL(); err != nil {
		mustFprintf(wtr, "%s - <invalid repo data url: %v>\n", prefix, err)
	} else {
		for url, err := range targetExt.FetchURLs(dataRootURL) {
			if err != nil {
				mustFprintf(wtr, "%s - <invalid target url: %v>\n", prefix, err)
			}
			mustFprintf(wtr, "%s - %s\n", prefix, url)
		}
	}
	mustFprintf(wtr, "%sSize: %d\n", prefix, target.Length)
	pprintHashes(wtr, prefix, target.Hashes)
	if target.Custom != nil {
		mustFprintf(wtr, "%sCustom:\n", prefix)
		pprint.JSON(wtr, prefix+"\t", "\t", []byte(*target.Custom))
	}
	// TODO(ext): UnrecognisedFields
}

func expandTargetFile(wtr io.Writer, fmtStr string, repo *tufext.Repository, target *tufmetadata.TargetFiles) error {
	targetExt := tufext.TargetFilesExt(target)

	expander := expand.NewExpansions().
		WithSource('R', func(_ *[]any) (string, error) { return repo.Name, nil }).
		WithSource('n', func(_ *[]any) (string, error) { return target.Path, nil }).
		WithSource('s', func(_ *[]any) (string, error) { return strconv.FormatInt(target.Length, 10), nil }).
		WithSource('h', func(_ *[]any) (string, error) { return target.Hashes["sha256"].String(), nil }).
		WithSource('u', func(_ *[]any) (string, error) {
			// TODO: This doesn't work when handling multiple fetch URLs.

			// Inlined targets might not be uploaded so represent them as a
			// data: URL.
			if data, err := targetExt.InlineData(); err != nil {
				return "", err
			} else if data != nil {
				return "data:;base64," + base64.StdEncoding.EncodeToString(data), nil
			}
			dataRootURL, err := repo.DataURL()
			if err != nil {
				return "", err
			}
			for url, err := range targetExt.FetchURLs(dataRootURL) {
				var urlStr string
				if url != nil {
					urlStr = url.String()
				}
				return urlStr, err
			}
			return "", errors.New("no fetch urls defined for target")
		})

	expanded, err := expander.ExpandString(fmtStr)
	if err != nil {
		return fmt.Errorf("invalid --format: %w", err)
	}
	mustFprintln(wtr, expanded)
	return nil
}

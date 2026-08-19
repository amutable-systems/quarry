// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"strconv"

	"github.com/opencontainers/go-digest"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/cmd/internal/cliext"
	"go.amutable.dev/quarry/cmd/internal/pprint"
	"go.amutable.dev/quarry/internal/ctxext"
	"go.amutable.dev/quarry/internal/expand"
	"go.amutable.dev/quarry/internal/generics"
	"go.amutable.dev/quarry/internal/tufclient"
	"go.amutable.dev/quarry/internal/tufclient/config"
	"go.amutable.dev/quarry/internal/tufext"
	"go.amutable.dev/quarry/internal/uapi16"
)

// getClient constructs a [tufclient.Client] from the configuration state.
// TODO: Unify this with quarry-sysupdate helper...
func getClient(ctx context.Context, repoNames ...string) (*tufclient.Client, error) {
	cfg := cliext.CtxConfig(ctx)

	// If the user asked for a specific set of repositories, strip out the rest
	// from the in-memory config.
	if len(repoNames) > 0 {
		filtered := make(map[string]*config.Repository, len(repoNames))
		for _, name := range repoNames {
			repo, ok := cfg.Repos[name]
			if !ok {
				return nil, fmt.Errorf("unknown repository %s requested", name)
			}
			filtered[name] = repo
		}
		cfg.Repos = filtered
	}

	client, err := tufclient.NewClient(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if refTime, ok := ctxext.RefTime(ctx); ok {
		client.SetRefTime(ctx, refTime)
	}
	return client, nil
}

func uapi16FromTargetFile(repo *config.Repository, target *tufmetadata.TargetFiles) iter.Seq2[*uapi16.File, error] {
	return generics.ErrorIter(func(yield func(*uapi16.File) bool) error {
		targetExt := tufext.TargetFilesExt(target)

		for url, err := range targetExt.FetchURLs(&repo.DataRootURL.URL) {
			if err != nil {
				return fmt.Errorf("get target candidate url: %w", err)
			}
			file := &uapi16.File{
				// TODO: What should we do about separators here?
				Name:     target.Path,
				DataURL:  url.String(),
				DataSize: uint64(target.Length),
				SHA256:   digest.SHA256.Encode(target.Hashes["sha256"]),
			}
			if !yield(file) {
				return nil
			}
		}
		return nil
	})
}

func pprintHashes(wtr io.Writer, prefix string, hashes tufmetadata.Hashes) {
	mustFprintf(wtr, "%sHashes:\n", prefix)
	for algoName, hashBytes := range hashes {
		mustFprintf(wtr, "%s - %s:%s\n", prefix, algoName, hashBytes)
	}
}

func pprintTargetFile(wtr io.Writer, prefix string, repo *config.Repository, target *tufmetadata.TargetFiles) {
	targetExt := tufext.TargetFilesExt(target)

	mustFprintf(wtr, "%s%s:\n", prefix, target.Path)
	prefix += "\t"
	mustFprintf(wtr, "%sURL(s):\n", prefix)
	for url, err := range targetExt.FetchURLs(&repo.DataRootURL.URL) {
		if err != nil {
			mustFprintf(wtr, "%s - <invalid target url: %v>\n", prefix, err)
		}
		mustFprintf(wtr, "%s - %s\n", prefix, url)
	}
	mustFprintf(wtr, "%sSize: %d\n", prefix, target.Length)
	pprintHashes(wtr, prefix, target.Hashes)
	if target.Custom != nil {
		mustFprintf(wtr, "%sCustom:\n", prefix)
		pprint.JSON(wtr, prefix+"\t", "\t", []byte(*target.Custom))
	}
	// TODO(ext): UnrecognisedFields
}

func expandTargetFile(wtr io.Writer, fmtStr string, repo *config.Repository, target *tufmetadata.TargetFiles) error {
	targetExt := tufext.TargetFilesExt(target)

	expander := expand.NewExpansions().
		WithSource('R', func(_ *[]any) (string, error) { return repo.Name, nil }).
		WithSource('n', func(_ *[]any) (string, error) { return target.Path, nil }).
		WithSource('s', func(_ *[]any) (string, error) { return strconv.FormatInt(target.Length, 10), nil }).
		WithSource('h', func(_ *[]any) (string, error) { return target.Hashes["sha256"].String(), nil }).
		WithSource('u', func(_ *[]any) (string, error) {
			// TODO: This doesn'T work
			for url, err := range targetExt.FetchURLs(&repo.DataRootURL.URL) {
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

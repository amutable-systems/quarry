// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"sync"

	"cyphar.com/go-pathrs"
	"github.com/opencontainers/umoci/pkg/hardening"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
	tufconfig "github.com/theupdateframework/go-tuf/v2/metadata/config"
	tuftrustedmetadata "github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
	tufupdater "github.com/theupdateframework/go-tuf/v2/metadata/updater"
	"golang.org/x/sys/unix"

	"go.amutable.dev/quarry/cmd/internal/pprint"
	"go.amutable.dev/quarry/internal/third_party/funchelpers"
	"go.amutable.dev/quarry/internal/tufext"
)

func makeUpdater(cacheDir *pathrs.Root, name string, repo Repository) (_ *tufupdater.Updater, Err error) {
	// TODO(tmpl): If we add template support, we need to expand it here.

	repoCacheDir, err := cacheDir.OpenFile(name, unix.O_DIRECTORY)
	if err != nil {
		return nil, fmt.Errorf("could not open repo cache dir: %w", err)
	}

	// TODO: Probably should use openat...?
	rootSubPath := filepath.Join(name, "root.json") //nolint:forbidigo // lexical pathname
	rootFile, err := cacheDir.Open(rootSubPath)
	if err != nil {
		return nil, fmt.Errorf("could not open cached root.json: %w", err)
	}
	defer funchelpers.VerifyClose(&Err, rootFile)

	rootData, err := io.ReadAll(rootFile)
	if err != nil {
		return nil, fmt.Errorf("could not read cached root.json: %w", err)
	}

	// Use the go-tuf defaults and adjust the arguments.
	tufConfig, err := tufconfig.New(repo.BaseURL.String(), rootData)
	if err != nil {
		return nil, fmt.Errorf("initialise tuf-client config: %w", err)
	}
	// Custom URLs.
	tufConfig.RemoteMetadataURL = repo.BaseURL.String()
	tufConfig.RemoteTargetsURL = repo.DataBaseURL.String()
	// Use our own cache dir.
	tufConfig.LocalMetadataDir = repoCacheDir.Name()
	// NOTE: Ideally we wouldn't have this (there is little point to this kind
	// of forced local caching) but go-tuf requires you to do it if you want to
	// cache the metadata. Really annoying.
	tufConfig.LocalTargetsDir = fmt.Sprintf("/tmp/quarry-targets-cache/%s", name)
	// At the moment our publishing flow doesn't use the <hash>.<file> naming.
	tufConfig.PrefixTargetsWithHash = false

	if err := tufConfig.EnsurePathsExist(); err != nil {
		return nil, fmt.Errorf("ensure tuf-client paths exist: %w", err)
	}
	return tufupdater.New(tufConfig)
}

// getUpdaters constructs go-tuf updater clients from the configuration state.
func getUpdaters(ctx context.Context, repoNames ...string) (map[string]*tufupdater.Updater, error) {
	config := ctxConfig(ctx)
	cacheDir := ctxCacheDir(ctx)
	refTime := ctxRefTime(ctx) // zero if unset

	if len(repoNames) == 0 {
		repoNames = slices.Collect(maps.Keys(config.Repos))
	}

	updaters := make(map[string]*tufupdater.Updater, len(config.Repos))
	for _, name := range repoNames {
		repo, ok := config.Repos[name]
		if !ok {
			return nil, fmt.Errorf("unknown repository %s", name)
		}
		updater, err := makeUpdater(cacheDir, name, repo)
		if err != nil {
			return nil, fmt.Errorf("bad repo %s: %w", name, err)
		}
		if !refTime.IsZero() {
			updater.UnsafeSetRefTime(refTime)
		}
		updaters[name] = updater
	}
	return updaters, nil
}

func verifiedHTTPGet(ctx context.Context, url *url.URL, length int64, hashes tufmetadata.Hashes) (io.ReadCloser, error) {
	digests, err := tufext.HashesToDigest(hashes)
	if err != nil {
		return nil, fmt.Errorf("convert TUF hashes to digests: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create http request: %w", err)
	}

	client := http.DefaultClient
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}

	rdr := res.Body
	for _, digest := range digests {
		rdr = &hardening.VerifiedReadCloser{
			Reader:         rdr,
			ExpectedDigest: digest,
			ExpectedSize:   length,
		}
	}
	return rdr, nil
}

func trustedMetadataTargetsFetcher(cacheDir *pathrs.Root, repo Repository, metadata *tuftrustedmetadata.TrustedMetadata) tufext.TargetMetadataFetchFunc {
	var mu sync.RWMutex // to serialise access to TrustedMetadata

	return func(ctx context.Context, roleName, delegatorName string) (_ *tufext.SignedTargets, Err error) {
		mu.RLock() // TODO: Make this cancellable with ctx.
		metaRef, ok := metadata.Snapshot.Signed.Meta[roleName+".json"]
		mu.RUnlock()
		if !ok {
			return nil, fmt.Errorf("role %s: %w", roleName, fs.ErrNotExist)
		}
		metaPath := fmt.Sprintf("%d.%s.json", metaRef.Version, roleName)
		metaURL := repo.BaseURL.JoinPath(metaPath)

		rdr, err := verifiedHTTPGet(ctx, metaURL, metaRef.Length, metaRef.Hashes)
		if err != nil {
			return nil, fmt.Errorf("get role %s (%s): %w", roleName, metaURL, err)
		}
		defer funchelpers.VerifyClose(&Err, rdr)

		data, err := io.ReadAll(rdr)
		if err != nil {
			return nil, fmt.Errorf("read %s (%s) failed: %w", metaPath, metaURL, err)
		}
		if err := rdr.Close(); err != nil {
			return nil, fmt.Errorf("close %s (%s) check failed: %w", metaPath, metaURL, err)
		}

		mu.Lock() // TODO: Make this cancellable with ctx.
		defer mu.Unlock()

		targets, err := metadata.UpdateDelegatedTargets(data, roleName, delegatorName)
		if err != nil {
			return nil, fmt.Errorf("load delegated targets: %w", err)
		}

		// Make sure to make a local copy of the file.
		// TODO: Use a pathrs-backed mktemp to allocate and swap over the file.
		filePath := filepath.Join(repo.Name, roleName+".json") //nolint:forbidigo // lexical pathname
		localFile, err := cacheDir.Create(filePath, unix.O_TRUNC|unix.O_CREAT|unix.O_WRONLY|unix.O_NOFOLLOW, 0o644)
		if err != nil {
			return nil, fmt.Errorf("open role %s cached json: %w", roleName, err)
		}
		defer funchelpers.VerifyClose(&Err, localFile)

		if _, err := localFile.Write(data); err != nil {
			return nil, fmt.Errorf("write role %s cached json: %w", roleName, err)
		}
		return targets, nil
	}
}

func pprintHashes(prefix string, hashes tufmetadata.Hashes) {
	fmt.Printf("%sHashes:\n", prefix)
	for algoName, hashBytes := range hashes {
		fmt.Printf("%s - %s:%x\n", prefix, algoName, hashBytes)
	}
}

func pprintTargetFile(prefix string, repo Repository, target *tufmetadata.TargetFiles) {
	fmt.Printf("%s%s:\n", prefix, target.Path)
	prefix += "\t"
	fmt.Printf("%sURL: %s\n", prefix, repo.DataBaseURL.JoinPath(target.Path))
	fmt.Printf("%sSize: %d\n", prefix, target.Length)
	pprintHashes(prefix, target.Hashes)
	if target.Custom != nil {
		fmt.Printf("%sCustom:\n", prefix)
		pprint.JSON(prefix+"\t", "\t", []byte(*target.Custom))
	}
	// TODO(ext): UnrecogniedFields
}

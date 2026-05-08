// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"log/slog"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"sync"

	"cyphar.com/go-pathrs"
	"github.com/opencontainers/go-digest"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
	tufconfig "github.com/theupdateframework/go-tuf/v2/metadata/config"
	tuftrustedmetadata "github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
	tufupdater "github.com/theupdateframework/go-tuf/v2/metadata/updater"
	"golang.org/x/sys/unix"

	"go.amutable.dev/quarry/cmd/internal/pprint"
	"go.amutable.dev/quarry/internal/expand"
	"go.amutable.dev/quarry/internal/generics"
	"go.amutable.dev/quarry/internal/httputils"
	"go.amutable.dev/quarry/internal/pathrsext"
	"go.amutable.dev/quarry/internal/third_party/funchelpers"
	"go.amutable.dev/quarry/internal/tufext"
	"go.amutable.dev/quarry/internal/uapi16"
)

var errSkippableRepo = errors.New("skippable repository error")

func makeUpdater(ctx context.Context, name string, repo *Repository) (_ *tufupdater.Updater, Err error) {
	cacheDir := ctxCacheDir(ctx)

	repoCacheDirHandle, err := cacheDir.MkdirAll(name, 0o755)
	if err != nil {
		return nil, fmt.Errorf("open repo cache dir: %w", err)
	}
	defer funchelpers.VerifyClose(&Err, repoCacheDirHandle)

	repoCacheDir, err := pathrs.RootFromFile(repoCacheDirHandle.IntoFile())
	if err != nil {
		return nil, fmt.Errorf("convert repo cache dir to root: %w", err)
	}
	defer funchelpers.VerifyClose(&Err, repoCacheDir)

	rootFile, err := repoCacheDir.OpenFile("root.json", unix.O_RDONLY|unix.O_NOFOLLOW)
	if errors.Is(err, fs.ErrNotExist) {
		// Fallback to fetch from the trusted root source.
		rootData, err := repo.RootTrust.FetchRoot(ctx, repo)
		if err != nil {
			return nil, fmt.Errorf("(%w) fetch trusted root.json: %w", errSkippableRepo, err)
		}
		rootFile, err = repoCacheDir.Create(".", unix.O_TMPFILE|unix.O_RDWR|unix.O_NOFOLLOW, 0o644)
		if err != nil {
			return nil, fmt.Errorf("create tmpfile for cached root.json: %w", err)
		}
		defer funchelpers.VerifyClose(&Err, rootFile)
		if _, err := rootFile.Write(rootData); err != nil {
			return nil, fmt.Errorf("write cached root.json: %w", err)
		}
		if err := rootFile.Sync(); err != nil {
			return nil, fmt.Errorf("sync cached root.json: %w", err)
		}
		_, _ = rootFile.Seek(0, io.SeekStart) // reset the file
		// Check if the local root.json is actually valid JSON before attaching
		// it. This should not happen with well-behaved servers but if we
		// accidentally commit an invalid root.json, the cache will be poisoned
		// permanently. For bundled root.json, this will cause us to never copy
		// the root.json data to the cache, but that's okay -- the bundled data
		// is static anyway.
		if root, err := tufmetadata.Root().FromBytes(rootData); err != nil {
			return nil, fmt.Errorf("(%w) root_trust root.json is invalid: %w", errSkippableRepo, err)
		} else if err := root.VerifyDelegate(tufmetadata.ROOT, root); err != nil {
			// root.json must be self-signed.
			return nil, fmt.Errorf("(%w) root_trust root.json is not self-signed: %w", errSkippableRepo, err)
		}
		// Attach as cached root.json.
		if err := pathrsext.AttachIntoRoot(repoCacheDir, "root.json", rootFile); err != nil {
			return nil, fmt.Errorf("attach trusted root.json to cache: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("open cached root.json: %w", err)
	}
	defer funchelpers.VerifyClose(&Err, rootFile)

	rootData, err := io.ReadAll(rootFile)
	if err != nil {
		return nil, fmt.Errorf("could not read cached root.json: %w", err)
	}

	// Use the go-tuf defaults and adjust the arguments.
	tufConfig, err := tufconfig.New(repo.MetaRootURL.String(), rootData)
	if err != nil {
		return nil, fmt.Errorf("initialise tuf-client config: %w", err)
	}
	tufConfig.RootMaxLength = maxRootBytes
	// Custom URLs.
	tufConfig.RemoteMetadataURL = repo.MetaRootURL.String()
	tufConfig.RemoteTargetsURL = repo.DataRootURL.String()
	// Use our own cache dir.
	tufConfig.LocalMetadataDir = repoCacheDir.IntoFile().Name()
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
		updater, err := makeUpdater(ctx, name, repo)
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, errSkippableRepo) {
			// If the root.json could not be fetched from the trust source,
			// skip it (the repository doesn't exist). This is not an issue for
			// repositories where we have already cached root.json.
			slog.Info("Cannot fetch repository root.json from root_trust -- skipping.", "error", err.Error(), "repository", name)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("bad repo %s: %w", name, err)
		}
		if !refTime.IsZero() {
			updater.UnsafeSetRefTime(refTime)
		}
		updaters[name] = updater
	}
	if len(updaters) < 1 {
		slog.Warn("no repositories defined -- all operations are a no-op")
	}
	return updaters, nil
}

func trustedMetadataTargetsFetcher(cacheDir *pathrs.Root, repo *Repository, metadata *tuftrustedmetadata.TrustedMetadata) tufext.TargetMetadataFetchFunc {
	var mu sync.RWMutex // to serialise access to TrustedMetadata

	return func(ctx context.Context, roleName, delegatorName string) (_ *tufext.SignedTargets, Err error) {
		mu.RLock() // TODO: Make this cancellable with ctx.
		metaRef, ok := metadata.Snapshot.Signed.Meta[roleName+".json"]
		mu.RUnlock()
		if !ok {
			return nil, fmt.Errorf("role %s: %w", roleName, fs.ErrNotExist)
		}
		metaPath := fmt.Sprintf("%d.%s.json", metaRef.Version, roleName)
		metaURL := repo.MetaRootURL.JoinPath(metaPath)

		rdr, _, err := httputils.VerifiedHTTPGet(ctx, metaURL, metaRef.Length, metaRef.Hashes)
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

func uapi16FromTargetFile(repo *Repository, target *tufmetadata.TargetFiles) iter.Seq2[*uapi16.File, error] {
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

func pprintHashes(prefix string, hashes tufmetadata.Hashes) {
	fmt.Printf("%sHashes:\n", prefix)
	for algoName, hashBytes := range hashes {
		fmt.Printf("%s - %s:%s\n", prefix, algoName, hashBytes)
	}
}

func pprintTargetFile(prefix string, repo *Repository, target *tufmetadata.TargetFiles) {
	targetExt := tufext.TargetFilesExt(target)

	fmt.Printf("%s%s:\n", prefix, target.Path)
	prefix += "\t"
	fmt.Printf("%sURL(s):\n", prefix)
	for url, err := range targetExt.FetchURLs(&repo.DataRootURL.URL) {
		if err != nil {
			fmt.Printf("%s - <invalid target url: %v>\n", prefix, err)
		}
		fmt.Printf("%s - %s\n", prefix, url)
	}
	fmt.Printf("%sSize: %d\n", prefix, target.Length)
	pprintHashes(prefix, target.Hashes)
	if target.Custom != nil {
		fmt.Printf("%sCustom:\n", prefix)
		pprint.JSON(prefix+"\t", "\t", []byte(*target.Custom))
	}
	// TODO(ext): UnrecognisedFields
}

func expandTargetFile(fmtStr string, repo *Repository, target *tufmetadata.TargetFiles) error {
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
	fmt.Println(expanded)
	return nil
}

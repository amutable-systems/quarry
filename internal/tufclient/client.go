// Copyright (C) 2026 Amutable GmbH

// Package tufclient provides helpers for creating a set TUF clients to fetch
// data from Quarry repositories.
package tufclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"sync"
	"time"

	"cyphar.com/go-pathrs"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
	tufconfig "github.com/theupdateframework/go-tuf/v2/metadata/config"
	tuftrustedmetadata "github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
	tufupdater "github.com/theupdateframework/go-tuf/v2/metadata/updater"
	"golang.org/x/sys/unix"

	"go.amutable.dev/quarry/internal/generics"
	"go.amutable.dev/quarry/internal/httputils"
	"go.amutable.dev/quarry/internal/jsonutils"
	"go.amutable.dev/quarry/internal/pathrsext"
	"go.amutable.dev/quarry/internal/third_party/funchelpers"
	"go.amutable.dev/quarry/internal/tufclient/config"
	"go.amutable.dev/quarry/internal/tufext"
)

// ErrSkippableRepo is returned as part of a wrapped error by [RepoClient] if
// the repository could not be loaded but the error should not necessarily be
// seen as a fatal error condition (i.e., the repository has never been seen
// before and so may not be created yet). [NewClient] skips such repositories,
// though [Client.WithRepos] will return the errors if said repositories are
// requested explicitly.
var ErrSkippableRepo = errors.New("skippable repository error")

// RepoClient constructs a [tufupdater.Updater] for a single TUF repository,
// defined by a [config.Repository] configuration.
func RepoClient(ctx context.Context, cacheDir *pathrs.Root, repo *config.Repository) (_ *tufupdater.Updater, Err error) {
	repoCacheDirHandle, err := cacheDir.MkdirAll(repo.Name, 0o755)
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
			return nil, fmt.Errorf("(%w) fetch trusted root.json: %w", ErrSkippableRepo, err)
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
		if root, err := jsonutils.Parse[*tufext.SignedRoot](rootData); err != nil {
			return nil, fmt.Errorf("(%w) root_trust root.json is invalid JSON: %w", ErrSkippableRepo, err)
		} else if err := tufext.CheckMetadataType(tufmetadata.ROOT, root); err != nil {
			return nil, fmt.Errorf("(%w) root_trust root.json is invalid tuf JSON: %w", ErrSkippableRepo, err)
		} else if err := root.VerifyDelegate(tufmetadata.ROOT, root); err != nil {
			// root.json must be self-signed.
			return nil, fmt.Errorf("(%w) root_trust root.json is not self-signed: %w", ErrSkippableRepo, err)
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
	tufConfig.RootMaxLength = config.MaxRootBytes
	// Custom URLs.
	tufConfig.RemoteMetadataURL = repo.MetaRootURL.String()
	tufConfig.RemoteTargetsURL = repo.DataRootURL.String()
	// Use our own cache dir.
	tufConfig.LocalMetadataDir = repoCacheDir.IntoFile().Name()
	// NOTE: Ideally we wouldn't have this (there is little point to this kind
	// of forced local caching) but go-tuf requires you to do it if you want to
	// cache the metadata. Really annoying.
	tufConfig.LocalTargetsDir = fmt.Sprintf("/tmp/quarry-targets-cache/%s", repo.Name)
	// At the moment our publishing flow doesn't use the <hash>.<file> naming.
	tufConfig.PrefixTargetsWithHash = false

	if err := tufConfig.EnsurePathsExist(); err != nil {
		return nil, fmt.Errorf("ensure tuf-client paths exist: %w", err)
	}
	return tufupdater.New(tufConfig)
}

// Client represents a Quarry client.
type Client struct {
	// Config is a copy of the configuration file used to instantiate this
	// client instance.
	Config *config.Config

	// CacheDir is a handle to the cache directory where all TUF metadata files
	// are stored. You should only operate on this if you are absolutely sure
	// that you know what you're doing (it includes the primary copy of trusted
	// local metadata).
	CacheDir *pathrs.Root

	// updaters contains the TUF updaters for every repository that was
	// successfully loaded by [NewClient], regardless of the subset currently
	// selected with [Client.WithRepos] (activeRepos).
	updaters map[string]*tufupdater.Updater

	// activeRepos contains the TUF updaters for the active set of repositories
	// that all operations act on. By default this is every loaded repository
	// (updaters), but [Client.WithRepos] can swap in a subset.
	activeRepos generics.Set[string]

	// skippedRepos records the (skippable) error that stopped each unloadable
	// repository from being included in updaters by [NewClient].
	skippedRepos map[string]error
}

// WithRepos restricts the [Client] to the given subset of configured
// repositories. Unknown repository names result in an error, as does a
// requested repository that could not be loaded when the [Client] was created
// (even if the failure was tagged as skippable with [ErrSkippableRepo]).
//
// Calling WithRepos with no arguments re-enables all configured repositories.
// If an error is returned, the active set of repositories is unchanged.
func (client *Client) WithRepos(repoNames ...string) error {
	if len(repoNames) == 0 {
		// Reset activeRepos and ignore any client.skippedRepos errors.
		client.activeRepos = generics.SeqSet(maps.Keys(client.updaters))
		return nil
	}
	var (
		active = make(generics.Set[string], len(repoNames))
		errs   []error
	)
	for _, name := range repoNames {
		if _, ok := client.updaters[name]; ok {
			active[name] = struct{}{}
		} else if err, ok := client.skippedRepos[name]; ok {
			errs = append(errs, fmt.Errorf("bad repo %s: %w", name, err))
		} else {
			errs = append(errs, fmt.Errorf("unknown repository %s requested", name))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	client.activeRepos = active
	return nil
}

// IterRepos returns an iterator over the ste of repositories in the [Client].
// Note that this operation is very rarely necessary, most of the time
// [GetTargetInfo] and [FetchTargetFile] are more ergonomic.
//
// TODO: Return some custom type?
func (client *Client) IterRepos(_ context.Context) iter.Seq2[string, *tufupdater.Updater] {
	return func(yield func(string, *tufupdater.Updater) bool) {
		for name := range client.updaters {
			if _, ok := client.activeRepos[name]; !ok {
				continue
			}
			if !yield(name, client.updaters[name]) {
				break
			}
		}
	}
}

// Close closes all resources associated with the client.
func (client *Client) Close() error {
	return client.CacheDir.Close()
}

// SetRefTime configures the reference time for the client. In principle this
// opens you up to freeze attacks, so this should only ever be used for testing
// purposes.
func (client *Client) SetRefTime(ctx context.Context, refTime time.Time) {
	for _, updater := range client.IterRepos(ctx) {
		updater.UnsafeSetRefTime(refTime)
	}
}

// TargetInfo is a tuple of [*tufmetadata.TargetFiles] and [*config.Repository]
// which is returned by most [Client] methods. This is necessary to help with
// identifying which repository a target file comes from, as well as doing some
// other operations.
type TargetInfo struct {
	*tufmetadata.TargetFiles
	Repo *config.Repository
}

// Fetch retreives the target file referenced by this [TargetInfo] and returns
// a stream to the file contents. This stream is backed by a
// [hardening.VerifiedReadCloser], so users must check the return value of the
// [io.ReadCloser.Close] method before using the data for anything.
//
// A wrapped [fs.ErrNotExist] error is returned if the target file could not be
// found (either in the repository metadata or from the download URL).
func (info *TargetInfo) Fetch(ctx context.Context) (io.ReadCloser, error) {
	infoExt := tufext.TargetFilesExt(info.TargetFiles)

	// Return the inline data if it is available (and valid).
	if data, err := infoExt.InlineData(); err != nil {
		slog.Info("Target file inline data is invalid, falling back to remote URL fetching...",
			"repo", info.Repo.Name, "target", info.Path, "err", err.Error())
	} else if data != nil {
		return io.NopCloser(bytes.NewReader(data)), nil
	}

	// Rather than using the go-tuf DownloadTarget (which requires the data be
	// stored in-memory) we fetch it directly.
	for url, err := range infoExt.FetchURLs(&info.Repo.DataRootURL.URL) {
		if err != nil {
			return nil, fmt.Errorf("check target candidate urls: %w", err)
		}
		rdr, _, err := httputils.VerifiedHTTPGet(ctx, url, info.Length, info.Hashes)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				slog.Info("Target file not available at URL, trying next candidate...",
					"repo", info.Repo.Name, "target", info.Path, "url", url.String())
			} else {
				slog.Info("Target file could not be fetched from URL, trying next candidate...",
					"repo", info.Repo.Name, "target", info.Path, "url", url.String(), "err", err.Error())
			}
			continue
		}
		return rdr, nil
	}
	return nil, fmt.Errorf("%w: target not present at any fetch url", fs.ErrNotExist)
}

// GetTargetInfo returns the TUF metadata concerning the given file name.
//
// A wrapped [fs.ErrNotExist] error is returned if the target file could not be
// found.
func (client *Client) GetTargetInfo(ctx context.Context, targetPath string) (*TargetInfo, error) {
	var got *TargetInfo
	for repoName, updater := range client.IterRepos(ctx) {
		info, err := updater.GetTargetInfo(targetPath)
		if err != nil {
			// FIXME: Grrr, why don't they use wrapped errors for this?!
			if err.Error() == fmt.Sprintf("target %s not found", targetPath) {
				continue
			}
			return nil, fmt.Errorf("bad repo %s: %w", repoName, err)
		}
		// We've found the target file, but continue iterating through the rest
		// of the repositories -- because map iteration order is randomised, we
		// can't be sure if subsequent calls to GetTargetInfo will return the
		// same file, which is *very bad*. The temporary solution here is to
		// make sure there are no duplicate targets.
		// TODO: We need to come up with an order to these updaters, as
		// blocking updates because of a clashing name is really quite drastic.
		// Maybe we should just do it in the order they were defined in the
		// config...?
		// TODO(links): This problem will only get worse once we have links...
		if got != nil {
			return nil, fmt.Errorf("ambiguous repository state: target %s defined in multiple repositories (%s and %s)", targetPath, got.Repo.Name, repoName)
		}
		got = &TargetInfo{
			TargetFiles: info,
			Repo:        client.Config.Repos[repoName],
		}
	}
	var err error
	if got == nil {
		err = fmt.Errorf("target %s not found: %w", targetPath, fs.ErrNotExist)
	}
	return got, err
}

// FetchTargetFile is shorthand for [ClientGetTargetInfo] followed by
// [TargetInfo.Fetch].
func (client *Client) FetchTargetFile(ctx context.Context, targetPath string) (io.ReadCloser, *TargetInfo, error) {
	info, err := client.GetTargetInfo(ctx, targetPath)
	if err != nil {
		return nil, nil, err
	}
	rdr, err := info.Fetch(ctx)
	if err != nil {
		return nil, nil, err
	}
	return rdr, info, nil
}

// trustedMetadataTargetsFetcher returns a [tufext.TargetMetadataFetchFunc] for
// the given repository in the client.
func (client *Client) trustedMetadataTargetsFetcher(repo *config.Repository, metadata *tuftrustedmetadata.TrustedMetadata) tufext.TargetMetadataFetchFunc {
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
			return nil, fmt.Errorf("load delegated target %s: %w", roleName, err)
		}

		// Make sure to make a local copy of the file.
		// TODO: Use a pathrs-backed mktemp to allocate and swap over the file.
		filePath := filepath.Join(repo.Name, roleName+".json") //nolint:forbidigo // lexical pathname
		localFile, err := client.CacheDir.Create(filePath, unix.O_TRUNC|unix.O_CREAT|unix.O_WRONLY|unix.O_NOFOLLOW, 0o644)
		if err != nil {
			return nil, fmt.Errorf("write role %s cached json: %w", roleName, err)
		}
		defer funchelpers.VerifyClose(&Err, localFile)

		if _, err := localFile.Write(data); err != nil {
			return nil, fmt.Errorf("write role %s cached json: %w", roleName, err)
		}
		return targets, localFile.Sync()
	}
}

// IterTargetFiles iterates over all target files in all repositories defined
// in the [Client].
func (client *Client) IterTargetFiles(ctx context.Context) iter.Seq2[*TargetInfo, error] {
	return generics.ErrorIter(func(yield func(*TargetInfo) bool) error {
		seen := make(map[string]struct{}, 512) // TODO: Figure out a reasonable default map size.
		for repoName, updater := range client.IterRepos(ctx) {
			if err := ctx.Err(); err != nil {
				return err
			}

			repo := client.Config.Repos[repoName]
			meta := updater.GetTrustedMetadataSet()
			if meta.Timestamp == nil {
				// FIXME: The local client TrustedMetadata state does not get
				// filled until we do a refresh but go-tuf's client does not
				// allow Refresh on the same updater more than once(?!). So we
				// do a refresh here opportunistically.
				// TODO: Add a (*Client).Refresh helper to make this much less
				// fragile.
				if err := updater.Refresh(); err != nil {
					return fmt.Errorf("refresh repo %s: %w", repo.Name, err)
				}
				meta = updater.GetTrustedMetadataSet()
			}
			fetchFn := client.trustedMetadataTargetsFetcher(repo, &meta)

			for target, err := range tufext.IterTargetFiles(ctx, fetchFn) {
				if err != nil {
					return fmt.Errorf("error while scanning repo %s: %w", repoName, err)
				}
				if err := ctx.Err(); err != nil {
					return err
				}
				if _, ok := seen[target.Path]; ok {
					// As with GetTargetInfo, we need to check and reject
					// duplicate entries.
					// TODO: We need to come up with an order to these
					// updaters, as blocking updates because of a clashing name
					// is really quite drastic. Maybe we should just do it in
					// the order they were defined in the config...? Then we
					// can just drop later entries.
					// TODO(links): This problem will only get worse once we
					// have links...
					continue
				}
				seen[target.Path] = struct{}{}

				info := &TargetInfo{
					TargetFiles: target.TargetFiles,
					Repo:        repo,
				}
				if !yield(info) {
					return nil
				}
			}
		}
		return nil
	})
}

// NewClient constructs a new Quarry [Client] for the given configuration. The
// cache directory referenced by [config.Config.CacheDir] may be written to by
// this operation.
func NewClient(ctx context.Context, config *config.Config) (_ *Client, Err error) {
	// TODO(links): Once we add cross-repo links this will need to expand out
	// the links, either here upfront or on-demand in IterRepos...?

	// TODO: Should this really be world-readable...?
	if err := os.MkdirAll(config.CacheDir, 0o755); err != nil { //nolint:forbidigo // user-controlled host path
		return nil, fmt.Errorf("create client cache directory: %w", err)
	}

	cacheDir, err := pathrs.OpenRoot(config.CacheDir)
	if err != nil {
		return nil, fmt.Errorf("open cache directory: %w", err)
	}
	defer funchelpers.CloseOnError(&Err, cacheDir)

	var (
		updaters     = make(map[string]*tufupdater.Updater, len(config.Repos))
		skippedRepos = make(map[string]error)
	)
	for _, repo := range config.Repos {
		updater, err := RepoClient(ctx, cacheDir, repo)
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, ErrSkippableRepo) {
			// If the root.json could not be fetched from the trust source,
			// skip it (the repository doesn't exist). This is not an issue for
			// repositories where we have already cached root.json. The error
			// is retained so that [Client.WithRepos] can surface it if
			// the repository is requested explicitly.
			slog.Info("Cannot fetch repository root.json from root_trust -- skipping.", "error", err.Error(), "repository", repo.Name)
			skippedRepos[repo.Name] = err
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("bad repo %s: %w", repo.Name, err)
		}
		updaters[repo.Name] = updater
	}
	if len(updaters) < 1 {
		slog.Warn("No repositories defined -- all operations are a no-op!")
	}
	return &Client{
		Config:       config,
		CacheDir:     cacheDir,
		updaters:     updaters,
		activeRepos:  generics.SeqSet(maps.Keys(updaters)), // enable all repos
		skippedRepos: skippedRepos,
	}, nil
}

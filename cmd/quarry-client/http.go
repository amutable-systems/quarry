//go:build http

// Copyright (C) 2026 Amutable GmbH

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-systemd/v22/activation"
	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/gorilla/handlers"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/third_party/funchelpers"
	"go.amutable.dev/quarry/internal/tufext"
)

func init() {
	app.Commands = append(app.Commands, httpCommand)
}

func httpErrHandler(fn func(http.ResponseWriter, *http.Request) error) func(http.ResponseWriter, *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		err := fn(rw, req)
		if err != nil {
			http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
			slog.ErrorContext(ctx, "Internal Server Error", "err", err.Error())
		}
	}
}

// sha256Empty is the sha256 hash of the empty string (used as a dummy
// value for BEST-BEFORE-YYYY-MM-DD).
const sha256Empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func validSystemdFilename(path string) bool {
	const _PATH_MAX = 4096 //nolint:revive // match unix.PAGE_SIZE naming style
	return path != "" && path != "." && path != ".." &&
		!strings.Contains(path, "/") && len(path) <= _PATH_MAX
}

func serveSHA256SUMS(rw http.ResponseWriter, req *http.Request) (Err error) {
	ctx := req.Context()

	// FIXME: This needs to be re-created every time because go-tuf has no
	// mechanism to refresh an updater that has already been used to fetch
	// information.
	// TODO: Add support for a Refresh in Client that doesn't break like that.
	client, err := getClient(ctx)
	if err != nil {
		return fmt.Errorf("get tuf-client updaters: %w", err)
	}
	defer funchelpers.VerifyClose(&Err, client)

	// Refresh all of the updaters first.
	var (
		errs   []error
		expiry time.Time
	)
	for repoName, updater := range client.IterRepos(ctx) {
		// Construct BEST-BEFORE-YYYY-MM-DD based on the earliest timestamp
		// expiry in any of the enabled repositories.
		meta := updater.GetTrustedMetadataSet()
		if meta.Timestamp == nil {
			// FIXME: The local client TrustedMetadata state does not get
			// filled until we do a refresh but go-tuf's client does not
			// allow Refresh on the same updater more than once(?!). So we
			// do a refresh here opportunistically.
			// TODO: Add a (*Client).Refresh helper to make this much less
			// fragile.
			if err := updater.Refresh(); err != nil {
				err := fmt.Errorf("refresh repo %s: %w", repoName, err)
				errs = append(errs, err)
			}
			meta = updater.GetTrustedMetadataSet()
		}
		timestampExpiry := meta.Timestamp.Signed.Expires
		if expiry.IsZero() || expiry.After(timestampExpiry) {
			// The BEST-BEFORE-* format only has day-resolution, so round to
			// the next day so that we never indicate that a repository is
			// invalid early. This tag in SHA256SUMS is also not really
			// security critical, TUF is actually protecting against the freeze
			// attack here.
			expiry = timestampExpiry.Add(24 * time.Hour)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("refresh repos: %w", err)
	}

	// TODO: We do not write to the ResponseWriter directly because we might
	// encounter errors during execution -- is that okay?
	sumfileBuf := bytes.NewBuffer(make([]byte, 0, 1<<16))

	if !expiry.IsZero() {
		fmt.Fprintf(sumfileBuf, "%s  BEST-BEFORE-%s\n", sha256Empty, expiry.Format(time.DateOnly))
	}

	for target, err := range client.IterTargetFiles(ctx) {
		if err != nil {
			return err
		}
		// sysupdate does not permit certain pathnames in repos, while TUF
		// basically allows everything. Would could path-escape the paths
		// but then we would need to unescape them on get, so just strip
		// them for now. Currently this is only planned to be used for
		// sysupdate.d/ injection (which is handled outside of sysupdate --
		// specifically, by hack/quarry-sysupdate -- anyway).
		if !validSystemdFilename(target.Path) {
			// TODO: Should we encode the path?
			slog.Info("Stripped sysupdate-incompatible pathname from generated SHA256SUMS",
				"target", target.Path)
			continue
		}
		fmt.Fprintf(sumfileBuf, "%s  %s\n", target.Hashes["sha256"], target.Path)
	}

	rw.Header().Set("Content-Length", strconv.Itoa(sumfileBuf.Len()))
	rw.Header().Set("Content-Type", "text/plain")

	_, _ = io.Copy(rw, sumfileBuf)
	return nil
}

func hashesToContentDigest(hashes tufmetadata.Hashes) []string {
	digests := make([]string, 0, len(hashes))
	for algoName, hashBytes := range hashes {
		digests = append(digests, fmt.Sprintf("%s=%s", algoName, hashBytes))
	}
	return digests
}

func proxyTargetFile(rw http.ResponseWriter, req *http.Request) (Err error) {
	ctx := req.Context()

	// FIXME: This needs to be re-created every time because go-tuf has no
	// mechanism to refresh an updater that has already been used to fetch
	// information.
	// TODO: Add support for a Refresh in Client that doesn't break like that.
	client, err := getClient(ctx)
	if err != nil {
		return fmt.Errorf("get tuf-client updaters: %w", err)
	}
	defer funchelpers.VerifyClose(&Err, client)

	// TODO: The updaters really should be sorted here so we can pick the first
	// one with a matching file.

	targetPath := filepath.Join(".", req.PathValue("target")) //nolint:forbidigo // lexical path conversion from absolute to relative

	info, err := client.GetTargetInfo(ctx, targetPath)
	if errors.Is(err, fs.ErrNotExist) {
		// Could not find the target file.
		http.NotFound(rw, req)
		return nil
	}
	if err != nil {
		return fmt.Errorf("fetch target %s info: %w", targetPath, err)
	}
	infoExt := tufext.TargetFilesExt(info.TargetFiles)

	// Redirect to the first target URL.
	// TODO(uapi16): Once we get UAPI.16 support into systemd, we would
	// generate an entry for every URL candidate.
	for url, err := range infoExt.FetchURLs(&info.Repo.DataRootURL.URL) {
		if err != nil {
			return fmt.Errorf("bad target data in repo %s for target %s: cannot compute target url: %w", info.Repo.Name, targetPath, err)
		}
		// TODO: Is it really not possible to provide Content-Length and
		// Content-Digest here...?
		rw.Header().Set("X-Quarry-Content-Length", strconv.FormatInt(info.Length, 10))
		rw.Header()["X-Quarry-Content-Digest"] = hashesToContentDigest(info.Hashes)
		http.Redirect(rw, req, url.String(), http.StatusFound)
		return nil
	}
	return errors.New("no fetch urls defined for target")
}

var httpCommand = &cli.Command{
	Name:  "http",
	Usage: "spawn a compatibility-shim SHA256SUMS-based sysupdate http server",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "bind-address",
			Aliases: []string{"H"},
			Usage:   "address ([host]:port) to bind to",
			Value:   ":20835", // hex("Qc")
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		listeners, err := activation.Listeners()
		if err != nil {
			return err
		}

		// TODO: Support serving via TLS?

		var proto http.Protocols
		proto.SetHTTP1(true)
		proto.SetHTTP2(false) // no TLS
		proto.SetUnencryptedHTTP2(true)

		mux := http.NewServeMux()
		mux.HandleFunc("/SHA256SUMS", httpErrHandler(serveSHA256SUMS))
		mux.HandleFunc("/{target...}", httpErrHandler(proxyTargetFile))

		handler := handlers.CombinedLoggingHandler(os.Stdout, mux)

		server := &http.Server{
			Addr:        cmd.String("bind-address"),
			Handler:     handler,
			BaseContext: func(_ net.Listener) context.Context { return ctx },
			Protocols:   &proto,
		}
		mustFprintf(os.Stdout, "Listening on http://%s...\n", server.Addr)

		var (
			wg    sync.WaitGroup
			errCh = make(chan error, len(listeners)+1)
		)
		if len(listeners) > 0 {
			for _, listener := range listeners {
				wg.Go(func() {
					if err := server.Serve(listener); err != nil {
						errCh <- err
					}
				})
			}
		} else {
			wg.Go(func() {
				if err := server.ListenAndServe(); err != nil {
					errCh <- err
				}
			})
		}
		if _, err := daemon.SdNotify(false, daemon.SdNotifyReady); err != nil {
			_ = server.Close()
			return err
		}
		wg.Wait()
		close(errCh)

		// TODO: Support graceful shutdown and ErrServerClosed.
		var errs []error
		for err := range errCh {
			errs = append(errs, err)
		}
		return errors.Join(errs...)
	},
}

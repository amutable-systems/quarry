// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/schollz/progressbar/v3"
	"github.com/urfave/cli/v3"
	"golang.org/x/sys/unix"

	"go.amutable.dev/quarry/internal/httputils"
	"go.amutable.dev/quarry/internal/third_party/fdutils"
	"go.amutable.dev/quarry/internal/third_party/funchelpers"
	"go.amutable.dev/quarry/internal/tufext"
)

var fetchCommand = withRefTimeFlag(&cli.Command{
	Name:  "fetch",
	Usage: "fetch a specific file from the repos",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "repo",
			Aliases:  []string{"r"},
			Usage:    "specify the repository to look for",
			Required: true,
		},
		&cli.StringFlag{
			Name:  "output",
			Usage: "save the file to the given path ('-' for stdout, if slash-terminated the target name is appended)",
			Value: "./",
		},
	},
	Arguments: []cli.Argument{
		&cli.StringArg{
			Name: "target",
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) (Err error) {
		config := ctxConfig(ctx)

		target := cmd.StringArg("target")
		if target == "" {
			return fmt.Errorf("target is a required argument")
		}

		var output io.Writer
		outputPath := cmd.String("output")
		if outputPath != "-" {
			if strings.HasSuffix(outputPath, "/") {
				outputPath = filepath.Join(outputPath, target) //nolint:forbidigo // user-controlled host path
			}
			dirPath := filepath.Dir(outputPath)                 //nolint:forbidigo // user-controlled host path
			if err := os.MkdirAll(dirPath, 0o755); err != nil { //nolint:forbidigo // user-controlled host path
				return fmt.Errorf("make parent directories for %s: %w", outputPath, err)
			}
			// We use an O_TMPFILE so that we do not expose untrusted data to
			// the filesystem until we have verified its hash.
			outputFile, err := os.OpenFile(dirPath, unix.O_TMPFILE|unix.O_WRONLY, 0o644) //nolint:forbidigo // O_TMPFILE
			if err != nil {
				return fmt.Errorf("create target tmpfile: %w", err)
			}
			defer funchelpers.VerifyClose(&Err, outputFile)

			output = outputFile
		} else {
			outputPath = "/dev/stdout"
			output = os.Stdout
		}

		repoName := cmd.String("repo")
		updaters, err := getUpdaters(ctx, repoName)
		if err != nil {
			return fmt.Errorf("get tuf-client updater for repo %s: %w", repoName, err)
		}
		if len(updaters) != 1 {
			return fmt.Errorf("incorrect number of updaters returned? %#v", updaters)
		}
		updater := updaters[repoName]
		repo := config.Repos[repoName]

		info, err := updater.GetTargetInfo(target)
		if err != nil {
			return fmt.Errorf("get target info for %s: %w", target, err)
		}
		targetFile := tufext.TargetFilesExt(info)

		// Rather than using the go-tuf DownloadTarget (which requires the data
		// be stored in-memory) we fetch it directly.

		var (
			targetRdr io.ReadCloser
			targetURL *url.URL
		)
		for url, err := range targetFile.FetchURLs(&repo.DataRootURL.URL) {
			if err != nil {
				return fmt.Errorf("get url for target %s: %w", target, err)
			}
			rdr, _, err := httputils.VerifiedHTTPGet(ctx, url, targetFile.Length, targetFile.Hashes)
			if errors.Is(err, fs.ErrNotExist) {
				slog.Info("Target file not available at URL, trying next candidate...",
					"repo", repo.Name, "target", target, "url", url.String())
				continue
			}
			if err != nil {
				return fmt.Errorf("fetch target candidate url %s: %w", url, err)
			}
			targetRdr, targetURL = rdr, url
			break
		}
		if targetRdr == nil {
			return fmt.Errorf("%w: target %s not present at any fetch url", fs.ErrNotExist, target)
		}
		defer funchelpers.VerifyClose(&Err, targetRdr)

		bar := progressbar.DefaultBytes(targetFile.Length, targetFile.Path)

		if _, err := io.Copy(io.MultiWriter(output, bar), targetRdr); err != nil {
			return fmt.Errorf("stream target %s (%s) to output: %w", target, targetURL, err)
		}
		if err := targetRdr.Close(); err != nil {
			return fmt.Errorf("close check %s (%s) failed: %w", target, targetURL, err)
		}

		if outputPath != "-" {
			outputFile := output.(*os.File) //nolint:forcetypeassert // guaranteed to be true
			if err := fdutils.WithFileFd(outputFile, func(srcFd uintptr) error {
				return unix.Linkat(int(srcFd), "", unix.AT_FDCWD, outputPath, unix.AT_EMPTY_PATH) //nolint:forbidigo // user-controlled host paths
			}); err != nil {
				return fmt.Errorf("attach target %s to %q: %w", target, outputPath, err)
			}
		}

		fmt.Fprintf(os.Stderr, "Wrote %d bytes to %q.\n", targetFile.Length, outputPath)
		return nil
	},
})

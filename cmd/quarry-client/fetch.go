// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/schollz/progressbar/v3"
	"github.com/urfave/cli/v3"
	"golang.org/x/sys/unix"

	"go.amutable.dev/quarry/internal/third_party/fdutils"
	"go.amutable.dev/quarry/internal/third_party/funchelpers"
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
		client, err := getClient(ctx, repoName)
		if err != nil {
			return fmt.Errorf("get tuf client for repo %s: %w", repoName, err)
		}
		defer funchelpers.VerifyClose(&Err, client)

		rdr, info, err := client.FetchTargetFile(ctx, target)
		if err != nil {
			return fmt.Errorf("fetch target %s: %w", target, err)
		}
		defer funchelpers.VerifyClose(&Err, rdr)

		bar := progressbar.DefaultBytes(info.Length, info.Path)

		if _, err := io.Copy(io.MultiWriter(output, bar), rdr); err != nil {
			return fmt.Errorf("stream target %s to output: %w", target, err)
		}
		if err := rdr.Close(); err != nil {
			return fmt.Errorf("close check %s failed: %w", target, err)
		}

		if outputPath != "-" {
			outputFile := output.(*os.File) //nolint:forcetypeassert // guaranteed to be true
			if err := fdutils.WithFileFd(outputFile, func(srcFd uintptr) error {
				return unix.Linkat(int(srcFd), "", unix.AT_FDCWD, outputPath, unix.AT_EMPTY_PATH) //nolint:forbidigo // user-controlled host paths
			}); err != nil {
				return fmt.Errorf("attach target %s to %q: %w", target, outputPath, err)
			}
		}

		fmt.Fprintf(os.Stderr, "Wrote %d bytes to %q.\n", info.Length, outputPath)
		return nil
	},
})

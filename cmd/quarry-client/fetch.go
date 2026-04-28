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

	"go.amutable.dev/quarry/internal/third_party/funchelpers"
)

var fetchCommand = &cli.Command{
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
			// TODO: Use an O_TMPFILE that gets attached once the hash check
			// succeeds.
			outputFile, err := os.Create(outputPath) //nolint:forbidigo // user-controlled host path
			if err != nil {
				return fmt.Errorf("open target path %s: %w", outputPath, err)
			}
			defer funchelpers.VerifyClose(&Err, outputFile)

			output = outputFile
		} else {
			outputPath = "/dev/stdout"
			output = os.Stdout
		}

		repoName := cmd.String("repo")
		updaters, err := getUpdaters(ctx, cmd, repoName)
		if err != nil {
			return fmt.Errorf("get tuf-client updater for repo %s: %w", repoName, err)
		}
		if len(updaters) != 1 {
			return fmt.Errorf("incorrect number of updaters returned? %#v", updaters)
		}
		updater := updaters[repoName]
		repo := config.Repos[repoName]

		targetFile, err := updater.GetTargetInfo(target)
		if err != nil {
			return fmt.Errorf("get target info for %s: %w", target, err)
		}

		// Rather than using the go-tuf DownloadTarget (which requires the data
		// be stored in-memory) we fetch it directly.
		targetURL := repo.DataBaseURL.JoinPath(targetFile.Path)
		rdr, err := verifiedHTTPGet(ctx, targetURL, targetFile.Length, targetFile.Hashes)
		if err != nil {
			return fmt.Errorf("get target %s (%s): %w", target, targetURL, err)
		}
		defer funchelpers.VerifyClose(&Err, rdr)

		bar := progressbar.DefaultBytes(targetFile.Length, targetFile.Path)

		if _, err := io.Copy(io.MultiWriter(output, bar), rdr); err != nil {
			return fmt.Errorf("stream target %s (%s) to output: %w", target, targetURL, err)
		}
		if err := rdr.Close(); err != nil {
			return fmt.Errorf("close check %s (%s) failed: %w", target, targetURL, err)
		}
		fmt.Fprintf(os.Stderr, "Wrote %d bytes to %q.\n", targetFile.Length, outputPath)
		return nil
	},
}

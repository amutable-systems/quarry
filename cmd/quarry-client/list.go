// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/generics"
	"go.amutable.dev/quarry/internal/third_party/funchelpers"
	"go.amutable.dev/quarry/internal/tufclient"
	"go.amutable.dev/quarry/internal/uapi16"
	"go.amutable.dev/quarry/internal/uapi16ext"
)

// listFormatter is the backend used by "list" to output the target files it
// finds, with one implementation per output format.
type listFormatter interface {
	// Begin is called before any target files are output to allow the
	// formatter to prepare any special metadata based on the client state.
	// Formatters must not iterate over target files themselves in this method.
	Begin(ctx context.Context, client *tufclient.Client) error

	// Output outputs a single target file.
	Output(ctx context.Context, target *tufclient.TargetInfo) error

	// Finish outputs anything that had to be buffered until the whole listing
	// was known.
	Finish(ctx context.Context) error
}

// plainListFormatter outputs just the name of each target file.
type plainListFormatter struct{ wtr io.Writer }

func newPlainListFormatter(wtr io.Writer) *plainListFormatter {
	return &plainListFormatter{wtr: wtr}
}

func (*plainListFormatter) Begin(context.Context, *tufclient.Client) error { return nil }

func (o *plainListFormatter) Output(_ context.Context, target *tufclient.TargetInfo) error {
	mustFprintln(o.wtr, target.Path)
	return nil
}

func (*plainListFormatter) Finish(context.Context) error { return nil }

// verboseListFormatter outputs all of the metadata we have for each target
// file.
type verboseListFormatter struct{ wtr io.Writer }

func newVerboseListFormatter(wtr io.Writer) *verboseListFormatter {
	return &verboseListFormatter{wtr: wtr}
}

func (*verboseListFormatter) Begin(context.Context, *tufclient.Client) error { return nil }

func (o *verboseListFormatter) Output(_ context.Context, target *tufclient.TargetInfo) error {
	pprintTargetFile(o.wtr, "", target.Repo, target.TargetFiles)
	return nil
}

func (*verboseListFormatter) Finish(context.Context) error { return nil }

// formatListFormatter outputs each target file using a user-provided
// %-expansion format string.
type formatListFormatter struct {
	wtr    io.Writer
	format string
}

func newFormatListFormatter(wtr io.Writer, format string) *formatListFormatter {
	return &formatListFormatter{wtr: wtr, format: format}
}

func (*formatListFormatter) Begin(context.Context, *tufclient.Client) error { return nil }

func (o *formatListFormatter) Output(_ context.Context, target *tufclient.TargetInfo) error {
	return expandTargetFile(o.wtr, o.format, target.Repo, target.TargetFiles)
}

func (*formatListFormatter) Finish(context.Context) error { return nil }

// uapi16ListFormatter streams the target files out as a UAPI.16 manifest.
type uapi16ListFormatter struct{ wtr *uapi16.Writer }

func newUAPI16ListFormatter(wtr io.Writer) *uapi16ListFormatter {
	return &uapi16ListFormatter{wtr: uapi16.NewWriter(wtr)}
}

func (o *uapi16ListFormatter) Begin(ctx context.Context, client *tufclient.Client) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var root uapi16.File
	// Include the earliest repo expiry in the manifest to act as a backstop
	// against someone using this manifest indefinitely.
	expiry, err := earliestTimestampExpiry(ctx, client)
	if err != nil {
		return fmt.Errorf("get repo metadata expiry: %w", err)
	}
	if !expiry.IsZero() {
		// Make sure we don't mishandle negative timestamps.
		expiryUSec := uint64(max(expiry.UnixMicro(), 0))
		root.ValidBeforeUSec = generics.Ptr(expiryUSec)
	}
	if err := o.wtr.WriteRoot(&root); err != nil {
		return fmt.Errorf("write uapi16 manifest root: %w", err)
	}
	return nil
}

func (o *uapi16ListFormatter) Output(_ context.Context, target *tufclient.TargetInfo) error {
	file, err := uapi16ext.FromTargetFile(target.TargetFiles, &target.Repo.DataRootURL.URL)
	if err != nil {
		return err
	}
	if err := uapi16.ValidateName(file.Name); err != nil {
		return fmt.Errorf("target cannot be represented as uapi.16 manifest entry: %w", err)
	}
	// We must not output any UAPI.16 submanifests as the TUF targets list is
	// the canonical source of all manifest information and someone inserting a
	// submanifest into a repo could cause UAPI.16 consumers to incorrectly
	// trust the manifest (allowing for stuffing attacks).
	basename := path.Base(file.Name) //nolint:forbidigo // purely lexical, never touches the filesystem
	if basename == uapi16.Filename || strings.HasPrefix(basename, uapi16.Filename+".") {
		return fmt.Errorf("target would be interpreted as a uapi.16 sub-manifest (%s) which is invalid when sourced from TUF", basename)
	}
	return o.wtr.WriteFile(file)
}

func (*uapi16ListFormatter) Finish(context.Context) error { return nil }

// getListFormatter returns the [listFormatter] selected by the user's flags,
// with all output written to the given [io.Writer].
func getListFormatter(wtr io.Writer, cmd *cli.Command) listFormatter {
	switch {
	case cmd.Bool("uapi-16"):
		return newUAPI16ListFormatter(wtr)
	case cmd.Bool("verbose"):
		return newVerboseListFormatter(wtr)
	case cmd.IsSet("format"):
		return newFormatListFormatter(wtr, cmd.String("format"))
	default:
		return newPlainListFormatter(wtr)
	}
}

var listCommand = &cli.Command{
	Name:  "list",
	Usage: "get a list of available update files",
	Flags: []cli.Flag{},
	Arguments: []cli.Argument{
		&cli.StringArgs{
			Name:      "repo-name",
			UsageText: "[repo-name]...",
			Min:       0,
			Max:       -1,
		},
	},
	MutuallyExclusiveFlags: []cli.MutuallyExclusiveFlags{
		{
			Flags: [][]cli.Flag{
				{
					&cli.BoolFlag{
						Name:    "verbose",
						Usage:   "output more textual information about each target file",
						Aliases: []string{"v"},
					},
				},
				{
					&cli.StringFlag{
						Name:    "format",
						Usage:   "output formatted text for each target file (%R = repo, %n = target name, %s = size, %h = sha256 hash, %u = download URL)",
						Aliases: []string{"f"},
					},
				},
				{
					&cli.BoolFlag{
						Name:  "uapi-16",
						Usage: "output the list as a UAPI.16 manifest",
					},
				},
			},
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) (Err error) {
		client, err := getClient(ctx, cmd.StringArgs("repo-name")...)
		if err != nil {
			return fmt.Errorf("get tuf-client: %w", err)
		}
		defer funchelpers.VerifyClose(&Err, client)
		// TODO: Do a client.Refresh here?

		out := getListFormatter(os.Stdout, cmd)
		if err := out.Begin(ctx, client); err != nil {
			return err
		}
		for target, err := range client.IterTargetFiles(ctx) {
			if err != nil {
				return err
			}
			if err := out.Output(ctx, target); err != nil {
				return fmt.Errorf("error while formatting target file %s from repo %s: %w", target.Path, target.Repo.Name, err)
			}
		}
		return out.Finish(ctx)
	},
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package main

import (
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/transferlayout"
	"go.amutable.dev/quarry/internal/tufext"
)

// quarryTargetsFlags returns the --quarry-* options of "hardhat targets". They
// add the transfer definition directories of
// internal/transferlayout that quarry-sysupdate reads. hardhat lays them out
// from plain definition files, so producers need not know the layout.
func quarryTargetsFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringSliceFlag{
			Name:  "quarry-transfer-dir",
			Usage: "ship sysupdate definitions for one component, given as <component dir>=<source>. <component dir> is the component's sysupdate definitions directory. It is \"sysupdate.d\" for the default component or \"sysupdate.<component>.d\". <source> is a directory of definitions (*.transfer, *.feature, <component>.component and drop-in directories) or \"" + confextSourcePrefix + "<name>\" for a generated transfer installing the confext DDI <name>_<version>.confext.raw. Repeat the option for the same <component dir> to merge sources. The files are published under " + transferlayout.Prefix + "<component dir>/. For a named component, <component>.component is generated (without Enabled=, so it is an enabled-by-default component) if no source ships it",
		},
	}
}

// quarryTransferDir is one <component dir> of --quarry-transfer-dir with its
// sources.
type quarryTransferDir struct {
	dir     string
	sources []string
}

// quarrySpecFromFlags parses and checks the --quarry-* options.
func quarrySpecFromFlags(cmd *cli.Command) ([]*quarryTransferDir, error) {
	var dirs []*quarryTransferDir
	byDir := map[string]*quarryTransferDir{}
	for _, arg := range cmd.StringSlice("quarry-transfer-dir") {
		dir, source, ok := strings.Cut(arg, "=")
		if !ok || source == "" {
			return nil, fmt.Errorf("--quarry-transfer-dir=%q must be <component dir>=<source>", arg)
		}
		if _, err := transferlayout.ParseComponentDir(dir); err != nil {
			return nil, fmt.Errorf("--quarry-transfer-dir=%q: %w", arg, err)
		}
		entry, ok := byDir[dir]
		if !ok {
			entry = &quarryTransferDir{dir: dir}
			byDir[dir] = entry
			dirs = append(dirs, entry)
		}
		if slices.Contains(entry.sources, source) {
			return nil, fmt.Errorf("--quarry-transfer-dir=%q given twice", arg)
		}
		entry.sources = append(entry.sources, source)
	}
	return dirs, nil
}

// confextSourcePrefix marks a --quarry-transfer-dir source that names a
// confext to generate the definitions for rather than a directory.
const confextSourcePrefix = "confext:"

// hasSpaceOrControl returns whether s would break a definition line.
func hasSpaceOrControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
}

// confextTransfer returns the transfer definition installing the confext DDI
// "<name>_<version>.confext.raw" into the /var/lib/confexts/<name>.raw.v/
// directory, from which systemd picks the newest instance. The source pattern
// matches the image at any depth (**/), so a repository may serve it from a
// subdirectory as well as flat. The source path is a placeholder that
// quarry-sysupdate replaces with its proxy URL when staging. Verify=no is set
// because TUF already authenticated the bytes.
func confextTransfer(name string) []byte {
	return []byte(`[Transfer]
Verify=no

[Source]
Type=url-file
Path=__quarry_will_replace_this__
MatchPattern=**/` + name + `_@v.confext.raw

[Target]
Type=regular-file
Path=/var/lib/confexts/` + name + `.raw.v
PathRelativeTo=root
MatchPattern=` + name + `_@v.raw
Mode=0644
InstancesMax=2
`)
}

// readDefinitionSource adds the definition files of one source directory to
// files, keyed by their path relative to it, or generates them for a confext
// source. A file name that another source already added is an error.
func readDefinitionSource(files map[string][]byte, source string) error {
	add := func(rel string, data []byte) error {
		if _, dup := files[rel]; dup {
			return fmt.Errorf("%s: definition file %s is also in another source", source, rel)
		}
		files[rel] = data
		return nil
	}
	if name, ok := strings.CutPrefix(source, confextSourcePrefix); ok {
		// systemd reads the confext name up to the first "_" of the file name.
		if !transferlayout.ValidPathComponent(name) || strings.Contains(name, "_") || hasSpaceOrControl(name) {
			return fmt.Errorf("invalid confext name %q in %s", name, source)
		}
		return add("50-"+name+".transfer", confextTransfer(name))
	}
	found := false
	err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error { //nolint:forbidigo // user-controlled host path
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(source, path) //nolint:forbidigo // user-controlled host path
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() > maxInlineSize {
			return fmt.Errorf("definition file %s is too large (%d bytes) to be inlined (limit %d bytes)", path, info.Size(), maxInlineSize)
		}
		data, err := os.ReadFile(path) //nolint:forbidigo // user-controlled host path
		if err != nil {
			return err
		}
		found = true
		return add(rel, data)
	})
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%s holds no definition files", source)
	}
	return nil
}

// layoutTransferDir turns the sources of one transfer directory into its
// files. For a named component, these include the generated component file
// if no source ships one.
func layoutTransferDir(entry *quarryTransferDir) (map[string][]byte, error) {
	files := map[string][]byte{}
	for _, source := range entry.sources {
		if err := readDefinitionSource(files, source); err != nil {
			return nil, err
		}
	}
	// quarrySpecFromFlags already checked the directory name.
	component, _ := transferlayout.ParseComponentDir(entry.dir)
	if component == "" {
		return files, nil
	}
	componentFile := component + ".component"
	if _, shipped := files[componentFile]; !shipped {
		files[componentFile] = transferlayout.ComponentFile(component)
	}
	return files, nil
}

// addQuarryTargets adds what the --quarry-* options ask for to the targets.
func addQuarryTargets(builder *tufext.TargetsBuilder, dirs []*quarryTransferDir) error {
	for _, entry := range dirs {
		files, err := layoutTransferDir(entry)
		if err != nil {
			return err
		}
		for _, rel := range slices.Sorted(maps.Keys(files)) {
			path, err := transferlayout.TargetPath(entry.dir, rel)
			if err != nil {
				return fmt.Errorf("%s: %s: %w", entry.dir, rel, err)
			}
			if err := rejectExisting(builder, path); err != nil {
				return err
			}
			if _, err := addInlineBytes(builder, path, files[rel]); err != nil {
				return err
			}
		}
	}
	return nil
}

// rejectExisting returns an error if the targets already hold path. The
// builder would otherwise silently replace the entry (a generated entry
// colliding with a hashed or merged one).
func rejectExisting(builder *tufext.TargetsBuilder, path string) error {
	if _, dup := builder.TargetsType().Targets[path]; dup {
		return fmt.Errorf("target %s is given twice", path)
	}
	return nil
}

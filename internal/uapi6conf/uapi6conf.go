// Copyright (C) 2026 Amutable GmbH

// Package uapi6conf implements the configuration file lookup rules from the
// UAPI Group Configuration Files Specification (UAPI.6): a main configuration
// file that may live in one of several prefixes, plus drop-in fragments in
// "<name>.d/" subdirectories that are applied on top of it.
//
// The lookup opens the files it selects, so that the file that was found is
// the file that gets read. Parsing and merging them is left to the caller, as
// quarry's configuration files are TOML rather than the systemd-style INI
// format that UAPI.6 assumes.
package uapi6conf

import (
	"cmp"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"go.amutable.dev/quarry/internal/third_party/funchelpers"
)

var standardPrefixes = []string{
	"/usr/lib",
	"/usr/local/lib",
	"/run",
	"/etc",
}

// SearchPaths is a set of configuration directories, ordered by increasing
// priority (i.e. the last directory wins).
type SearchPaths []string

// Files are opened configuration files, in the order they need to be applied.
// The caller takes ownership of them and has to close them.
type Files []*os.File

var _ io.Closer = (*Files)(nil)

// Close closes all of the files.
//
// The receiver is a pointer so that a close deferred while the slice is still
// being filled sees every file: deferring on a Files value would capture the
// slice header as it was at that point, and silently leak the rest.
func (f *Files) Close() error {
	errs := make([]error, 0, len(*f))
	for _, file := range *f {
		errs = append(errs, file.Close())
	}
	return errors.Join(errs...)
}

// Standard returns the UAPI.6 search paths for project, the per-prefix
// subdirectory holding its configuration, below root ("" for the host root).
func Standard(root, project string) SearchPaths {
	paths := make(SearchPaths, 0, len(standardPrefixes))
	for _, prefix := range standardPrefixes {
		paths = append(paths, filepath.Join(root, prefix, project)) //nolint:forbidigo // host-controlled path
	}
	return paths
}

// Resolve opens the main configuration file called name, if there is one,
// followed by its drop-ins, in the order they need to be applied.
func (s SearchPaths) Resolve(name string) (_ Files, Err error) {
	main, err := s.mainFile(name)
	if err != nil {
		return nil, err
	}

	var files Files
	if main != nil {
		files = append(files, main)
	}
	// The caller only takes ownership on success.
	defer funchelpers.CloseOnError(&Err, &files)

	dropIns, err := s.dropIns(name)
	if err != nil {
		return nil, err
	}
	return append(files, dropIns...), nil
}

// mainFile opens name from the highest-priority search path that has it, or
// returns nil if no search path has one.
func (s SearchPaths) mainFile(name string) (*os.File, error) {
	for _, dir := range slices.Backward(s) {
		file, err := os.Open(filepath.Join(dir, name)) //nolint:forbidigo // host-controlled path
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return file, nil
	}
	return nil, nil //nolint:nilnil // a missing mainFile is not an error, data may come via a dropIn
}

type dropIn struct {
	name string
	prio int // index in the search paths
	file *os.File
}

// dropIns opens the drop-ins for name, the files in "<name>.d/" with the same
// extension as name, in the order they need to be applied.
//
// That order depends on the file name alone, so the prefix a drop-in comes from
// decides only whether a same-named one in a higher-priority prefix masks it.
// An empty file (or a symlink to /dev/null) is therefore enough to disable a
// drop-in shipped elsewhere.
func (s SearchPaths) dropIns(name string) (_ Files, Err error) {
	ext := filepath.Ext(name)

	var (
		found  []dropIn
		opened Files
	)
	// The caller only takes ownership on success. Close tolerates the masked
	// files below being closed twice.
	defer funchelpers.CloseOnError(&Err, &opened)

	for prio, dir := range s {
		dropInDir := filepath.Join(dir, name+".d") //nolint:forbidigo // host-controlled directory
		entries, err := os.ReadDir(dropInDir)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ext {
				continue
			}
			path := filepath.Join(dropInDir, entry.Name()) //nolint:forbidigo // host-controlled path
			file, err := os.Open(path)                     //nolint:forbidigo // host-controlled path
			if err != nil {
				return nil, err
			}
			opened = append(opened, file)
			found = append(found, dropIn{name: entry.Name(), prio: prio, file: file})
		}
	}

	// Highest priority first per name, so the masked ones are dropped below.
	slices.SortFunc(found, func(a, b dropIn) int {
		return cmp.Or(cmp.Compare(a.name, b.name), cmp.Compare(b.prio, a.prio))
	})

	files := make(Files, 0, len(found))
	for i, d := range found {
		if i > 0 && found[i-1].name == d.name {
			if err := d.file.Close(); err != nil {
				return nil, err
			}
			continue
		}
		files = append(files, d.file)
	}
	return files, nil
}

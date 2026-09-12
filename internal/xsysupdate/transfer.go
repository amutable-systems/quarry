// Copyright (C) 2026 Amutable GmbH

package xsysupdate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"cyphar.com/go-pathrs"
	"golang.org/x/sys/unix"
	"gopkg.in/ini.v1"

	"go.amutable.dev/quarry/internal/hostnamed"
	"go.amutable.dev/quarry/internal/pathrsext"
	"go.amutable.dev/quarry/internal/third_party/funchelpers"
	"go.amutable.dev/quarry/internal/transferlayout"
	"go.amutable.dev/quarry/internal/tufclient"
	"go.amutable.dev/quarry/internal/uapi10"
)

const (
	// TransferFilePrefix is the prefix of the "versioned transfer directory"
	// extension to sysupdate. A repository ships the sysupdate.d definitions
	// of one version of a sysupdate component as the target files
	//
	//	.zzz-quarry-special/sysupdate.d=<version>/<file>              (default component)
	//	.zzz-quarry-special/sysupdate.<component>.d=<version>/<file>  (component)
	//
	// where <file> is a *.transfer, *.feature or <component>.component
	// definition or the [transferlayout.AttrFileName] attribute file. Nothing
	// is installed from these directly. Instead, quarry-sysupdate picks one
	// version per component (see cmd/quarry-sysupdate), and
	// [TransferFileExtension.Stage] lays that version out for a single
	// systemd-sysupdate run.
	TransferFilePrefix = transferlayout.TransferPrefix

	// maxAttrFileSize bounds how much of an ATTR file is read.
	maxAttrFileSize = 64 << 10 // 64 KiB
	// maxDefinitionFileSize bounds how much of a definition file is read.
	maxDefinitionFileSize = 1 << 20 // 1 MiB

	// bindMountDir is where the staged definitions are bind-mounted for
	// systemd-sysupdate. It is /run rather than /etc because systemd creates
	// missing mount points on the host filesystem (the service only has a
	// private mount table), and on /run (a tmpfs in sysupdate's search path)
	// these empty placeholders do not persist.
	bindMountDir = "/run"
)

// hostDefinitionsDir is the highest-precedence sysupdate search directory on
// the host. Definitions there take precedence over our bind mounts, so we warn
// about them. This is a variable so that tests can override it.
var hostDefinitionsDir = "/etc"

// TransferDir is one version of one sysupdate component as shipped by a
// repository (see [TransferFilePrefix]).
type TransferDir struct {
	// Component is the sysupdate component name ("" for the default
	// component).
	Component string
	// Version is the component version the directory describes and the
	// version the component is updated to with it.
	Version string
	// Attr is the parsed [transferlayout.AttrFileName] file. It is valid
	// once the directory is returned by [TransferFileExtension.Transfers].
	Attr transferlayout.Attr

	// files are the definition files (relative to the directory, excluding
	// ATTR) and the targets providing them.
	files map[string]*tufclient.TargetInfo
	// path is the target path of the directory, for log messages.
	path string
	// hasAttr records that an ATTR was collected (the first one seen wins).
	hasAttr bool
	// invalid records why the directory is unusable, if it is.
	invalid error
}

// SteppingStone returns whether the version must be installed (and
// activated) before updating past it.
func (dir *TransferDir) SteppingStone() bool {
	return dir.Attr.Validity == transferlayout.ValiditySteppingStone
}

// Files returns the sorted list of definition files in the directory.
func (dir *TransferDir) Files() []string {
	return slices.Sorted(maps.Keys(dir.files))
}

// String returns the target path of the directory.
func (dir *TransferDir) String() string { return dir.path }

// finalize validates the collected metadata. It returns an error if the
// directory cannot be used.
func (dir *TransferDir) finalize() error {
	if dir.invalid != nil {
		return dir.invalid
	}
	if len(dir.files) == 0 {
		return errors.New("no definition files")
	}
	if dir.Version == "" { // TODO(transition)
		if dir.SteppingStone() {
			return errors.New("an unversioned directory cannot be a stepping stone")
		}
		// TODO(transition): Require an ATTR of unversioned directories too
		// (they ship none today). Until then they count as pre-enabled.
		dir.Attr.PreEnabled = true
	}
	return dir.Attr.Validate()
}

// componentFileName returns the name of the component definition file of a
// non-default component ("sysupdate.<component>.component").
func componentFileName(component string) string {
	return "sysupdate." + component + ".component"
}

// ParseTransferPath parses a target path of the versioned transfer directory
// extension into the component ("" for the default component), the version
// and the file path relative to the directory. ok is false if the target is
// not part of this extension at all. err is non-nil if it is part of it but is
// malformed.
//
// The directory is named "sysupdate[.<component>].d=<version>". "@" and "="
// in the suffix are rejected because they are reserved for a later qualifier.
//
// A directory without "=<version>" is the unversioned layout of the
// transition period. Its version is "", and it is only used while the
// component has no versioned directory (see [TransferFileExtension.Transfers]).
//
// TODO(transition): Reject unversioned directories again once no repository
// ships them (also drop the "" handling in finalize, Transfers and
// quarry-sysupdate's stageComponent/updateStaged).
func ParseTransferPath(path string) (component, version, file string, ok bool, err error) {
	if !strings.HasPrefix(path, TransferFilePrefix) {
		return "", "", "", false, nil
	}
	// Only handle the sysupdate directories (and misspellings of their suffix,
	// which are rejected below rather than ignored). Another extension named
	// sysupdate-* is not ours to claim.
	if after := strings.TrimPrefix(path, TransferFilePrefix); after == "" || !strings.ContainsRune(".=@/", rune(after[0])) {
		return "", "", "", false, nil
	}
	rest := strings.TrimPrefix(path, ExtensionTargetPrefix)
	dirName, file, found := strings.Cut(rest, "/")
	if !found || file == "" {
		return "", "", "", true, fmt.Errorf("transfer target %s has no file component", path)
	}
	for part := range strings.SplitSeq(file, "/") {
		if !transferlayout.ValidPathComponent(part) {
			return "", "", "", true, fmt.Errorf("transfer target %s has an invalid file path %q", path, file)
		}
	}
	name, suffix, found := strings.Cut(dirName, "=")
	if found {
		if _, err := transferlayout.DirSuffix(suffix); err != nil {
			return "", "", "", true, fmt.Errorf("transfer target %s: %w", path, err)
		}
		version = suffix
	} else if strings.Contains(dirName, "@") {
		return "", "", "", true, fmt.Errorf("transfer target %s has an invalid directory name %q", path, dirName)
	}
	component, err = transferlayout.ParseComponentDir(name)
	if err != nil {
		return "", "", "", true, fmt.Errorf("transfer target %s: %w", path, err)
	}
	return component, version, file, true, nil
}

// dirKey identifies a transfer directory in [TransferFileExtension].
type dirKey struct{ component, version string }

// TransferFileExtension is an [Extension] that implements auto-installation of
// target files from Quarry repositories.
// It only collects the versioned transfer directories (see
// [TransferFilePrefix]). quarry-sysupdate picks the version of each component
// from [TransferFileExtension.Transfers] and stages it for systemd-sysupdate
// with [TransferFileExtension.Stage].
type TransferFileExtension struct {
	// OverrideSourcePathURL (if non-nil) is a URL which replaces all [Source]
	// Path entries in transfer files when persisting them to disk. This is
	// intended to be the URL to the "quarry-client http" server that proxies
	// sysupdate requests.
	OverrideSourcePathURL *string

	// storeDir is the storage for the staged transfer files.
	storeDir *pathrs.Root

	// dirs are the collected transfer directories.
	dirs map[dirKey]*TransferDir
}

var _ Extension = &TransferFileExtension{}

// Name returns the name of this extension.
func (ext *TransferFileExtension) Name() string { return "transfers" }

// Init constructs the storage area for the auto-enabled transfer files.
// Staging directories left behind by earlier runs (they are kept on failure,
// for debugging) are removed.
func (ext *TransferFileExtension) Init(ctx context.Context) (context.Context, error) {
	ctx, err := makeExtStoreDir(ctx, ext)
	if err != nil {
		return nil, fmt.Errorf("make %s extension store: %w", ext.Name(), err)
	}
	ext.storeDir = ctxExtStoreDir(ctx, ext)
	// storeDir will be closed by Abort on error.

	if err := ext.pruneStore(); err != nil {
		return nil, fmt.Errorf("prune old staging directories: %w", err)
	}

	ext.dirs = map[dirKey]*TransferDir{}
	return ctx, nil
}

// pruneStore removes everything in the store directory. Staged definitions
// are only needed while their update runs, so anything present at the start
// of a run is a leftover from a failed (or interrupted) one.
func (ext *TransferFileExtension) pruneStore() (Err error) {
	dir, err := ext.storeDir.OpenFile(".", unix.O_DIRECTORY)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer funchelpers.VerifyClose(&Err, dir)

	entries, err := dir.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("list store: %w", err)
	}
	for _, entry := range entries {
		slog.Info("[xsysupdate transfers] Removing staging directory.",
			"name", entry.Name())
		if err := ext.storeDir.RemoveAll(entry.Name()); err != nil {
			return fmt.Errorf("remove staging directory %s: %w", entry.Name(), err)
		}
	}
	return nil
}

// dir returns the (possibly new) transfer directory record for the given
// component version, whose target path is path.
func (ext *TransferFileExtension) dir(component, version, path string) *TransferDir {
	key := dirKey{component: component, version: version}
	dir, ok := ext.dirs[key]
	if !ok {
		dir = &TransferDir{
			Component: component,
			Version:   version,
			files:     map[string]*tufclient.TargetInfo{},
			path:      path,
		}
		ext.dirs[key] = dir
	}
	return dir
}

// readTarget fetches and verifies a (small) target file.
func readTarget(ctx context.Context, info *tufclient.TargetInfo, maxSize int64) (_ []byte, Err error) {
	file, err := info.Fetch(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch target %s: %w", info.Path, err)
	}
	defer funchelpers.VerifyClose(&Err, file)

	data, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read target %s: %w", info.Path, err)
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("target %s is too large (limit %d)", info.Path, maxSize)
	}
	// The stream is hash-verified on Close, so this must succeed before the
	// data is used for anything.
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("verify target %s: %w", info.Path, err)
	}
	return data, nil
}

// ApplyTarget collects the target into its versioned transfer directory. A
// malformed target (or ATTR file) makes its version unusable but does not
// abort the update, so that one bad entry cannot block the updates of other
// versions or components.
func (ext *TransferFileExtension) ApplyTarget(ctx context.Context, info *tufclient.TargetInfo) (bool, error) {
	component, version, file, ok, err := ParseTransferPath(info.Path)
	if !ok {
		return false, nil // not for this extension
	}
	if err != nil {
		slog.Warn("[xsysupdate transfers target] Ignoring invalid transfer target.",
			"target", info.Path, "repository", info.Repo.Name, "err", err.Error())
		return true, nil
	}
	dir := ext.dir(component, version, strings.TrimSuffix(info.Path, "/"+file))

	if file == transferlayout.AttrFileName {
		// As for definition files, the first ATTR seen wins.
		if dir.hasAttr {
			slog.Info("[xsysupdate transfers target] Ignoring duplicate ATTR file.",
				"target", info.Path, "repository", info.Repo.Name)
			return true, nil
		}
		dir.hasAttr = true
		if info.Length > maxAttrFileSize {
			slog.Warn("[xsysupdate transfers target] Ignoring transfer directory with oversized ATTR file.",
				"target", info.Path, "repository", info.Repo.Name, "length", info.Length)
			dir.invalid = fmt.Errorf("%s is too large (%d bytes)", transferlayout.AttrFileName, info.Length)
			return true, nil
		}
		// Unlike a malformed file, a fetch failure is not the repository's
		// doing (ATTR is inline data in practice), so it aborts the update.
		data, err := readTarget(ctx, info, maxAttrFileSize)
		if err != nil {
			return false, fmt.Errorf("read %s of %s: %w", transferlayout.AttrFileName, dir, err)
		}
		var attr transferlayout.Attr
		if err := json.Unmarshal(data, &attr); err != nil {
			slog.Warn("[xsysupdate transfers target] Ignoring transfer directory with invalid ATTR file.",
				"target", info.Path, "repository", info.Repo.Name, "err", err.Error())
			dir.invalid = fmt.Errorf("invalid %s: %w", transferlayout.AttrFileName, err)
			return true, nil
		}
		dir.Attr = attr
		return true, nil
	}

	// For equal paths (e.g. from two repositories) the first one seen wins.
	if _, seen := dir.files[file]; seen {
		slog.Info("[xsysupdate transfers target] Ignoring duplicate transfer definition.",
			"target", info.Path, "repository", info.Repo.Name)
		return true, nil
	}
	slog.Info("[xsysupdate transfers target] Collected transfer definition.",
		"target", info.Path, "repository", info.Repo.Name, "component", transferlayout.ComponentDir(component), "version", version)
	dir.files[file] = info
	return true, nil
}

// Transfers returns the usable transfer directories, keyed by component and
// sorted by version (oldest first). Unusable directories are logged and
// skipped, and so is a component's unversioned directory once it has a
// versioned one.
func (ext *TransferFileExtension) Transfers() map[string][]*TransferDir {
	transfers := map[string][]*TransferDir{}
	unversioned := map[string]*TransferDir{}
	for _, dir := range ext.dirs {
		if err := dir.finalize(); err != nil {
			slog.Warn("[xsysupdate transfers] Ignoring unusable transfer directory.",
				"directory", dir.path, "err", err.Error())
			continue
		}
		if dir.Version == "" { // TODO(transition)
			unversioned[dir.Component] = dir
			continue
		}
		transfers[dir.Component] = append(transfers[dir.Component], dir)
	}
	for _, candidates := range transfers {
		slices.SortFunc(candidates, func(a, b *TransferDir) int {
			return uapi10.Compare(a.Version, b.Version)
		})
	}
	for component, dir := range unversioned {
		if _, ok := transfers[component]; ok {
			slog.Warn("[xsysupdate transfers] Ignoring unversioned transfer directory, the component has versioned ones.",
				"directory", dir.path)
			continue
		}
		transfers[component] = []*TransferDir{dir}
	}
	return transfers
}

// hostDefinitions returns the sysupdate definitions present in
// [hostDefinitionsDir], which take precedence over the staged ones.
func hostDefinitions() ([]string, error) {
	var found []string
	for _, pattern := range []string{"sysupdate.d/*", "sysupdate.*.d", "sysupdate.*.component"} {
		pattern = filepath.Join(hostDefinitionsDir, pattern) //nolint:forbidigo // host-controlled directory
		matches, err := filepath.Glob(pattern)               //nolint:forbidigo // host-controlled directory
		if err != nil {
			return nil, fmt.Errorf("could not glob %q pattern: %w", pattern, err)
		}
		found = append(found, matches...)
	}
	slices.Sort(found)
	return found, nil
}

// BeforeUpdate warns about sysupdate definitions on the host that would
// take precedence over the staged ones.
func (ext *TransferFileExtension) BeforeUpdate(_ context.Context) error {
	found, err := hostDefinitions()
	if err != nil {
		return err
	}
	if len(found) > 0 {
		slog.Warn("[xsysupdate transfers before-update] Host has sysupdate definitions that take precedence over the repository ones.",
			"definitions", found)
	}
	return nil
}

// Abort resets the transfer file state to before the update was started.
// Init left the store empty, so everything in it was staged by this run.
func (ext *TransferFileExtension) Abort(_ context.Context, srcErr error) error {
	var errs []error
	if ext.storeDir != nil {
		slog.Info("[xsysupdate transfers abort] Removing staged transfer definitions.",
			"err", srcErr.Error())
		if err := ext.pruneStore(); err != nil {
			errs = append(errs, fmt.Errorf("remove staged transfer definitions: %w", err))
		}
	}
	if err := ext.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close transfer extension resources: %w", err))
	}
	// Clear the internal state so a double-abort doesn't do any thing dumb.
	*ext = TransferFileExtension{
		OverrideSourcePathURL: ext.OverrideSourcePathURL,
	}
	return errors.Join(errs...)
}

// Close clears any resources used by the extension. Staged definitions that
// were not removed are left in place until the next Init.
func (ext *TransferFileExtension) Close() error {
	var err error
	if ext.storeDir != nil {
		if err = ext.storeDir.Close(); errors.Is(err, fs.ErrClosed) {
			err = nil
		}
		ext.storeDir = nil
	}
	ext.dirs = nil
	return err
}

func init() {
	// Write "Key=Value" like the definitions we are given (and systemd
	// itself), not the library's default "Key = Value". These are package
	// globals of the ini library. Nothing else in quarry writes ini files.
	ini.PrettyFormat = false
	ini.PrettyEqual = false
}

// loadINI parses a systemd-style definition file. Repeated keys are kept
// verbatim (sysupdate allows e.g. multiple MatchPattern= lines) and "#" and
// ";" only start a comment at the start of a line.
func loadINI(source any) (*ini.File, error) {
	return ini.LoadSources(ini.LoadOptions{
		AllowShadows:               true,
		AllowDuplicateShadowValues: true,
		IgnoreInlineComment:        true,
	}, source)
}

// setKey sets the key to exactly one value, dropping any repeated (shadow)
// assignments, as systemd would only honour the last one anyway.
func setKey(section *ini.Section, name, value string) {
	section.DeleteKey(name)
	section.Key(name).SetValue(value)
}

// rewriteINI parses a definition file (see [loadINI]), applies edit to it and
// serialises the result.
func rewriteINI(data []byte, edit func(*ini.File)) ([]byte, error) {
	file, err := loadINI(data)
	if err != nil {
		return nil, fmt.Errorf("load ini: %w", err)
	}
	edit(file)
	var out bytes.Buffer
	if _, err := file.WriteTo(&out); err != nil {
		return nil, fmt.Errorf("serialise ini: %w", err)
	}
	return out.Bytes(), nil
}

// StageOptions are the options for [TransferFileExtension.Stage].
type StageOptions struct {
	// MachineTags are the machine tags currently set on the host, which
	// decide the enablement of features (see [TransferFileExtension.Stage]).
	MachineTags []string
}

// StagedTransfers are the definitions of one component version laid out for
// a systemd-sysupdate run, see [TransferFileExtension.Stage].
type StagedTransfers struct {
	// Component is the staged component.
	Component string
	// Version is the staged version.
	Version string
	// EnabledFeatures are the features the staging enabled.
	EnabledFeatures []string

	// root is the staging directory of the component.
	root *pathrs.Root
	// removeFn removes the staging directory.
	removeFn func() error
}

// Path returns the absolute path of the staging directory.
func (staged *StagedTransfers) Path() string {
	return staged.root.IntoFile().Name()
}

// BindPaths returns the "<source>:<destination>" bind mounts that make
// systemd-sysupdate see the staged definitions (as BindReadOnlyPaths=
// values), which are the definitions directory of the component and, for
// non-default components, its component file.
func (staged *StagedTransfers) BindPaths() []string {
	names := []string{transferlayout.ComponentDir(staged.Component)}
	if staged.Component != "" {
		names = append(names, componentFileName(staged.Component))
	}
	path := staged.Path()
	binds := make([]string, 0, len(names))
	for _, name := range names {
		binds = append(binds, path+"/"+name+":"+bindMountDir+"/"+name)
	}
	return binds
}

// Close releases the staging directory handle but leaves the directory in
// place for debugging a failed run. It is removed at the start of the next
// run.
func (staged *StagedTransfers) Close() error {
	if staged.root == nil {
		return nil
	}
	err := staged.root.Close()
	staged.root = nil
	if err != nil && !errors.Is(err, fs.ErrClosed) {
		return err
	}
	return nil
}

// Remove deletes the staging directory.
func (staged *StagedTransfers) Remove() error {
	return errors.Join(staged.Close(), staged.removeFn())
}

// Stage lays the definitions of the given component version out for a
// systemd-sysupdate run, in a staging directory of its own:
//
//	<store>/sysupdate.d/sysupdate.d/*                                   (default component)
//	<store>/sysupdate.<component>.d/sysupdate.<component>.d/*           (component)
//	<store>/sysupdate.<component>.d/sysupdate.<component>.component
//
// Transfer files get their [Source] Path= replaced by OverrideSourcePathURL.
// A feature gets [Feature] Enabled=true iff ATTR "features" lists it and the
// machine tag it names there is set. Otherwise it keeps the enablement it
// ships. The component file (generated if the directory ships none) gets
// [Component] Enabled=true unless the component is pre-enabled. The build's
// version bounds are kept as they are. The caller removes the staging
// directory once the run succeeded (or closes it to keep it for debugging).
func (ext *TransferFileExtension) Stage(ctx context.Context, dir *TransferDir, opts StageOptions) (_ *StagedTransfers, Err error) {
	if ext.storeDir == nil {
		return nil, errors.New("transfer extension is not initialised")
	}
	subdir := transferlayout.ComponentDir(dir.Component)
	if err := ext.storeDir.RemoveAll(subdir); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("remove old staging dir %s: %w", subdir, err)
	}
	handle, err := ext.storeDir.MkdirAll(subdir, 0o755)
	if err != nil {
		return nil, fmt.Errorf("create staging dir %s: %w", subdir, err)
	}
	defer funchelpers.VerifyClose(&Err, handle)
	root, err := pathrs.RootFromFile(handle.IntoFile())
	if err != nil {
		return nil, fmt.Errorf("convert staging dir %s to root: %w", subdir, err)
	}
	staged := &StagedTransfers{
		Component: dir.Component,
		Version:   dir.Version,
		root:      root,
		removeFn: func() error {
			if err := ext.storeDir.RemoveAll(subdir); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("remove staging dir %s: %w", subdir, err)
			}
			return nil
		},
	}
	defer func() {
		if Err != nil {
			Err = errors.Join(Err, staged.Remove())
		}
	}()

	slog.Info("[xsysupdate transfers stage] Staging transfer definitions.",
		"directory", dir.path, "version", dir.Version, "path", staged.Path())

	componentBase := []byte{} // The component file is generated if none is shipped.
	for _, file := range dir.Files() {
		info := dir.files[file]
		data, err := readTarget(ctx, info, maxDefinitionFileSize)
		if err != nil {
			return nil, err
		}
		switch {
		case dir.Component != "" && file == dir.Component+".component":
			// Shipped as a sibling of the definitions directory below.
			componentBase = data
			continue
		case strings.HasSuffix(file, ".transfer"):
			data, err = rewriteINI(data, func(transfer *ini.File) {
				if overrideURL := ext.OverrideSourcePathURL; overrideURL != nil {
					// This allocates a new Source section and Path value if missing.
					setKey(transfer.Section("Source"), "Path", *overrideURL)
				}
			})
		case strings.HasSuffix(file, ".feature"):
			name := strings.TrimSuffix(file, ".feature")
			feature, listed := dir.Attr.Features[name]
			enabled := listed && slices.ContainsFunc(opts.MachineTags, func(tag string) bool {
				return hostnamed.TagKey(tag) == feature.Tag
			})
			data, err = rewriteINI(data, func(def *ini.File) {
				if enabled {
					setKey(def.Section("Feature"), "Enabled", "true")
				}
			})
			if enabled {
				staged.EnabledFeatures = append(staged.EnabledFeatures, name)
			}
			slog.Info("[xsysupdate transfers stage] Decided feature enablement.",
				"feature", file, "enabled", enabled)
		}
		if err != nil {
			return nil, fmt.Errorf("patch %s: %w", info.Path, err)
		}
		if err := pathrsext.WriteFile(root, subdir+"/"+file, data); err != nil {
			return nil, fmt.Errorf("stage %s: %w", info.Path, err)
		}
	}
	if dir.Component != "" {
		data, err := rewriteINI(componentBase, func(component *ini.File) {
			if !dir.Attr.PreEnabled {
				setKey(component.Section("Component"), "Enabled", "true")
			}
		})
		if err != nil {
			return nil, fmt.Errorf("patch component file of %s: %w", dir.path, err)
		}
		if err := pathrsext.WriteFile(root, componentFileName(dir.Component), data); err != nil {
			return nil, fmt.Errorf("stage component file of %s: %w", dir.path, err)
		}
	}
	return staged, nil
}

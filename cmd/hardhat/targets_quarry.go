// Copyright (C) 2026 Amutable GmbH

package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/jsonutils"
	"go.amutable.dev/quarry/internal/transferlayout"
	"go.amutable.dev/quarry/internal/tufext"
)

// quarryTargetsFlags returns the --quarry-* options of "hardhat targets" (and
// --custom-version). They add the targets of internal/transferlayout that
// quarry-sysupdate reads. These are versioned transfer directories with their
// ATTR and machine tag entries. hardhat lays them out from plain definition
// files and options, so producers need not know the layout.
func quarryTargetsFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringSliceFlag{
			Name:  "quarry-transfer-dir",
			Usage: "ship sysupdate definitions for one component, given as <component dir>=<source>. <component dir> is the component's sysupdate definitions directory. It is \"sysupdate.d\" for the default component or \"sysupdate.<component>.d\", and it names the component in the other --quarry-transfer-* options. <source> is a directory of definitions (*.transfer, *.feature, <component>.component and drop-in directories) or \"" + confextSourcePrefix + "<name>\" for a generated transfer installing the confext DDI <name>_<version>.confext.raw. Repeat the option for the same <component dir> to merge sources. The files are published under " + transferlayout.Prefix + "<component dir>=<version>/. Every transfer and component file is bounded to the version with MinVersion=/MaxVersion=, and <component>.component is generated if no source ships it",
		},
		&cli.StringFlag{
			Name:  "quarry-transfer-version",
			Usage: "the component version the --quarry-transfer-dir definitions are for (required with --quarry-transfer-dir)",
		},
		&cli.StringSliceFlag{
			Name:  "quarry-transfer-pre-enabled",
			Usage: "mark the <component dir> component as pre-enabled so that it is updated on every machine (ATTR \"pre-enabled\"). Each component needs this or --quarry-transfer-tag",
		},
		&cli.StringSliceFlag{
			Name:  "quarry-transfer-tag",
			Usage: "set the machine tag gating the component as <component dir>=<machine tag> (ATTR \"tag\"). The machine tag is a key without value. For a pre-enabled component it only names the <machine tag>.version=<version> pin",
		},
		&cli.StringSliceFlag{
			Name:  "quarry-transfer-feature",
			Usage: "set the machine tag enabling the component's <feature>.feature definition as <component dir>=<feature>=<machine tag> (ATTR \"features\")",
		},
		&cli.StringSliceFlag{
			Name:  "quarry-transfer-stepping-stone",
			Usage: "mark this version of the <component dir> component as a stepping stone that every machine has to install before updating past it (ATTR \"validity\")",
		},
		&cli.StringSliceFlag{
			Name:  "quarry-machine-tag",
			Usage: "add the machine tag entry <name>[=<value>] (" + transferlayout.TagsPrefix + "<name>) that quarry-sysupdate applies",
		},
		&cli.StringFlag{
			Name:  "custom-version",
			Usage: "set custom.quarry.version on every target outside " + transferlayout.Prefix + " (the --quarry-transfer-dir files carry --quarry-transfer-version)",
		},
	}
}

// quarryTransferDir is one <component dir> of --quarry-transfer-dir. It holds
// the sources and the ATTR that the --quarry-transfer-* options build.
type quarryTransferDir struct {
	dir     string
	sources []string
	attr    transferlayout.Attr
}

// quarrySpec is what the --quarry-* options ask for.
type quarrySpec struct {
	version     string
	dirs        []*quarryTransferDir
	machineTags []string
}

// quarrySpecFromFlags parses and checks the --quarry-* options.
func quarrySpecFromFlags(cmd *cli.Command) (*quarrySpec, error) {
	spec := &quarrySpec{
		version:     cmd.String("quarry-transfer-version"),
		machineTags: cmd.StringSlice("quarry-machine-tag"),
	}
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
			spec.dirs = append(spec.dirs, entry)
		}
		if slices.Contains(entry.sources, source) {
			return nil, fmt.Errorf("--quarry-transfer-dir=%q given twice", arg)
		}
		entry.sources = append(entry.sources, source)
	}
	if (len(spec.dirs) > 0) != (spec.version != "") {
		return nil, fmt.Errorf("--quarry-transfer-dir and --quarry-transfer-version need each other")
	}
	if spec.version != "" {
		// The version also goes into the MinVersion=/MaxVersion= lines.
		if _, err := transferlayout.DirSuffix(spec.version); err != nil || hasSpaceOrControl(spec.version) {
			return nil, fmt.Errorf("invalid --quarry-transfer-version=%q", spec.version)
		}
	}
	lookup := func(flag, dir string) (*quarryTransferDir, error) {
		entry, ok := byDir[dir]
		if !ok {
			return nil, fmt.Errorf("--%s: %q is no <component dir> of a --quarry-transfer-dir", flag, dir)
		}
		return entry, nil
	}
	for _, arg := range cmd.StringSlice("quarry-transfer-tag") {
		dir, tag, ok := strings.Cut(arg, "=")
		if !ok || !transferlayout.ValidTagName(tag) {
			return nil, fmt.Errorf("--quarry-transfer-tag=%q must be <component dir>=<machine tag>", arg)
		}
		entry, err := lookup("quarry-transfer-tag", dir)
		if err != nil {
			return nil, err
		}
		if entry.attr.Tag != "" {
			return nil, fmt.Errorf("--quarry-transfer-tag=%q: %s already has a tag", arg, dir)
		}
		entry.attr.Tag = tag
	}
	for _, arg := range cmd.StringSlice("quarry-transfer-feature") {
		parts := strings.SplitN(arg, "=", 3)
		if len(parts) != 3 || !transferlayout.ValidPathComponent(parts[1]) || !transferlayout.ValidTagName(parts[2]) {
			return nil, fmt.Errorf("--quarry-transfer-feature=%q must be <component dir>=<feature>=<machine tag>", arg)
		}
		entry, err := lookup("quarry-transfer-feature", parts[0])
		if err != nil {
			return nil, err
		}
		if entry.attr.Features == nil {
			entry.attr.Features = map[string]transferlayout.FeatureAttr{}
		}
		if _, dup := entry.attr.Features[parts[1]]; dup {
			return nil, fmt.Errorf("--quarry-transfer-feature=%q: feature given twice", arg)
		}
		entry.attr.Features[parts[1]] = transferlayout.FeatureAttr{Tag: parts[2]}
	}
	for _, dir := range cmd.StringSlice("quarry-transfer-pre-enabled") {
		entry, err := lookup("quarry-transfer-pre-enabled", dir)
		if err != nil {
			return nil, err
		}
		entry.attr.PreEnabled = true
	}
	for _, dir := range cmd.StringSlice("quarry-transfer-stepping-stone") {
		entry, err := lookup("quarry-transfer-stepping-stone", dir)
		if err != nil {
			return nil, err
		}
		entry.attr.Validity = transferlayout.ValiditySteppingStone
	}
	for _, entry := range spec.dirs {
		if err := entry.attr.Validate(); err != nil {
			return nil, fmt.Errorf("--quarry-transfer-dir %s: %w", entry.dir, err)
		}
	}
	for _, tag := range spec.machineTags {
		name, _, _ := strings.Cut(tag, "=")
		if _, err := transferlayout.MachineTagPath(name); err != nil {
			return nil, fmt.Errorf("--quarry-machine-tag=%q: %w", tag, err)
		}
	}
	return spec, nil
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
		if !transferlayout.ValidPathComponent(name) || strings.ContainsAny(name, "_@=") || hasSpaceOrControl(name) {
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
		if rel == transferlayout.AttrFileName {
			return fmt.Errorf("%s ships an %s file; the ATTR comes from the --quarry-transfer-* options", source, rel)
		}
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

// layoutTransferDir turns the sources of one transfer directory into the
// files of its versioned directory. These are the bounded definitions, the
// generated component file and the ATTR.
func layoutTransferDir(entry *quarryTransferDir, version string) (map[string][]byte, error) {
	files := map[string][]byte{}
	for _, source := range entry.sources {
		if err := readDefinitionSource(files, source); err != nil {
			return nil, err
		}
	}
	// quarrySpecFromFlags already checked the directory name.
	component, _ := transferlayout.ParseComponentDir(entry.dir)
	for feature := range entry.attr.Features {
		if _, ok := files[feature+".feature"]; !ok {
			return nil, fmt.Errorf("%s names feature %q but its sources hold no %s.feature", entry.dir, feature, feature)
		}
	}
	if component != "" {
		if _, ok := files[component+".component"]; !ok {
			files[component+".component"] = transferlayout.ComponentFile(component, &entry.attr)
		}
	}
	for rel, data := range files {
		if strings.Contains(rel, "/") {
			// Drop-ins are shipped as they are, but may not undo the bounds.
			if err := transferlayout.CheckNoVersionBounds(data); err != nil {
				return nil, fmt.Errorf("%s: %s: %w", entry.dir, rel, err)
			}
			continue
		}
		var section string
		switch {
		case strings.HasSuffix(rel, ".transfer"):
			section = transferlayout.TransferSection
		case strings.HasSuffix(rel, ".component"):
			section = transferlayout.ComponentSection
		default:
			continue
		}
		bounded, err := transferlayout.InjectVersionBounds(data, section, version)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", entry.dir, rel, err)
		}
		files[rel] = bounded
	}
	attr, err := json.Marshal(&entry.attr)
	if err != nil {
		return nil, fmt.Errorf("%s: encode ATTR: %w", entry.dir, err)
	}
	files[transferlayout.AttrFileName] = append(attr, '\n')
	return files, nil
}

// addQuarryTargets adds what the --quarry-* options ask for to the targets.
// Every transfer directory entry carries custom.quarry.version.
func addQuarryTargets(builder *tufext.TargetsBuilder, spec *quarrySpec) error {
	for _, entry := range spec.dirs {
		files, err := layoutTransferDir(entry, spec.version)
		if err != nil {
			return err
		}
		for _, rel := range slices.Sorted(maps.Keys(files)) {
			path, err := transferlayout.TargetPath(entry.dir, spec.version, rel)
			if err != nil {
				return fmt.Errorf("%s: %s: %w", entry.dir, rel, err)
			}
			if err := rejectExisting(builder, path); err != nil {
				return err
			}
			target, err := addInlineBytes(builder, path, files[rel])
			if err != nil {
				return err
			}
			if err := setQuarryCustomVersion(target, spec.version); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
		}
	}
	for _, tag := range spec.machineTags {
		name, value, _ := strings.Cut(tag, "=")
		path, err := transferlayout.MachineTagPath(name)
		if err != nil {
			return err
		}
		if err := rejectExisting(builder, path); err != nil {
			return err
		}
		// The content is the value, which is empty for a sentinel tag. There
		// is no custom.quarry.version because a tag belongs to no version.
		if _, err := addInlineBytes(builder, path, []byte(value)); err != nil {
			return err
		}
	}
	return nil
}

// rejectExisting returns an error if the targets already hold path. The
// builder would otherwise silently replace the entry (a repeated
// --quarry-machine-tag, or a generated entry colliding with a hashed or merged
// one).
func rejectExisting(builder *tufext.TargetsBuilder, path string) error {
	if _, dup := builder.TargetsType().Targets[path]; dup {
		return fmt.Errorf("target %s is given twice", path)
	}
	return nil
}

// setQuarryCustomVersion sets custom.quarry.version on a target, keeping its
// other custom fields.
func setQuarryCustomVersion(target *tufmetadata.TargetFiles, version string) error {
	return updateCustom(target, func(custom map[string]json.RawMessage) error {
		quarry := map[string]json.RawMessage{}
		if raw, ok := custom[tufext.QuarryCustomField]; ok {
			if err := json.Unmarshal(raw, &quarry); err != nil {
				return fmt.Errorf("existing custom.quarry data is not an object: %w", err)
			}
		}
		if quarry == nil { // "quarry": null
			quarry = map[string]json.RawMessage{}
		}
		encodedVersion, err := json.Marshal(version)
		if err != nil {
			return err
		}
		quarry["version"] = encodedVersion
		encodedQuarry, err := jsonutils.MarshalNoEscapeHTML(quarry)
		if err != nil {
			return err
		}
		custom[tufext.QuarryCustomField] = encodedQuarry
		return nil
	})
}

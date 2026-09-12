// Copyright (C) 2026 Amutable GmbH

// Package transferlayout describes the repository layout of what quarry
// ships as special TUF targets for systemd-sysupdate. This covers the
// versioned transfer definition directories under ".zzz-quarry-special/",
// their ATTR file, the version bounds stamped into the definitions, and the
// machine tag entries.
//
// hardhat writes this layout ("hardhat targets --quarry-*") and
// quarry-sysupdate (internal/xsysupdate) reads it, so both sides share the
// names and rules here.
package transferlayout

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
)

const (
	// Prefix is the target path prefix of everything quarry-specific in a
	// repository. Such a target is never a file that a client installs
	// directly.
	Prefix = ".zzz-quarry-special/"

	// TransferPrefix is the target path prefix of the transfer definition
	// directories. Their form is "sysupdate[.<component>].d=<version>/<file>".
	TransferPrefix = Prefix + "sysupdate"

	// TagsPrefix is the target path prefix of the machine tag entries. Their
	// form is "machine-tags/<name>", with the tag value (if any) as the
	// content.
	TagsPrefix = Prefix + "machine-tags/"

	// AttrFileName is the name of the JSON file in a versioned transfer
	// directory that describes the version (see [Attr]).
	AttrFileName = "ATTR"

	// defaultDir is the definitions directory of the default (component-less)
	// sysupdate component. The directory of a named component is
	// "sysupdate.<component>.d".
	defaultDir = "sysupdate.d"

	// ValiditySteppingStone is the [Attr.Validity] value marking a version
	// that must be installed (and activated) before updating to any newer
	// version.
	ValiditySteppingStone = "stepping-stone"

	// TransferSection is the section of a transfer definition that gets the
	// version bounds (see [InjectVersionBounds]).
	TransferSection = "[Transfer]"
	// ComponentSection is the same for a component definition.
	ComponentSection = "[Component]"
)

// Attr is the content of the [AttrFileName] file of a versioned transfer
// directory. Unknown fields are ignored by readers to allow for future
// extensions.
type Attr struct {
	// Validity qualifies the version (see [ValiditySteppingStone]).
	Validity string `json:"validity,omitempty"`

	// PreEnabled marks a pre-enabled component. It is updated on every machine
	// without needing a machine tag. Its definitions are staged as shipped,
	// without Enabled= stamped in. A component is either pre-enabled or gated
	// by Tag.
	PreEnabled bool `json:"pre-enabled,omitempty"`

	// Tag is the key of the machine tag gating the component. A machine takes
	// the directory iff it carries the tag. With PreEnabled it gates nothing.
	// Either way the machine tag "<key>.version=<version>" pins the component
	// to that version.
	Tag string `json:"tag,omitempty"`

	// Features maps the features of this version (the <name>.feature
	// definitions, by name) to what enables them. A feature is enabled iff
	// its Tag is set on the machine.
	Features map[string]FeatureAttr `json:"features,omitempty"`
}

// FeatureAttr describes one feature in [Attr.Features].
type FeatureAttr struct {
	// Tag is the machine tag (key) that enables the feature.
	Tag string `json:"tag"`
}

// ValidTagName returns whether name is usable as a machine tag key without
// value. Such a key serves as an ATTR or feature tag, or as a machine tag entry
// name.
func ValidTagName(name string) bool {
	return name != "" && !strings.ContainsAny(name, "=@/")
}

// ValidPathComponent returns whether name is usable as one path element.
func ValidPathComponent(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.Contains(name, "/")
}

// FeatureNames returns the sorted feature names of the ATTR, checking each
// entry.
func (attr *Attr) FeatureNames() ([]string, error) {
	names := slices.Sorted(maps.Keys(attr.Features))
	for _, name := range names {
		if !ValidPathComponent(name) || strings.HasSuffix(name, ".feature") {
			return nil, fmt.Errorf("invalid feature name %q", name)
		}
		if !ValidTagName(attr.Features[name].Tag) {
			return nil, fmt.Errorf("feature %q has invalid tag %q", name, attr.Features[name].Tag)
		}
	}
	return names, nil
}

// Validate checks the ATTR the way a reader would.
func (attr *Attr) Validate() error {
	if attr.Tag != "" && !ValidTagName(attr.Tag) {
		return fmt.Errorf("invalid tag %q", attr.Tag)
	}
	if !attr.PreEnabled && attr.Tag == "" {
		return errors.New("component is neither pre-enabled nor gated by a tag")
	}
	if attr.Validity != "" && attr.Validity != ValiditySteppingStone {
		return fmt.Errorf("unsupported validity %q", attr.Validity)
	}
	_, err := attr.FeatureNames()
	return err
}

// ComponentDir returns the definitions directory name of a component. The
// component "" names the default component.
func ComponentDir(component string) string {
	if component == "" {
		return defaultDir
	}
	return "sysupdate." + component + ".d"
}

// ParseComponentDir returns the component a definitions directory name is
// for. It returns "" for the default component's directory "sysupdate.d".
func ParseComponentDir(dir string) (string, error) {
	if dir == defaultDir {
		return "", nil
	}
	if !strings.HasPrefix(dir, "sysupdate.") || !strings.HasSuffix(dir, ".d") {
		return "", fmt.Errorf("invalid definitions directory name %q", dir)
	}
	component := strings.TrimSuffix(strings.TrimPrefix(dir, "sysupdate."), ".d")
	// "default" is reserved because quarry-sysupdate files the default
	// component under that name.
	if !ValidPathComponent(component) || strings.ContainsAny(component, "@=.") || component == "default" {
		return "", fmt.Errorf("invalid component name %q in directory %q", component, dir)
	}
	return component, nil
}

// DirSuffix returns what follows the definitions directory name in a
// versioned directory's target path, which is "=<version>". "@" and "=" are
// kept out of the version so a later qualifier can be added to the suffix.
func DirSuffix(version string) (string, error) {
	if version == "" || strings.ContainsAny(version, "@=/") {
		return "", fmt.Errorf("invalid transfer version %q", version)
	}
	return "=" + version, nil
}

// TargetPath returns the target path of one file of a versioned transfer
// directory.
func TargetPath(dir, version, file string) (string, error) {
	if _, err := ParseComponentDir(dir); err != nil {
		return "", err
	}
	suffix, err := DirSuffix(version)
	if err != nil {
		return "", err
	}
	for part := range strings.SplitSeq(file, "/") {
		if !ValidPathComponent(part) {
			return "", fmt.Errorf("invalid transfer file path %q", file)
		}
	}
	return Prefix + dir + suffix + "/" + file, nil
}

// MachineTagPath returns the target path of a machine tag entry.
func MachineTagPath(name string) (string, error) {
	if !ValidTagName(name) {
		return "", fmt.Errorf("invalid machine tag name %q", name)
	}
	return TagsPrefix + name, nil
}

// InjectVersionBounds bounds a definition to its own version. MinVersion= and
// MaxVersion= are inserted right after the given section header
// ([TransferSection] for a transfer, [ComponentSection] for a component file).
// A definition that sets either itself is rejected because the build owns
// them.
// MaxVersion= (and both keys in a [Component] section) are ahead of systemd,
// which warns about the unknown keys until they land. The rest of the file is
// left byte for byte.
func InjectVersionBounds(text []byte, section, version string) ([]byte, error) {
	if err := CheckNoVersionBounds(text); err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSuffix(string(text), "\n"), "\n")
	header := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == section {
			if header >= 0 {
				return nil, fmt.Errorf("definition has more than one %s section", section)
			}
			header = i
		}
	}
	if header < 0 {
		return nil, fmt.Errorf("definition has no %s section", section)
	}
	bounds := []string{"MinVersion=" + version, "MaxVersion=" + version}
	lines = slices.Insert(lines, header+1, bounds...)
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}

// CheckNoVersionBounds rejects a definition (or drop-in) that sets MinVersion=
// or MaxVersion= itself, as the build owns them (see [InjectVersionBounds]).
func CheckNoVersionBounds(text []byte) error {
	for line := range strings.SplitSeq(string(text), "\n") {
		key, _, _ := strings.Cut(line, "=")
		switch strings.TrimSpace(key) {
		case "MinVersion", "MaxVersion":
			return fmt.Errorf("definition sets %s= itself, but the build owns it", strings.TrimSpace(key))
		}
	}
	return nil
}

// ComponentFile returns the generated "<component>.component" definition for
// a component directory that ships none. A tag-gated component is off by
// default and suggested on its tag, so plain sysupdate enables it for the
// same machines as quarry-sysupdate does, which stamps Enabled= itself. A
// pre-enabled one gets Enabled=true. The caller injects the version bounds
// as for a shipped one.
func ComponentFile(component string, attr *Attr) []byte {
	text := ComponentSection + "\nDescription=" + component + "\n"
	switch {
	case attr.PreEnabled:
		text += "Enabled=true\n"
	case attr.Tag != "":
		text += "Enabled=false\nSuggestOnMachineTag=" + attr.Tag + "\n"
	}
	return []byte(text)
}

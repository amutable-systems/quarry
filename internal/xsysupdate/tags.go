// Copyright (C) 2026 Amutable GmbH

package xsysupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"

	"go.amutable.dev/quarry/internal/hostnamed"
	"go.amutable.dev/quarry/internal/systemdcmd"
	"go.amutable.dev/quarry/internal/third_party/funchelpers"
	"go.amutable.dev/quarry/internal/tufclient"
)

const (
	// TagsPrefix is the prefix used for our "machine tags" extension to
	// sysupdate. Any target file in a repository with this prefix indicates a
	// machine-info(5) machine tag to be set on the local machine.
	//
	// The filename suffix is the tag name, and the target file contents are
	// the tag value. If the file is zero-length then the tag is a "sentinel"
	// and thus is just of the form "foo.bar" rather than "foo.bar=baz".
	TagsPrefix = ExtensionTargetPrefix + "machine-tags/"

	// maxTagFileSize is the maximum tag target file size we are willing to
	// read. hostnamed has a restriction of 255 characters but lets use
	// something a little bit less aggressive purely to protect against
	// out-of-memory attacks.
	maxTagFileSize = 1 << 15 // 32 KiB
)

// fullTag returns the composed systemd machine tag string for the given tag
// name and value (nil for plain "sentinel" tags).
func fullTag(name string, value *string) string {
	if value == nil {
		return name
	}
	return name + "=" + *value
}

// TagsExtension is an [Extension] that implements the automated application
// of machine-info(5) machine tags from a repository. As there are multiple
// sources of tags on a system, you must provide the set of permitted tag
// names and namespaces that will be applied from repositories.
//
// Note that the application of tags from repositories is declarative -- the
// machine's set of tags within AllowedNamespaces is made to exactly match the
// set of tags shipped by the configured repositories, so any previous tags
// from these namespaces that are no longer in any repository will be removed
// during updates! Tags outside of AllowedNamespaces are never touched.
//
// TODO: Add file-based tag setting to systemd so that we can ship tags as
// regular files in /etc/machine-tags.d/quarry.tags -- which would allow users
// to set tags that we will not clear.
type TagsExtension struct {
	// AllowedNamespaces is the set of tag names and namespaces that
	// repositories are permitted to own.
	//
	// An entry witout a trailing dot only matches that exact tag, while an
	// entry with a trailing dot is a namespace prefix -- in other words,
	// "foo.bar." permits every tag under "foo.bar.*" but not "foo.bar".
	AllowedNamespaces []string

	// SocketURI (if non-empty) overrides the varlink URI used to talk to
	// systemd-hostnamed. This is primarily intended for tests. The default is
	// [hostnamed.DefaultSocketURI].
	SocketURI string

	// toApplyTags is the set of tags we have collected this update cycle to
	// apply before the updates fire, keyed by tag name. A nil value
	// indicates a plain "sentinel" tag.
	toApplyTags map[string]*string

	// appliedSetTags is the [hostnamed.SetTagsParams] used in BeforeUpdate,
	// kept for revert purposes in Abort. If nil or empty, Abort is a no-op.
	appliedSetTags *hostnamed.SetTagsParams
	// testingSkipSysupdate is set by tests to disable the call to start the
	// systemd-sysupdate-auto-enable.service unit, which will fail in our test
	// environment.
	testingSkipSysupdate bool
}

var _ Extension = &TagsExtension{}

// Name returns the name of this extension.
func (ext *TagsExtension) Name() string { return "tags" }

// tagNameMatches returns whether the given tag name (key) matches a single
// allowed tag entry. An entry with a trailing dot is a namespace prefix that
// matches every tag under the namespace ("foo.bar." matches "foo.bar.*" but
// not "foo.bar" itself), while any other entry matches only the exact tag
// name.
func tagNameMatches(allowed, name string) bool {
	if strings.HasSuffix(allowed, ".") {
		return strings.HasPrefix(name, allowed)
	}
	return name == allowed
}

// allowedTagName returns whether the given tag name (key) is permitted by
// AllowedNamespaces.
func (ext *TagsExtension) allowedTagName(name string) bool {
	return slices.ContainsFunc(ext.AllowedNamespaces, func(allowed string) bool {
		return tagNameMatches(allowed, name)
	})
}

// managedTags filters the given tag list down to the tags whose keys are
// within AllowedNamespaces (i.e., the tags this extension owns).
func (ext *TagsExtension) managedTags(tags []string) []string {
	var managed []string
	for _, tag := range tags {
		if ext.allowedTagName(hostnamed.TagKey(tag)) {
			managed = append(managed, tag)
		}
	}
	return managed
}

// Init prepares the extension for collecting tags.
func (ext *TagsExtension) Init(ctx context.Context) (context.Context, error) {
	ext.toApplyTags = map[string]*string{}
	return ctx, nil
}

// ApplyTarget collects the machine tag described by the target file, to be
// applied in BeforeUpdate.
func (ext *TagsExtension) ApplyTarget(ctx context.Context, info *tufclient.TargetInfo) (_ bool, Err error) {
	if !strings.HasPrefix(info.Path, TagsPrefix) {
		return false, nil // not for this extension
	}
	tagName := strings.TrimPrefix(info.Path, TagsPrefix)

	slog.Info("[xsysupdate tags target] Collecting machine tag file.",
		"target", info.Path, "repository", info.Repo.Name, "tagName", tagName)

	// If there is something wrong with a tags entry, we should not abort the
	// entire update as we are quite lenient in [setTags] and aborting allows
	// for one repo to stop the machine from getting base system updates. The
	// user will get feedback about bad tags from ACP anyway (as they won't
	// show up in reports).
	if err := func() error {
		// While we do not validate any part of the tag name, having "=" in the
		// tag name makes no sense and will screw up our other tag accounting
		// and overrides.
		if tagName == "" || strings.Contains(tagName, "=") {
			return fmt.Errorf("invalid machine tag target file name %q", info.Path)
		}
		if !ext.allowedTagName(tagName) {
			return fmt.Errorf("machine tag %q is not within the allowed namespaces %v", tagName, ext.AllowedNamespaces)
		}
		if info.Length > maxTagFileSize {
			return fmt.Errorf("machine tag file %s is too large (%d bytes) to be a valid machine tag", info.Path, info.Length)
		}
		return nil
	}(); err != nil {
		slog.Warn("[xsysupdate tags target] Provided machine tag is invalid -- skipping.",
			"target", info.Path, "repository", info.Repo.Name, "tagName", tagName, "err", err.Error())
		// Pretend that we "applied" it to get past the xsysupdate machinery.
		return true, nil
	}

	// However, if we hit spurious network errors we do abort the update to
	// avoid deleting valid tags in Abort.
	tagFile, err := info.Fetch(ctx)
	if err != nil {
		return false, fmt.Errorf("fetch machine tag file %s: %w", info.Path, err)
	}
	defer funchelpers.VerifyClose(&Err, tagFile)

	data, err := io.ReadAll(tagFile)
	if err != nil {
		return false, fmt.Errorf("read machine tag file %s: %w", info.Path, err)
	}
	if err := tagFile.Close(); err != nil {
		return false, fmt.Errorf("machine tag file %s close check failed: %w", info.Path, err)
	}

	// Strip newlines to make us slightly more resilient to the producer of
	// these tag files. An empty tag file represents a sentinel tag.
	var value *string
	if v := strings.TrimSuffix(string(data), "\n"); v != "" {
		value = &v
	}
	// We do not validate the tag data or format here, [hostnamed.SetTags]
	// handles that more elegantly than we can here.
	ext.toApplyTags[tagName] = value
	return true, nil
}

// tagSetDifference returns the sorted set of tags in a that are not in b.
func tagSetDifference(a, b []string) []string {
	diff := slices.DeleteFunc(slices.Clone(a), func(tag string) bool {
		return slices.Contains(b, tag)
	})
	slices.Sort(diff)
	return slices.Compact(diff)
}

// computeWantedSetTags computes the necessary [hostnamed.SetTagsParams]
// parameters in order to take the "current" set of tags and convert them to
// the "wanted" set of tags.
func computeWantedSetTags(current, want []string) *hostnamed.SetTagsParams {
	return &hostnamed.SetTagsParams{
		// While Add is idempotent, when we use Invert to compute the revert
		// operation we need to make sure that we will not accidentally remove
		// a pre-existing tag.
		Add: tagSetDifference(want, current),
		// The same goes for Remove but (by construction) it cannot contain
		// non-existent tags.
		Remove: tagSetDifference(current, want),
	}
}

// setTags is a wrapper around [hostnamed.SetTags] but any rejected tags are
// logged and only the applied tags are returned.
func setTags(ctx context.Context, uri string, params *hostnamed.SetTagsParams) (applied *hostnamed.SetTagsParams, _ error) {
	applied, rejected, err := hostnamed.SetTags(ctx, uri, params)
	if !rejected.IsEmpty() {
		slog.Warn("[xsysupdate tags] Machine tag update was rejected by hostnamed -- only a subset of tags could be applied.",
			"applied", applied, "rejected", rejected)
	}
	return applied, err
}

// BeforeUpdate reconciles the machine's tags with the set collected from the
// repositories.
func (ext *TagsExtension) BeforeUpdate(ctx context.Context) error {
	want := make([]string, 0, len(ext.toApplyTags))
	for name, value := range ext.toApplyTags {
		want = append(want, fullTag(name, value))
	}
	slices.Sort(want)

	current, err := hostnamed.CurrentTags(ctx, ext.SocketURI)
	if err != nil {
		return fmt.Errorf("fetch current machine tags: %w", err)
	}
	currentManaged := ext.managedTags(current)

	params := computeWantedSetTags(currentManaged, want)
	if params.IsEmpty() {
		slog.Info("[xsysupdate tags before-update] Machine tags are already up-to-date.",
			"tags", want)
		return nil
	}

	slog.Info("[xsysupdate tags before-update] Updating machine tags.",
		"tags", want, "SetTags", params)

	applied, err := setTags(ctx, ext.SocketURI, params)
	// applied can be non-empty even with errors, so set the metadata for Abort
	// before handling the error.
	ext.appliedSetTags = applied
	if err != nil {
		return fmt.Errorf("apply machine tags: %w", err)
	}

	// Trigger the auto-enablement of any components or features that are
	// conditional based on the tags we just applied.
	// TODO: This should be dropped once we have more on-demand handling, as
	// this model cannot handle disabling a component.
	if !ext.testingSkipSysupdate {
		if err := systemdcmd.Call(ctx, "systemctl", "start", "systemd-sysupdate-auto-enable.service"); err != nil {
			return fmt.Errorf("failed to trigger systemd-sysupdate-auto-enable service: %w", err)
		}
	}
	return nil
}

// Abort resets the machine tags to before the update was started.
func (ext *TagsExtension) Abort(ctx context.Context, srcErr error) error {
	var errs []error
	if !ext.appliedSetTags.IsEmpty() {
		// Invert the applied set to remove the new tags and add the old tags.
		// NOTE: This relies on [computeWantedSetTags] correctly avoiding
		// including spurious tags in the add and remove sets.
		revertParams := ext.appliedSetTags.Inverted()
		slog.Info("[xsysupdate tags abort] Reverting machine tags to pre-update state.",
			"revert-SetTags", revertParams, "err", srcErr.Error())
		if _, err := setTags(ctx, ext.SocketURI, revertParams); err != nil {
			errs = append(errs, fmt.Errorf("revert machine tags: %w", err))
		}
	}
	if err := ext.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close tags extension resources: %w", err))
	}
	// Clear the internal state so a double-abort doesn't do anything dumb.
	*ext = TagsExtension{
		AllowedNamespaces: ext.AllowedNamespaces,
		SocketURI:         ext.SocketURI,
	}
	return errors.Join(errs...)
}

// Close clears any resources used by the extension.
func (ext *TagsExtension) Close() error {
	ext.toApplyTags = nil
	return nil
}

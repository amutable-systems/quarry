//go:build insecure

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package xsysupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
	"snai.pe/go-varlink"
	service "snai.pe/go-varlink/org.varlink.service"

	"go.amutable.dev/quarry/internal/hostnamed/hostnamedtest"
	"go.amutable.dev/quarry/internal/testrepo"
	"go.amutable.dev/quarry/internal/tufclient"
	"go.amutable.dev/quarry/internal/tufext"
)

func TestMain(m *testing.M) {
	hostnamedtest.Main(m)
}

func initTagsExt(t *testing.T, uri string, allowed ...string) (*TagsExtension, context.Context) {
	t.Helper()
	if len(allowed) == 0 {
		allowed = []string{"acp.", "amutable."}
	}
	ctx := context.Background()
	ext := &TagsExtension{
		AllowedNamespaces:    allowed,
		SocketURI:            uri,
		testingSkipSysupdate: true,
	}
	_, err := ext.Init(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ext.Close() })
	return ext, ctx
}

func TestTagsAllowedTagName(t *testing.T) {
	ext := &TagsExtension{
		AllowedNamespaces:    []string{"acp.", "special.tag"},
		testingSkipSysupdate: true,
	}
	for _, test := range []struct {
		name    string
		allowed bool
	}{
		// "acp." is a namespace prefix: everything under it, not itself.
		{"acp.foo", true},
		{"acp.foo.bar", true},
		{"acp", false},
		{"acpx.foo", false},
		{"acp-other.foo", false},
		// "special.tag" is an exact tag name: only itself.
		{"special.tag", true},
		{"special.tag.sub", false},
		{"special.tagx", false},
		{"special", false},
		{"special.tag=x", false}, // keys are matched, not full tags
	} {
		assert.Equalf(t, test.allowed, ext.allowedTagName(test.name), "allowedTagName(%q)", test.name)
	}
}

// targetURLPath returns the URL path the given target is fetched from.
func targetURLPath(srv *testrepo.Server, targetPath string) string {
	return strings.TrimPrefix(srv.DataRootURL(), srv.URL) + "/" + targetPath
}

// makeTagTargetInfo builds a fetchable TargetInfo for a machine tag target
// file with the given contents.
func makeTagTargetInfo(t *testing.T, repoName, tagName string, content []byte) *tufclient.TargetInfo {
	t.Helper()
	srv := testrepo.New(t)
	return &tufclient.TargetInfo{
		TargetFiles: srv.WriteTarget(t, TagsPrefix+tagName, bytes.NewReader(content)),
		Repo:        makeRepo(t, srv, repoName),
	}
}

// makeInlineTagTargetInfo builds a TargetInfo for a machine tag target file
// whose contents are embedded in the target metadata itself with
// x-quarry-inline-data. Machine tags are the canonical use-case for inline
// data, so the repository fails the test if the tag is fetched at all --
// inlined tags must never cost a fetch round-trip.
func makeInlineTagTargetInfo(t *testing.T, repoName, tagName string, content []byte) *tufclient.TargetInfo {
	t.Helper()
	srv := testrepo.New(t)
	// The exact-path pattern takes precedence over the server's target file
	// serving.
	srv.Handle(targetURLPath(srv, TagsPrefix+tagName), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("inlined machine tag %q must be read from the metadata, not fetched (got request for %s)", tagName, r.URL)
		http.NotFound(w, r)
	}))

	// A sentinel tag file is empty, not absent: nil content must be inlined
	// as present-but-empty data ("") rather than as a JSON null (which
	// clients treat the same as having no inline data at all).
	if content == nil {
		content = []byte{}
	}
	sum := sha256.Sum256(content)
	target := &tufmetadata.TargetFiles{
		Length: int64(len(content)),
		Hashes: tufmetadata.Hashes{"sha256": sum[:]},
	}
	tufext.TargetFilesExt(target).WithInlineData(content)
	// NOTE: Path must be set after WithInlineData -- SetExtensionJSON
	// round-trips the struct through JSON, which drops non-JSON fields.
	target.Path = TagsPrefix + tagName
	return &tufclient.TargetInfo{
		TargetFiles: target,
		Repo:        makeRepo(t, srv, repoName),
	}
}

func applyTagInfo(ctx context.Context, t *testing.T, ext *TagsExtension, info *tufclient.TargetInfo) error {
	t.Helper()
	applied, err := ext.ApplyTarget(ctx, info)
	if err == nil {
		assert.True(t, applied, "valid tag target files must be claimed by the tags extension")
	}
	return err
}

// applyTag collects a machine tag whose contents are fetched from the
// repository like any other target file.
func applyTag(ctx context.Context, t *testing.T, ext *TagsExtension, repoName, tagName string, content []byte) error {
	t.Helper()
	return applyTagInfo(ctx, t, ext, makeTagTargetInfo(t, repoName, tagName, content)) //nolint:contextcheck // testrepo.New uses t.Context internally
}

// applyInlineTag collects a machine tag whose contents are inlined into the
// target metadata.
func applyInlineTag(ctx context.Context, t *testing.T, ext *TagsExtension, repoName, tagName string, content []byte) error {
	t.Helper()
	return applyTagInfo(ctx, t, ext, makeInlineTagTargetInfo(t, repoName, tagName, content)) //nolint:contextcheck // testrepo.New uses t.Context internally
}

// tagDeliveryModes are the ways a repository can deliver tag file contents:
// fetched from the data URL like any other target file, or inlined into the
// signed target metadata (expected to be the common case for tags, which are
// tiny).
var tagDeliveryModes = map[string]func(ctx context.Context, t *testing.T, ext *TagsExtension, repoName, tagName string, content []byte) error{
	"Fetched": applyTag,
	"Inline":  applyInlineTag,
}

func TestTagsApplyTarget_NotForUs(t *testing.T) {
	ext, ctx := initTagsExt(t, hostnamedtest.Start(t).URI())

	for _, targetPath := range []string{
		"regular/target.bin",
		".zzz-quarry-special/sysupdate.d/foo.transfer",
		".zzz-quarry-special/machine-tags", // no trailing slash: not a tag file
	} {
		info := &tufclient.TargetInfo{
			TargetFiles: &tufmetadata.TargetFiles{Path: targetPath},
		}
		applied, err := ext.ApplyTarget(ctx, info)
		require.NoErrorf(t, err, "ApplyTarget(%q)", targetPath)
		assert.Falsef(t, applied, "ApplyTarget(%q)", targetPath)
	}
}

func TestTagsApplyTarget_CollectsTags(t *testing.T) {
	for mode, applyTagFn := range tagDeliveryModes {
		t.Run(mode, func(t *testing.T) {
			ext, ctx := initTagsExt(t, hostnamedtest.Start(t).URI())

			require.NoError(t, applyTagFn(ctx, t, ext, "repo1", "acp.sentinel", nil))
			require.NoError(t, applyTagFn(ctx, t, ext, "repo1", "amutable.kv", []byte("some-value\n")))
			require.NoError(t, applyTagFn(ctx, t, ext, "repo1", "acp.no-newline", []byte("v")))

			require.Len(t, ext.toApplyTags, 3)
			assert.Equal(t, "acp.sentinel", fullTag("acp.sentinel", ext.toApplyTags["acp.sentinel"]))
			assert.Equal(t, "amutable.kv=some-value", fullTag("amutable.kv", ext.toApplyTags["amutable.kv"]))
			assert.Equal(t, "acp.no-newline=v", fullTag("acp.no-newline", ext.toApplyTags["acp.no-newline"]))
		})
	}
}

// Invalid tag target file names are not fatal: a repository shipping a broken
// tags directory must not be able to wedge base system updates, so the bad
// entry is logged and skipped without being collected.
func TestTagsApplyTarget_InvalidNamesSkipped(t *testing.T) {
	ext, ctx := initTagsExt(t, hostnamedtest.Start(t).URI())

	// Name validation fails before any fetch, so the repository never needs
	// to serve anything.
	repo := makeRepo(t, testrepo.New(t), "repo1")

	for _, test := range []struct {
		name    string
		tagName string
	}{
		{"EmptyName", ""},
		{"EqualsInName", "acp.foo=bar"},
		{"OutsideNamespaces", "other.foo"},
		{"BareNamespace", "acp"},
		{"NamespacePrefixNotDotted", "acpfoo"},
		{"SubdirectoryOutsideNamespaces", "acp/foo"},
	} {
		t.Run(test.name, func(t *testing.T) {
			info := &tufclient.TargetInfo{
				TargetFiles: &tufmetadata.TargetFiles{Path: TagsPrefix + test.tagName},
				Repo:        repo,
			}
			applied, err := ext.ApplyTarget(ctx, info)
			require.NoError(t, err, "invalid tag names must be skipped, not fatal")
			assert.True(t, applied, "skipped tag targets must still be claimed by the tags extension")
			assert.Empty(t, ext.toApplyTags, "skipped tag targets must not be collected")
		})
	}
}

// Tag values (and names within the allowed namespaces, beyond "=") are
// deliberately not validated by quarry itself -- ApplyTarget collects them
// as-is and hostnamed (the sole authority on tag validity) rejects them when
// the collected tags are applied in BeforeUpdate. Rejected tags must not fail
// the update or modify the machine state; they are logged and skipped.
func TestTagsBeforeUpdate_InvalidTagsSkipped(t *testing.T) {
	for _, test := range []struct {
		name    string
		tagName string
		content string
	}{
		{"SpaceInValue", "acp.foo", "hello world\n"},
		{"ColonInValue", "acp.foo", "a:b\n"},
		{"MultiLineValue", "acp.foo", "a\nb\n"},
		{"TrailingDashSentinel", "acp.foo-", ""},
		{"TrailingDotSentinel", "acp.foo.", ""},
		{"SlashInName", "acp.sub/dir", ""},
		{"TooLongValue", "acp.foo", strings.Repeat("a", 250) + "\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := hostnamedtest.Start(t, "user.keep")
			ext, ctx := initTagsExt(t, h.URI())

			require.NoError(t, applyTag(ctx, t, ext, "repo1", test.tagName, []byte(test.content)),
				"invalid tag values must still be collected -- validation is hostnamed's job")

			require.NoError(t, ext.BeforeUpdate(ctx), "rejected tags must not fail the update")
			assert.True(t, ext.appliedSetTags.IsEmpty(), "rejected tags must not be recorded for Abort")
			assert.Equal(t, []string{"user.keep"}, h.Tags(t), "rejected tags must not modify the machine state")
		})
	}
}

// The tag-by-tag fallback: when the bulk update is rejected (here because an
// invalid hand-edited tag within the managed namespaces ends up in the remove
// list, and an invalid repository tag is in the add list), all the other tags
// must still be applied, with the rejected ones logged and skipped.
func TestTagsBeforeUpdate_MixedInvalidTags(t *testing.T) {
	h := hostnamedtest.Start(t, "acp.bad-", "acp.stale", "user.keep")
	ext, ctx := initTagsExt(t, h.URI())

	require.NoError(t, applyTag(ctx, t, ext, "repo1", "acp.new", nil))
	require.NoError(t, applyTag(ctx, t, ext, "repo1", "acp.broken-", nil))

	require.NoError(t, ext.BeforeUpdate(ctx), "rejected tags must not fail the update")

	// acp.new was applied and acp.stale removed despite the rejected tags --
	// and hostnamed itself dropped the invalid hand-edited acp.bad- when it
	// rewrote machine-info.
	assert.Equal(t, []string{"acp.new", "user.keep"}, h.Tags(t))
	require.NotNil(t, ext.appliedSetTags)
	assert.Equal(t, []string{"acp.new"}, ext.appliedSetTags.Add,
		"only the tags hostnamed accepted must be recorded for Abort")
	assert.Equal(t, []string{"acp.stale"}, ext.appliedSetTags.Remove,
		"only the tags hostnamed accepted must be recorded for Abort")

	// The revert inverts only the applied set, so it restores acp.stale and
	// removes acp.new in one shot without tripping over the tags that were
	// rejected during the update.
	require.NoError(t, ext.Abort(ctx, errors.New("test")))
	assert.Equal(t, []string{"acp.stale", "user.keep"}, h.Tags(t))
}

// Oversized tag files are skipped like other invalid tag entries. The length
// check uses the signed metadata, so no fetch happens for them either.
func TestTagsApplyTarget_FileTooLargeSkipped(t *testing.T) {
	ext, ctx := initTagsExt(t, hostnamedtest.Start(t).URI())

	info := &tufclient.TargetInfo{
		TargetFiles: &tufmetadata.TargetFiles{
			Path:   TagsPrefix + "acp.foo",
			Length: maxTagFileSize + 1,
		},
		Repo: makeRepo(t, testrepo.New(t), "repo1"),
	}
	applied, err := ext.ApplyTarget(ctx, info)
	require.NoError(t, err, "oversized tag files must be skipped, not fatal")
	assert.True(t, applied, "skipped tag targets must still be claimed by the tags extension")
	assert.Empty(t, ext.toApplyTags, "skipped tag targets must not be collected")
}

// Unlike invalid tag entries, transient fetch failures must abort the update
// -- otherwise a network blip would make a currently-set tag look unshipped
// and get it removed during reconciliation in BeforeUpdate.
func TestTagsApplyTarget_FetchErrorFatal(t *testing.T) {
	ext, ctx := initTagsExt(t, hostnamedtest.Start(t).URI())

	content := []byte("value\n")
	sum := sha256.Sum256(content)
	info := &tufclient.TargetInfo{
		TargetFiles: &tufmetadata.TargetFiles{
			Path:   TagsPrefix + "acp.foo",
			Length: int64(len(content)),
			Hashes: tufmetadata.Hashes{"sha256": sum[:]},
		},
		// The tag's file was never written to the repository, so every fetch
		// fails.
		Repo: makeRepo(t, testrepo.New(t), "repo1"),
	}
	_, err := ext.ApplyTarget(ctx, info)
	require.Error(t, err, "fetch failures must abort the update")
	assert.ErrorContains(t, err, "fetch machine tag file") //nolint:testifylint // assert is fine for error path checks
	assert.Empty(t, ext.toApplyTags)
}

// Fetched contents that do not match the signed hashes must also be fatal --
// unlike corrupt inline data there is no fallback source left to try, and
// treating it as a skip would remove the currently-set tag.
func TestTagsApplyTarget_CorruptDataFatal(t *testing.T) {
	ext, ctx := initTagsExt(t, hostnamedtest.Start(t).URI())

	genuine := []byte("good-value\n")
	sum := sha256.Sum256(genuine)
	const targetPath = TagsPrefix + "acp.foo"
	srv := testrepo.New(t)
	srv.WriteTarget(t, targetPath, bytes.NewReader([]byte("evil-value\n")))
	info := &tufclient.TargetInfo{
		TargetFiles: &tufmetadata.TargetFiles{
			Path:   targetPath,
			Length: int64(len(genuine)),
			Hashes: tufmetadata.Hashes{"sha256": sum[:]},
		},
		Repo: makeRepo(t, srv, "repo1"),
	}
	_, err := ext.ApplyTarget(ctx, info)
	require.Error(t, err, "corrupt tag file contents must abort the update")
	assert.ErrorContains(t, err, "machine tag file") //nolint:testifylint // assert is fine for error path checks
	assert.Empty(t, ext.toApplyTags)
}

// Inline data that does not match the signed hashes is not fatal: Fetch falls
// back to fetching the tag from the repository, where the contents are still
// verified against the same signed hashes.
func TestTagsApplyTarget_CorruptInlineDataFallback(t *testing.T) {
	ext, ctx := initTagsExt(t, hostnamedtest.Start(t).URI())

	genuine := []byte("good-value\n")
	const targetPath = TagsPrefix + "acp.foo"
	srv := testrepo.New(t)
	target := srv.WriteTarget(t, targetPath, bytes.NewReader(genuine))
	tufext.TargetFilesExt(target).WithInlineData([]byte("evil-value\n"))
	// NOTE: Path must be set after WithInlineData -- SetExtensionJSON
	// round-trips the struct through JSON, which drops non-JSON fields.
	target.Path = targetPath
	info := &tufclient.TargetInfo{
		TargetFiles: target,
		Repo:        makeRepo(t, srv, "repo1"),
	}

	require.NoError(t, applyTagInfo(ctx, t, ext, info))
	require.Len(t, ext.toApplyTags, 1)
	assert.Equal(t, "acp.foo=good-value", fullTag("acp.foo", ext.toApplyTags["acp.foo"]))
}

// A sentinel tag file is empty, and an empty target's contents are known from
// its signed metadata alone -- so even a repository that does not inline its
// tags never costs a fetch round-trip for a sentinel.
func TestTagsApplyTarget_EmptyTagNotFetched(t *testing.T) {
	ext, ctx := initTagsExt(t, hostnamedtest.Start(t).URI())

	const targetPath = TagsPrefix + "acp.sentinel"
	srv := testrepo.New(t)
	// The tag is deliberately never written to the repository, and the
	// exact-path pattern takes precedence over the server's target file
	// serving.
	srv.Handle(targetURLPath(srv, targetPath), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("empty machine tag must be read from the metadata, not fetched (got request for %s)", r.URL)
		http.NotFound(w, r)
	}))
	sum := sha256.Sum256(nil)
	info := &tufclient.TargetInfo{
		TargetFiles: &tufmetadata.TargetFiles{
			Path:   targetPath,
			Length: 0,
			Hashes: tufmetadata.Hashes{"sha256": sum[:]},
		},
		Repo: makeRepo(t, srv, "repo1"),
	}

	require.NoError(t, applyTagInfo(ctx, t, ext, info))
	require.Len(t, ext.toApplyTags, 1)
	assert.Equal(t, "acp.sentinel", fullTag("acp.sentinel", ext.toApplyTags["acp.sentinel"]))
}

// Duplicate target paths are resolved by repository order before extensions
// ever see them, so ApplyTarget just takes the last value it was given.
func TestTagsApplyTarget_LastValueWins(t *testing.T) {
	ext, ctx := initTagsExt(t, hostnamedtest.Start(t).URI())

	require.NoError(t, applyTag(ctx, t, ext, "repo1", "acp.foo", []byte("bar\n")))
	require.NoError(t, applyTag(ctx, t, ext, "repo2", "acp.foo", []byte("baz\n")))
	require.NoError(t, applyTag(ctx, t, ext, "repo1", "acp.sentinel", []byte("value\n")))
	require.NoError(t, applyTag(ctx, t, ext, "repo2", "acp.sentinel", nil))

	require.Len(t, ext.toApplyTags, 2)
	assert.Equal(t, "acp.foo=baz", fullTag("acp.foo", ext.toApplyTags["acp.foo"]))
	assert.Equal(t, "acp.sentinel", fullTag("acp.sentinel", ext.toApplyTags["acp.sentinel"]))
}

func TestTagsBeforeUpdate_FreshSystem(t *testing.T) {
	h := hostnamedtest.Start(t)
	ext, ctx := initTagsExt(t, h.URI())

	require.NoError(t, applyTag(ctx, t, ext, "repo1", "acp.sentinel", nil))
	require.NoError(t, applyTag(ctx, t, ext, "repo1", "amutable.kv", []byte("value\n")))

	require.NoError(t, ext.BeforeUpdate(ctx))

	assert.Equal(t, []string{"acp.sentinel", "amutable.kv=value"}, h.Tags(t))
	require.NotNil(t, ext.appliedSetTags)
	assert.Equal(t, []string{"acp.sentinel", "amutable.kv=value"}, ext.appliedSetTags.Add)
	assert.Empty(t, ext.appliedSetTags.Remove, "nothing to remove on a fresh system")
}

// A single update can mix inlined and fetched tag files (repositories choose
// per-target whether to inline); both are collected and reconciled the same
// way.
func TestTagsBeforeUpdate_InlineData(t *testing.T) {
	h := hostnamedtest.Start(t, "acp.stale", "user.tag")
	ext, ctx := initTagsExt(t, h.URI())

	require.NoError(t, applyInlineTag(ctx, t, ext, "repo1", "acp.sentinel", nil))
	require.NoError(t, applyInlineTag(ctx, t, ext, "repo1", "amutable.kv", []byte("value\n")))
	require.NoError(t, applyTag(ctx, t, ext, "repo2", "acp.fetched", []byte("f\n")))

	require.NoError(t, ext.BeforeUpdate(ctx))

	assert.Equal(t, []string{"acp.fetched=f", "acp.sentinel", "amutable.kv=value", "user.tag"}, h.Tags(t))
}

func TestTagsBeforeUpdate_Reconciles(t *testing.T) {
	h := hostnamedtest.Start(t, "acp.stale", "acp.keep=v", "user.tag", "other.ns=1")
	ext, ctx := initTagsExt(t, h.URI())

	require.NoError(t, applyTag(ctx, t, ext, "repo1", "acp.keep", []byte("v\n")))
	require.NoError(t, applyTag(ctx, t, ext, "repo1", "acp.new", nil))

	require.NoError(t, ext.BeforeUpdate(ctx))

	// acp.stale is removed, acp.new added, and unmanaged tags are untouched
	// -- which also proves that the update was applied with add/remove
	// semantics rather than a wholesale reset via SetTags' "set" field.
	assert.Equal(t, []string{"acp.keep=v", "acp.new", "other.ns=1", "user.tag"}, h.Tags(t))
}

func TestTagsBeforeUpdate_ChangesValue(t *testing.T) {
	h := hostnamedtest.Start(t, "acp.key=old", "user.tag")
	ext, ctx := initTagsExt(t, h.URI())

	require.NoError(t, applyTag(ctx, t, ext, "repo1", "acp.key", []byte("new\n")))

	require.NoError(t, ext.BeforeUpdate(ctx))

	assert.Equal(t, []string{"acp.key=new", "user.tag"}, h.Tags(t))
}

// An exact (non-trailing-dot) allowed entry manages only that one tag: tags
// underneath it are neither settable from repositories nor reconciled away.
func TestTagsBeforeUpdate_ExactAllowedTag(t *testing.T) {
	h := hostnamedtest.Start(t, "special.tag=old", "special.other", "special.tag.sub")
	ext, ctx := initTagsExt(t, h.URI(), "special.tag", "acp.")

	// special.tag.sub is outside the allowed set, so it is skipped (not
	// collected) rather than failing the update.
	require.NoError(t, applyTag(ctx, t, ext, "repo1", "special.tag.sub", nil))
	assert.Empty(t, ext.toApplyTags, "disallowed tag names must not be collected")

	require.NoError(t, applyTag(ctx, t, ext, "repo1", "special.tag", []byte("new\n")))
	require.NoError(t, ext.BeforeUpdate(ctx))

	// Only special.tag was reconciled; special.tag.sub and special.other are
	// outside the allowed set and must survive.
	assert.Equal(t, []string{"special.other", "special.tag.sub", "special.tag=new"}, h.Tags(t))
}

func TestTagsBeforeUpdate_NoChangesNeeded(t *testing.T) {
	h := hostnamedtest.Start(t, "acp.foo", "user.tag")
	ext, ctx := initTagsExt(t, h.URI())

	require.NoError(t, applyTag(ctx, t, ext, "repo1", "acp.foo", nil))

	before := h.MachineInfoFingerprint(t)
	require.NoError(t, ext.BeforeUpdate(ctx))

	assert.Equal(t, before, h.MachineInfoFingerprint(t),
		"machine state must not be modified when tags already match")
	assert.True(t, ext.appliedSetTags.IsEmpty(), "no-op updates must not record anything to revert")

	// A subsequent Abort must not try to revert anything either.
	require.NoError(t, ext.Abort(ctx, errors.New("test")))
	assert.Equal(t, before, h.MachineInfoFingerprint(t))
	assert.Equal(t, []string{"acp.foo", "user.tag"}, h.Tags(t))
}

func TestTagsBeforeUpdate_EmptyDesiredPurgesManaged(t *testing.T) {
	h := hostnamedtest.Start(t, "acp.foo", "amutable.bar=baz", "user.tag")
	ext, ctx := initTagsExt(t, h.URI())

	// No tag target files in any repository: all managed tags are removed.
	require.NoError(t, ext.BeforeUpdate(ctx))

	assert.Equal(t, []string{"user.tag"}, h.Tags(t))
}

func TestTagsBeforeUpdate_SetTagsFails(t *testing.T) {
	// A systemd too old to support SetTags (pre-v262) replies with
	// MethodNotFound; error replies cannot be provoked from the real daemon,
	// so this test uses the fake service.
	uri := hostnamedtest.StartFake(t, map[string]varlink.Error{
		"SetTags": service.MethodNotFound("io.systemd.Hostname.SetTags"),
	})
	ext, ctx := initTagsExt(t, uri)

	require.NoError(t, applyTag(ctx, t, ext, "repo1", "acp.foo", nil))

	err := ext.BeforeUpdate(ctx)
	require.ErrorContains(t, err, "apply machine tags")
	assert.True(t, ext.appliedSetTags.IsEmpty(), "nothing was applied so nothing must be recorded for Abort")
}

func TestTagsBeforeUpdate_HostnamedUnavailable(t *testing.T) {
	ext := &TagsExtension{
		AllowedNamespaces:    []string{"acp"},
		SocketURI:            "unix:" + t.TempDir() + "/nonexistent-socket",
		testingSkipSysupdate: true,
	}
	ctx := context.Background()
	_, err := ext.Init(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ext.Close() })

	err = ext.BeforeUpdate(ctx)
	require.Error(t, err)
	assert.ErrorContains(t, err, "fetch current machine tags")
}

func TestTagsAbort_RestoresPreviousTags(t *testing.T) {
	h := hostnamedtest.Start(t, "acp.old", "acp.same", "user.tag")
	ext, ctx := initTagsExt(t, h.URI())

	require.NoError(t, applyTag(ctx, t, ext, "repo1", "acp.new", nil))
	require.NoError(t, applyTag(ctx, t, ext, "repo1", "acp.same", nil))

	require.NoError(t, ext.BeforeUpdate(ctx))
	require.Equal(t, []string{"acp.new", "acp.same", "user.tag"}, h.Tags(t))

	require.NoError(t, ext.Abort(ctx, errors.New("test")))
	assert.Equal(t, []string{"acp.old", "acp.same", "user.tag"}, h.Tags(t))

	// Double-abort must not do anything dumb.
	require.NoError(t, ext.Abort(ctx, errors.New("second")))
	assert.Equal(t, []string{"acp.old", "acp.same", "user.tag"}, h.Tags(t))
}

// The revert must still work when the abort was caused by context
// cancellation. Detaching the abort from the caller's cancellation is
// abortOnError's job (not Abort's), so this exercises that path.
func TestTagsAbort_WithCancelledContext(t *testing.T) {
	h := hostnamedtest.Start(t, "acp.old", "user.tag")
	ext, ctx := initTagsExt(t, h.URI())

	require.NoError(t, applyTag(ctx, t, ext, "repo1", "acp.new", nil))
	require.NoError(t, ext.BeforeUpdate(ctx))
	require.Equal(t, []string{"acp.new", "user.tag"}, h.Tags(t))

	cancelledCtx, cancel := context.WithCancel(ctx)
	cancel()

	ExtensionSet{ext}.abortOnError(cancelledCtx, context.Canceled)
	assert.Equal(t, []string{"acp.old", "user.tag"}, h.Tags(t))
}

func TestTagsAbort_BeforeModification(t *testing.T) {
	h := hostnamedtest.Start(t, "acp.foo")
	ext, ctx := initTagsExt(t, h.URI())

	require.NoError(t, applyTag(ctx, t, ext, "repo1", "acp.bar", nil))

	before := h.MachineInfoFingerprint(t)
	require.NoError(t, ext.Abort(ctx, errors.New("some other extension failed")))
	assert.Equal(t, before, h.MachineInfoFingerprint(t),
		"machine state must not be modified by an abort before any tags were applied")
	assert.Equal(t, []string{"acp.foo"}, h.Tags(t))
}

func TestTagsClose_Idempotent(t *testing.T) {
	ext, _ := initTagsExt(t, hostnamedtest.Start(t).URI())
	require.NoError(t, ext.Close())
	require.NoError(t, ext.Close())
}

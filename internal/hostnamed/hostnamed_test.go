// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package hostnamed_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	govarlink "snai.pe/go-varlink"
	service "snai.pe/go-varlink/org.varlink.service"

	"go.amutable.dev/quarry/internal/hostnamed"
	"go.amutable.dev/quarry/internal/hostnamed/hostnamedtest"
	"go.amutable.dev/quarry/internal/varlink"
)

func TestMain(m *testing.M) {
	hostnamedtest.Main(m)
}

func TestDescribe(t *testing.T) {
	h := hostnamedtest.Start(t, "acp.foo")

	// The real daemon's Describe reply contains plenty of fields we do not
	// know about (and grows more with every systemd release), so this also
	// verifies that unknown reply fields are tolerated.
	desc, err := hostnamed.Describe(context.Background(), h.URI())
	require.NoError(t, err)

	hostname, err := os.Hostname()
	require.NoError(t, err)
	assert.Equal(t, hostname, desc.Hostname)

	machineID, err := os.ReadFile("/etc/machine-id") //nolint:forbidigo // test code
	require.NoError(t, err)
	assert.Equal(t, strings.TrimSpace(string(machineID)), desc.MachineID)

	assert.Contains(t, desc.MachineInformationData, "TAGS=acp.foo")
}

func TestCurrentTags(t *testing.T) {
	h := hostnamedtest.Start(t)
	h.WriteMachineInfo(t,
		"PRETTY_HOSTNAME=Fake Host",
		"DEPLOYMENT=production",
		"TAGS=zzz.last:acp.foo=bar:acp.sentinel")

	tags, err := hostnamed.CurrentTags(context.Background(), h.URI())
	require.NoError(t, err)
	assert.Equal(t, []string{"acp.foo=bar", "acp.sentinel", "zzz.last"}, tags)
}

func TestCurrentTags_NoTags(t *testing.T) {
	h := hostnamedtest.Start(t)
	h.WriteMachineInfo(t, "PRETTY_HOSTNAME=Fake Host")

	tags, err := hostnamed.CurrentTags(context.Background(), h.URI())
	require.NoError(t, err)
	assert.Empty(t, tags)
}

func TestCurrentTags_NoMachineInfo(t *testing.T) {
	h := hostnamedtest.Start(t)

	tags, err := hostnamed.CurrentTags(context.Background(), h.URI())
	require.NoError(t, err)
	assert.Empty(t, tags)
}

func TestRawSetTags(t *testing.T) {
	h := hostnamedtest.Start(t, "acp.old", "user.keep")

	err := hostnamed.RawSetTags(context.Background(), h.URI(), &hostnamed.SetTagsParams{
		Add:    []string{"acp.new", "acp.kv=1"},
		Remove: []string{"acp.old"},
	})
	require.NoError(t, err)

	// user.keep surviving also proves that we never sent the "set" field,
	// which would have reset the whole tag list.
	assert.Equal(t, []string{"acp.kv=1", "acp.new", "user.keep"}, h.Tags(t))
}

func TestRawSetTags_EmptyIsNoop(t *testing.T) {
	h := hostnamedtest.Start(t, "acp.foo")

	before := h.MachineInfoFingerprint(t)
	require.NoError(t, hostnamed.RawSetTags(context.Background(), h.URI(), &hostnamed.SetTagsParams{}))
	require.NoError(t, hostnamed.RawSetTags(context.Background(), h.URI(), nil))
	assert.Equal(t, before, h.MachineInfoFingerprint(t),
		"machine state must not be modified for empty or nil add+remove")
	assert.Equal(t, []string{"acp.foo"}, h.Tags(t))
}

// Calls must keep working across hostnamed restarts (in production it
// idle-exits after ~30s, so restarts between calls are routine). Every call
// dials a fresh connection precisely so that there is no cached state to go
// stale here.
func TestCallsSpanDaemonRestarts(t *testing.T) {
	h := hostnamedtest.Start(t, "acp.foo")

	tags, err := hostnamed.CurrentTags(context.Background(), h.URI())
	require.NoError(t, err)
	require.Equal(t, []string{"acp.foo"}, tags)

	h.Restart(t)

	require.NoError(t, hostnamed.RawSetTags(context.Background(), h.URI(),
		&hostnamed.SetTagsParams{Add: []string{"acp.bar"}}))
	assert.Equal(t, []string{"acp.bar", "acp.foo"}, h.Tags(t))
}

func TestRawSetTags_InvalidTagsRejected(t *testing.T) {
	h := hostnamedtest.Start(t, "acp.foo")
	ctx := context.Background()

	// Invalid tag in the add list.
	err := hostnamed.RawSetTags(ctx, h.URI(), &hostnamed.SetTagsParams{Add: []string{"-invalid"}})
	require.ErrorContains(t, err, "org.varlink.service.InvalidParameter")
	assert.True(t, varlink.IsInvalidParameter(err), "IsInvalidParameter must match real hostnamed rejections")

	// Same key with two different values within the add list.
	err = hostnamed.RawSetTags(ctx, h.URI(), &hostnamed.SetTagsParams{Add: []string{"acp.k=1", "acp.k=2"}})
	require.ErrorContains(t, err, "org.varlink.service.InvalidParameter")
	assert.True(t, varlink.IsInvalidParameter(err), "IsInvalidParameter must match real hostnamed rejections")

	assert.Equal(t, []string{"acp.foo"}, h.Tags(t), "rejected SetTags must not modify tags")
}

func TestRawSetTags_ErrorReply(t *testing.T) {
	// Error replies other than InvalidParameter cannot be provoked from the
	// real daemon (this one mimics a pre-v262 systemd without SetTags), so
	// this test uses the fake service.
	uri := hostnamedtest.StartFake(t, map[string]govarlink.Error{
		"SetTags": service.MethodNotFound("io.systemd.Hostname.SetTags"),
	})

	err := hostnamed.RawSetTags(context.Background(), uri,
		&hostnamed.SetTagsParams{Add: []string{"acp.bar"}})
	require.ErrorContains(t, err, "org.varlink.service.MethodNotFound")
	assert.False(t, varlink.IsInvalidParameter(err), "MethodNotFound is not a tag rejection")
}

func TestSetTags(t *testing.T) {
	h := hostnamedtest.Start(t, "acp.old", "user.keep")

	params := &hostnamed.SetTagsParams{
		Add:    []string{"acp.new", "acp.kv=1"},
		Remove: []string{"acp.old"},
	}
	applied, rejected, err := hostnamed.SetTags(context.Background(), h.URI(), params)
	require.NoError(t, err)
	assert.Equal(t, params, applied, "a fully-valid update must be reported as applied in full")
	assert.Nil(t, rejected, "valid tags must not be reported as rejected")
	assert.Equal(t, []string{"acp.kv=1", "acp.new", "user.keep"}, h.Tags(t))
}

func TestSetTags_EmptyIsNoop(t *testing.T) {
	h := hostnamedtest.Start(t, "acp.foo")

	before := h.MachineInfoFingerprint(t)
	applied, rejected, err := hostnamed.SetTags(context.Background(), h.URI(), &hostnamed.SetTagsParams{})
	require.NoError(t, err)
	assert.True(t, applied.IsEmpty(), "an empty request must report nothing as applied")
	assert.Nil(t, rejected)

	applied, rejected, err = hostnamed.SetTags(context.Background(), h.URI(), nil)
	require.NoError(t, err)
	assert.True(t, applied.IsEmpty(), "a nil request must report nothing as applied")
	assert.Nil(t, rejected)

	assert.Equal(t, before, h.MachineInfoFingerprint(t),
		"machine state must not be modified for empty or nil add+remove")
	assert.Equal(t, []string{"acp.foo"}, h.Tags(t))
}

func TestSetTags_PartiallyRejected(t *testing.T) {
	h := hostnamedtest.Start(t, "acp.old", "user.keep")

	// The invalid tags poison the one-shot fast path, forcing the one-by-one
	// slow path -- the valid add and remove must still be applied, with only
	// the invalid tags reported as rejected.
	applied, rejected, err := hostnamed.SetTags(context.Background(), h.URI(), &hostnamed.SetTagsParams{
		Add:    []string{"-invalid", "acp.new"},
		Remove: []string{"acp.old", "-alsobad"},
	})
	require.NoError(t, err)
	require.NotNil(t, applied)
	assert.Equal(t, []string{"acp.new"}, applied.Add)
	assert.Equal(t, []string{"acp.old"}, applied.Remove)
	require.NotNil(t, rejected)
	assert.Equal(t, []string{"-invalid"}, rejected.Add)
	assert.Equal(t, []string{"-alsobad"}, rejected.Remove)
	assert.Equal(t, []string{"acp.new", "user.keep"}, h.Tags(t))
}

func TestSetTags_AllRejected(t *testing.T) {
	h := hostnamedtest.Start(t, "acp.foo")

	before := h.MachineInfoFingerprint(t)
	applied, rejected, err := hostnamed.SetTags(context.Background(), h.URI(), &hostnamed.SetTagsParams{
		Add:    []string{"-bad1"},
		Remove: []string{"-bad2"},
	})
	require.NoError(t, err)
	assert.True(t, applied.IsEmpty(), "a fully-rejected update must report nothing as applied")
	require.NotNil(t, rejected)
	assert.Equal(t, []string{"-bad1"}, rejected.Add)
	assert.Equal(t, []string{"-bad2"}, rejected.Remove)
	assert.Equal(t, before, h.MachineInfoFingerprint(t),
		"machine state must not be modified when every tag is rejected")
	assert.Equal(t, []string{"acp.foo"}, h.Tags(t))
}

func TestSetTags_ErrorReply(t *testing.T) {
	// Errors other than InvalidParameter must be returned immediately rather
	// than triggering the per-tag retry slow path.
	uri := hostnamedtest.StartFake(t, map[string]govarlink.Error{
		"SetTags": service.MethodNotFound("io.systemd.Hostname.SetTags"),
	})

	applied, rejected, err := hostnamed.SetTags(context.Background(), uri,
		&hostnamed.SetTagsParams{Add: []string{"acp.bar"}})
	require.ErrorContains(t, err, "org.varlink.service.MethodNotFound")
	assert.False(t, varlink.IsInvalidParameter(err), "MethodNotFound is not a tag rejection")
	assert.Nil(t, applied, "hard errors must not report tags as applied")
	assert.Nil(t, rejected, "non-rejection errors must not report tags as rejected")
}

func TestSetTagsParams_Invert(t *testing.T) {
	p := hostnamed.SetTagsParams{Add: []string{"acp.a"}, Remove: []string{"acp.b", "acp.c"}}
	p.Invert()
	assert.Equal(t, hostnamed.SetTagsParams{Add: []string{"acp.b", "acp.c"}, Remove: []string{"acp.a"}}, p)
}

func TestSetTagsParams_Inverted(t *testing.T) {
	p := hostnamed.SetTagsParams{Add: []string{"acp.a"}, Remove: []string{"acp.b", "acp.c"}}
	p2 := p.Inverted()
	assert.Equal(t, hostnamed.SetTagsParams{Add: []string{"acp.a"}, Remove: []string{"acp.b", "acp.c"}}, p,
		"Inverted must not modify the original params")
	assert.Equal(t, &hostnamed.SetTagsParams{Add: []string{"acp.b", "acp.c"}, Remove: []string{"acp.a"}}, p2)
}

func TestSetTagsParams_IsEmpty(t *testing.T) {
	assert.True(t, (*hostnamed.SetTagsParams)(nil).IsEmpty(), "IsEmpty must be nil-safe")
	assert.True(t, (&hostnamed.SetTagsParams{}).IsEmpty())
	assert.False(t, (&hostnamed.SetTagsParams{Add: []string{"acp.a"}}).IsEmpty())
	assert.False(t, (&hostnamed.SetTagsParams{Remove: []string{"acp.b"}}).IsEmpty())
}

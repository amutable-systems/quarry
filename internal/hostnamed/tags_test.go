// Copyright (C) 2026 Amutable GmbH

package hostnamed_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.amutable.dev/quarry/internal/hostnamed"
)

func TestTagKey(t *testing.T) {
	for _, test := range []struct {
		tag, key string
	}{
		{"foo", "foo"},
		{"foo=bar", "foo"},
		{"foo=bar=baz", "foo"},
		{"acp.feature", "acp.feature"},
		{"acp.key=value", "acp.key"},
	} {
		assert.Equalf(t, test.key, hostnamed.TagKey(test.tag), "TagKey(%q)", test.tag)
	}
}

func TestParseTags(t *testing.T) {
	for _, test := range []struct {
		name, value string
		tags        []string
	}{
		{"Single", "foo", []string{"foo"}},
		{"Multiple", "foo:bar=baz", []string{"bar=baz", "foo"}},
		{"Sorted", "zzz:aaa:mmm", []string{"aaa", "mmm", "zzz"}},
		{"Deduplicated", "foo:foo:bar:foo", []string{"bar", "foo"}},
		// Invalid entries are preserved here because we want to avoid having
		// to replicate the validation rules from systemd-homenamed (which can
		// get out of date) we need to have robust fallback logic in xsysupdate
		// anyway.
		{"InvalidNames", "foo:not valid:-bad:x=trailing-", []string{"-bad", "foo", "not valid", "x=trailing-"}},
		// But empty entries get dropped as otherwise you end up with confusing
		// behaviour with an empty TAGS=.
		{"EmptyEntries", "foo::bar:", []string{"bar", "foo"}},
		{"Empty", "", []string{}},
		{"EmptyMultiple", "::", []string{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.tags, hostnamed.ParseTags(test.value))
		})
	}
}

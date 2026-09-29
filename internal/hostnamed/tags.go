// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package hostnamed

import (
	"slices"
	"strings"
)

// TagKey returns the key part of a "key=value" machine tag. For sentinel tags,
// the whole tag is the key.
func TagKey(tag string) string {
	key, _, _ := strings.Cut(tag, "=")
	return key
}

// ParseTags parses the value of a TAGS= machine-info(5) field (a
// colon-separated list of machine tags) into a sorted, deduplicated list.
//
// The tag values or formats are not validated against systemd-hostnamed's
// restrictions, it is up to the caller to validate tags if they wish.
func ParseTags(value string) []string {
	tags := strings.Split(value, ":")
	// Drop any "" tags since a bare TAGS= should be treated as empty.
	tags = slices.DeleteFunc(tags, func(tag string) bool { return tag == "" })
	// Sort and compact them like hostnamed does.
	slices.Sort(tags)
	return slices.Compact(tags)
}

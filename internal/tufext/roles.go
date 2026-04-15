// Copyright (C) 2026 Amutable GmbH

package tufext

import (
	"slices"

	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
)

// IsCoreRole returns whether the given role name is a "core" role defined by
// the TUF specification -- in other words, top-level role that is delegated by
// the root role.
func IsCoreRole(roleName string) bool {
	return slices.Contains(tufmetadata.TOP_LEVEL_ROLE_NAMES[:], roleName)
}

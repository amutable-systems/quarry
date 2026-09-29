// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package tufext

import (
	"fmt"

	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/keystore"
)

// CheckMetadataType is a post-parse check that a parsed [tufmetadata.Metadata]
// object actually is the expected type for the Go type and role name. An error
// is returned if any mismatch is detected.
//
// go-tuf does implement this internally but the checking is only done in
// [tufmetadata.Metadata.FromBytes] and not from its [json.Unmarshaler]
// implementation.
func CheckMetadataType[T tufmetadata.Roles](roleName string, data *tufmetadata.Metadata[T]) error {
	var objType, jsonType string
	switch data := any(data).(type) {
	case *SignedRoot:
		objType = tufmetadata.ROOT
		jsonType = data.Signed.Type
	case *SignedTimestamp:
		objType = tufmetadata.TIMESTAMP
		jsonType = data.Signed.Type
	case *SignedSnapshot:
		objType = tufmetadata.SNAPSHOT
		jsonType = data.Signed.Type
	case *SignedTargets:
		objType = tufmetadata.TARGETS
		jsonType = data.Signed.Type
	default:
		return fmt.Errorf("unknown metadata type %T", data)
	}
	if objType != jsonType {
		return fmt.Errorf("metadata type %T should have _type value %q but got %q", data, objType, jsonType)
	}
	roleExpectedType := roleName
	if !IsCoreRole(roleExpectedType) {
		// Delegated targets all have a "targets" type despite having different
		// role names.
		roleExpectedType = tufmetadata.TARGETS
	}
	if roleExpectedType != jsonType {
		return fmt.Errorf("metadata role %s should have _type value %s but got %q", roleName, roleExpectedType, jsonType)
	}
	// Check that the signatures are unique. This should not be necessary (our
	// code and go-tuf correctly only counts duplicate signatures once) but
	// (*tufmetadata.Metadata[T]).FromBytes rejects such objects and so we
	// should too, to avoid needlessly delaying errors from go-tuf.
	sigKeyIDs := make(map[keystore.KeyID]struct{}, len(data.Signatures))
	for _, sig := range data.Signatures {
		keyID := keystore.KeyID(sig.KeyID)
		if _, dup := sigKeyIDs[keyID]; dup {
			return fmt.Errorf("metadata role %s has multiple signatures for key %s", roleName, keyID)
		}
		sigKeyIDs[keyID] = struct{}{}
	}
	return nil
}

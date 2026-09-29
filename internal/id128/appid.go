// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package id128

import (
	"crypto/hmac"
	"crypto/sha256"

	"github.com/google/uuid"
)

// toUUIDv4 takes a given 16-byte string and converts it to a "random" UUIDv4.
// The logic for this comes from id128_make_v4_uuid(), to make sure
// [appSpecificID] is byte-for-byte compatible.
func toUUIDv4(id [16]byte) uuid.UUID {
	// Set the version to v4.
	id[6] = (id[6] & 0x0F) | 0x40
	// Set the UUID variant to DCE.
	id[8] = (id[8] & 0x3F) | 0x80
	return uuid.UUID(id)
}

// appSpecificID is a Go implementation of sd_id128_get_app_specific, which is
// used to generate privacy-preserving derived UUIDs for machine-ids.
func appSpecificID(base, appID uuid.UUID) uuid.UUID {
	// HMAC_SHA256(key=base, msg=appID)[:16]
	mac := hmac.New(sha256.New, base[:])
	mac.Write(appID[:])
	bytes := mac.Sum(nil)
	// Copy the first 16 bytes.
	var id [16]byte
	copy(id[:], bytes)
	return toUUIDv4(id)
}

// MachineAppSpecificID returns the application-specific UUID for this
// particular machine, in a byte-for-byte compatible manner to
// sd_id28_get_machine_app_specific.
func MachineAppSpecificID(appID uuid.UUID) (uuid.UUID, error) {
	machineID, err := MachineID()
	if err != nil {
		return uuid.Nil, err
	}
	return appSpecificID(machineID, appID), nil
}

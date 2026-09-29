// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package expand

import (
	"encoding/hex"

	"github.com/google/uuid"

	"go.amutable.dev/quarry"
	"go.amutable.dev/quarry/internal/id128"
)

var defaultPredicates = map[rune]PredicateFunc{
	// systemd-escape --path
	'e': systemdEscape,
}

var defaultSources = map[rune]SourceFunc{
	// systemd-id128 application-specific machine-id
	'm': quarryMachineID,
}

// hexUUID returns the no-separators version of the given UUID, to match the
// default output format of systemd-id128.
func hexUUID(uuid uuid.UUID) string {
	return hex.EncodeToString(uuid[:])
}

func quarryMachineID(_ *[]any) (string, error) {
	uuid, err := id128.MachineAppSpecificID(quarry.ApplicationID)
	if err != nil {
		return "", err
	}
	return hexUUID(uuid), nil
}

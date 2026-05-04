// Copyright (C) 2026 Amutable GmbH

package expand

import (
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

func quarryMachineID(_ *[]any) (string, error) {
	uuid, err := id128.MachineAppSpecificID(quarry.ApplicationID)
	if err != nil {
		return "", err
	}
	return uuid.String(), nil
}

// Copyright (C) 2026 Amutable GmbH

package id128

import (
	"bytes"
	"os"

	"github.com/google/uuid"
)

// MachineID returns the [uuid.UUID] of the current machine, as stored in
// /etc/machine-id. If the machine-id is an invalid UUID, an error is returned.
func MachineID() (uuid.UUID, error) {
	id, err := os.ReadFile("/etc/machine-id") //nolint:forbidigo // well-known root-owned host path
	if err != nil {
		return uuid.Nil, err
	}
	return uuid.ParseBytes(bytes.TrimRight(id, "\n"))
}

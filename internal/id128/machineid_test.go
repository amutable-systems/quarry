// Copyright (C) 2026 Amutable GmbH

package id128

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMachineID(t *testing.T) {
	raw, err := os.ReadFile("/etc/machine-id") //nolint:forbidigo // test code
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("/etc/machine-id is not present on this host")
	}
	require.NoError(t, err)

	want, err := uuid.ParseBytes(bytes.TrimRight(raw, "\n"))
	if err != nil {
		t.Skipf("/etc/machine-id is not parseable as a UUID: %v", err)
	}

	got, err := MachineID()
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

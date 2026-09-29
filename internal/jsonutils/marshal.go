// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package jsonutils

import (
	"bytes"
	"encoding/json"
)

// MarshalNoEscapeHTML is [json.Marshal] with HTML escaping disabled.
//
// TODO(json-v2): Drop this once we move to encoding/json/v2.
func MarshalNoEscapeHTML(value any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	// Trim trailing "\n"s so that our round-trip tests pass (the encoded
	// versions are identical but the in-memory representation changes after
	// round-trip encoding if you have trailing whitespace).
	return bytes.TrimSpace(buf.Bytes()), nil
}

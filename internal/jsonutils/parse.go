// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package jsonutils

import (
	"encoding/json"
)

// Parse is shorthand for [json.Unmarshal] with a new instance of the type.
func Parse[T any](data []byte) (T, error) {
	var v T
	err := json.Unmarshal(data, &v)
	return v, err
}

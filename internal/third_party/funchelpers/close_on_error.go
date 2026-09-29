// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package funchelpers

import (
	"errors"
	"fmt"
	"io"
	"io/fs"

	"go.amutable.dev/quarry/internal/third_party/assert"
)

// CloseOnError closes the given [io.Closer] if there was an error. This is
// intended to be used to shorten defer statements.
func CloseOnError(Err *error, closer io.Closer) {
	assert.Assert(Err != nil,
		"CloseOnError must be called with non-nil Err slot") // programmer error
	if *Err != nil {
		err := closer.Close()
		if errors.Is(err, fs.ErrClosed) {
			err = nil // no useful error to join
		}
		if err != nil {
			*Err = errors.Join(*Err,
				fmt.Errorf("encountered error while closing resource: %w", err))
		}
	}
}

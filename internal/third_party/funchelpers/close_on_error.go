// Copyright (C) 2026 Amutable GmbH

package funchelpers

import (
	"io"
)

// CloseOnError closes the given [io.Closer] if there was an error. This is
// intended to be used to shorten defer statements.
func CloseOnError(Err error, closer io.Closer) {
	if Err != nil {
		// It's fine to ignore an error here because we know the function is
		// already returning some other root error cause.
		_ = closer.Close()
	}
}

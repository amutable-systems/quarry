// Copyright (C) 2026 Amutable GmbH

package client

import (
	"fmt"
	"io"
)

// mustFprintf is [fmt.Fprintf] but panics if the write fails. Failing to write
// to the output stream is not something we can recover from (nor report), so
// the alternative would be for every caller to silently ignore the error.
func mustFprintf(wtr io.Writer, format string, args ...any) {
	if _, err := fmt.Fprintf(wtr, format, args...); err != nil {
		panic(err)
	}
}

// mustFprintln is [fmt.Fprintln] but panics if the write fails. See
// [mustFprintf].
func mustFprintln(wtr io.Writer, args ...any) {
	if _, err := fmt.Fprintln(wtr, args...); err != nil {
		panic(err)
	}
}

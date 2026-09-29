// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package main

import (
	"fmt"
	"io"

	"go.amutable.dev/quarry/cmd/internal/pprint"
	"go.amutable.dev/quarry/internal/keystore"
)

func pprintGenericKey(wtr io.Writer, prefix string, key *keystore.GenericKey) error {
	keyID, err := key.ID()
	if err != nil {
		return err
	}
	mustFprintf(wtr, "%sKey %s:\n", prefix, keyID)

	prefix += "\t"
	mustFprintf(wtr, "%sDriver: %s\n", prefix, key.Driver)
	mustFprintf(wtr, "%sType: %s\n", prefix, key.Public.Type)
	mustFprintf(wtr, "%sScheme: %s\n", prefix, key.Public.Scheme)
	mustFprintf(wtr, "%sPublicKey: %q\n", prefix, key.Public.Value.PublicKey)

	mustFprintf(wtr, "%sData:\n", prefix)
	pprint.JSON(wtr, prefix+"\t", "\t", []byte(key.Data))
	return nil
}

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

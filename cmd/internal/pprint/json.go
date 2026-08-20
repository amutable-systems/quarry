// Copyright (C) 2026 Amutable GmbH

package pprint

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
)

// ToJSON converts the given type to JSON and then prints it with [JSON].
func ToJSON(wtr io.Writer, prefix, indent string, data any) {
	payload, err := cjson.EncodeCanonical(data)
	if err != nil {
		panic(err)
	}
	JSON(wtr, prefix, indent, payload)
}

// JSON pretty-prints the given JSON bytes to the given [io.Writer].
func JSON(wtr io.Writer, prefix, indent string, data []byte) {
	var indented bytes.Buffer
	if err := json.Indent(&indented, data, prefix, indent); err != nil {
		panic(err)
	}
	if _, err := fmt.Fprintln(wtr, indented.String()); err != nil {
		panic(err)
	}
}

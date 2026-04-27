// Copyright (C) 2026 Amutable GmbH

package pprint

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
)

// ToJSON converts the given type to JSON and then prints it with [JSON].
func ToJSON(prefix, indent string, data any) {
	payload, err := cjson.EncodeCanonical(data)
	if err != nil {
		panic(err)
	}
	JSON(prefix, indent, payload)
}

// JSON pretty-prints the given JSON bytes.
func JSON(prefix, indent string, data []byte) {
	var indented bytes.Buffer
	if err := json.Indent(&indented, data, prefix, indent); err != nil {
		panic(err)
	}
	fmt.Println(indented.String())
}

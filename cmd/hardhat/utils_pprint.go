// Copyright (C) 2026 Amutable GmbH

package main

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"

	"go.amutable.dev/quarry/internal/keystore"
)

func pprintToJSON(prefix string, data any) { //nolint:unparam // prefix is useful for generic usage
	payload, err := cjson.EncodeCanonical(data)
	if err != nil {
		panic(err)
	}
	pprintJSON(prefix, payload)
}

func pprintJSON(prefix string, data []byte) {
	var indented bytes.Buffer
	if err := json.Indent(&indented, data, prefix, "\t"); err != nil {
		panic(err)
	}
	fmt.Println(indented.String())
}

func pprintGenericKey(prefix string, key *keystore.GenericKey) error {
	keyID, err := key.ID()
	if err != nil {
		return err
	}
	fmt.Printf("%sKey %s:\n", prefix, keyID)

	prefix += "\t"
	fmt.Printf("%sDriver: %s\n", prefix, key.Driver)
	fmt.Printf("%sType: %s\n", prefix, key.Public.Type)
	fmt.Printf("%sScheme: %s\n", prefix, key.Public.Scheme)
	fmt.Printf("%sPublicKey: %q\n", prefix, key.Public.Value.PublicKey)

	fmt.Printf("%sData:\n", prefix)
	pprintJSON(prefix+"\t", []byte(key.Data))
	return nil
}

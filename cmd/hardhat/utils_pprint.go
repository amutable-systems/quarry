// Copyright (C) 2026 Amutable GmbH

package main

import (
	"fmt"

	"go.amutable.dev/quarry/cmd/internal/pprint"
	"go.amutable.dev/quarry/internal/keystore"
)

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
	pprint.JSON(prefix+"\t", "\t", []byte(key.Data))
	return nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package cryptoext

import (
	"crypto"
)

// CommonPrivateKey is [crypto.PrivateKey] but it includes the methods that the
// standard library guarantees are implemented by the standard library.
type CommonPrivateKey interface {
	crypto.PrivateKey
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
}

// CommonPublicKey is [crypto.PublicKey] but it includes the methods that the
// standard library guarantees are implemented by the standard library.
type CommonPublicKey interface {
	crypto.PublicKey
	Equal(x crypto.PublicKey) bool
}

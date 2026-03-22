// Copyright (C) 2026 Amutable GmbH

package keystore_test

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.amutable.dev/quarry/internal/keystore"
)

func TestKeyType_SignerOpts(t *testing.T) {
	for _, tc := range []struct {
		name     string
		keyType  keystore.KeyType
		wantHash crypto.Hash
		wantNil  bool
	}{
		{"Ed25519", keystore.KeyTypeEd25519, crypto.Hash(0), false},
		{"ECDSA_SHA2_P256", keystore.KeyTypeECDSA_SHA2_P256, crypto.SHA256, false},
		{"RSASSA_PSS_SHA256", keystore.KeyTypeRSASSA_PSS_SHA256, crypto.SHA256, false},
		{"Unknown", keystore.KeyType{Type: "unknown", Scheme: "unknown"}, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.keyType.SignerOpts()
			if tc.wantNil {
				assert.Nil(t, opts)
			} else {
				require.NotNil(t, opts)
				assert.Equal(t, tc.wantHash, opts.HashFunc())
			}
		})
	}
}

func TestKeyID_IsValid(t *testing.T) {
	for _, tc := range []struct {
		name  string
		id    keystore.KeyID
		valid bool
	}{
		{"Valid64Hex", keystore.KeyID("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), true},
		{"AllZeros", keystore.KeyID("0000000000000000000000000000000000000000000000000000000000000000"), true},
		{"TooShort", keystore.KeyID("0123456789abcdef0123456789abcdef"), false},
		{"TooLong", keystore.KeyID("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"), false},
		{"UpperCase", keystore.KeyID("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"), false},
		{"BadChars", keystore.KeyID("0123456789abcdeg0123456789abcdef0123456789abcdef0123456789abcdef"), false},
		{"Empty", keystore.KeyID(""), false},
		{"BadKeyID", keystore.BadKeyID, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.valid, tc.id.IsValid())
		})
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package cryptoext_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.amutable.dev/quarry/internal/cryptoext"
)

func generateEd25519Key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

func generateECDSAKey(t *testing.T) (*ecdsa.PublicKey, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &priv.PublicKey, priv
}

func generateRSAKey(t *testing.T) (*rsa.PublicKey, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return &priv.PublicKey, priv
}

func hashMessage(msg []byte, signOpts crypto.SignerOpts) []byte {
	if hash := signOpts.HashFunc(); hash != 0 {
		h := hash.New()
		h.Write(msg)
		msg = h.Sum(nil)
	}
	return msg
}

func TestNewVerifier_Unsupported(t *testing.T) {
	// crypto.PublicKey is actually equivalent to "any", so we can provide a
	// string as a "public key" to check that unsupported key types get an
	// error.
	_, err := cryptoext.NewVerifier("not-a-key")
	require.Error(t, err, "NewVerifier should reject unsupported key types")
	assert.Contains(t, err.Error(), "unsupported public key type", "error should mention unsupported key type")
}

func TestVerify_Ed25519(t *testing.T) {
	pub, priv := generateEd25519Key(t)
	msg := []byte("test message")
	signOpts := crypto.Hash(0)

	sig, err := crypto.SignMessage(priv, rand.Reader, msg, signOpts)
	require.NoError(t, err)

	v, err := cryptoext.NewVerifier(pub)
	require.NoError(t, err)

	t.Run("Valid", func(t *testing.T) {
		// Ed25519 doesn't pre-hash, so Verify and VerifyMessage should both
		// succeed with the raw message.
		okVerify, err := v.Verify(msg, sig, signOpts)
		require.NoError(t, err, "Verify should not return an error")
		assert.True(t, okVerify, "Verify should accept a valid ed25519 signature")

		okVerifyMessage, err := cryptoext.VerifyMessage(v, msg, sig, signOpts)
		require.NoError(t, err, "VerifyMessage should not return an error")
		assert.True(t, okVerifyMessage, "VerifyMessage should accept a valid ed25519 signature")
	})

	t.Run("WithSignerOpts", func(t *testing.T) {
		edOpts := &ed25519.Options{} // equivalent to crypto.Hash(0)
		edSig, err := crypto.SignMessage(priv, rand.Reader, msg, edOpts)
		require.NoError(t, err)

		okVerify, err := v.Verify(msg, edSig, edOpts)
		require.NoError(t, err, "Verify should not return an error")
		assert.True(t, okVerify, "Verify should accept a valid signature with ed25519.Options{}")

		okVerifyMessage, err := cryptoext.VerifyMessage(v, msg, edSig, edOpts)
		require.NoError(t, err, "VerifyMessage should not return an error")
		assert.True(t, okVerifyMessage, "VerifyMessage should accept a valid signature with ed25519.Options{}")
	})

	t.Run("WrongKey", func(t *testing.T) {
		_, otherPriv := generateEd25519Key(t)
		badSig, err := crypto.SignMessage(otherPriv, rand.Reader, msg, signOpts)
		require.NoError(t, err)

		okVerify, err := v.Verify(msg, badSig, signOpts)
		require.NoError(t, err, "Verify should not return an error for wrong-key signature")
		assert.False(t, okVerify, "Verify should reject a signature from a different key")

		okVerifyMessage, err := cryptoext.VerifyMessage(v, msg, badSig, signOpts)
		require.NoError(t, err, "VerifyMessage should not return an error for wrong-key signature")
		assert.False(t, okVerifyMessage, "VerifyMessage should reject a signature from a different key")
	})

	t.Run("CorruptedSignature", func(t *testing.T) {
		corruptSig := slices.Clone(sig)
		corruptSig[0] ^= 0xff

		okVerify, err := v.Verify(msg, corruptSig, signOpts)
		require.NoError(t, err, "Verify should not return an error for corrupted signature")
		assert.False(t, okVerify, "Verify should reject a corrupted signature")

		okVerifyMessage, err := cryptoext.VerifyMessage(v, msg, corruptSig, signOpts)
		require.NoError(t, err, "VerifyMessage should not return an error for corrupted signature")
		assert.False(t, okVerifyMessage, "VerifyMessage should reject a corrupted signature")
	})

	t.Run("WrongMessage", func(t *testing.T) {
		badMsg := []byte("different message")

		okVerify, err := v.Verify(badMsg, sig, signOpts)
		require.NoError(t, err, "Verify should not return an error for wrong message")
		assert.False(t, okVerify, "Verify should reject when message doesn't match signature")

		okVerifyMessage, err := cryptoext.VerifyMessage(v, badMsg, sig, signOpts)
		require.NoError(t, err, "VerifyMessage should not return an error for wrong message")
		assert.False(t, okVerifyMessage, "VerifyMessage should reject when message doesn't match signature")
	})

	t.Run("RejectContext", func(t *testing.T) {
		sigOpts := &ed25519.Options{Context: "some-context"}
		sig, err := crypto.SignMessage(priv, rand.Reader, msg, sigOpts)
		require.NoError(t, err)

		okVerify, err := v.Verify(msg, sig, sigOpts)
		require.Error(t, err, "Verify should return an error for ed25519ctx")
		assert.Contains(t, err.Error(), "ed25519ctx", "error should mention ed25519ctx")
		assert.False(t, okVerify, "Verify should reject ed25519ctx signatures")

		// VerifyMessage with hash=0 doesn't pre-hash, so it hits the same
		// rejection path as Verify.
		okVerifyMessage, err := cryptoext.VerifyMessage(v, msg, sig, sigOpts)
		require.Error(t, err, "VerifyMessage should return an error for ed25519ctx")
		assert.Contains(t, err.Error(), "ed25519ctx", "error should mention ed25519ctx")
		assert.False(t, okVerifyMessage, "VerifyMessage should reject ed25519ctx signatures")
	})

	t.Run("RejectPreHashed", func(t *testing.T) {
		// crypto.SignMessage with a non-zero hash on an ed25519 key will hash
		// the message and call Sign with the hash option, producing an ed25519ph
		// signature. Our verifier should reject this because it doesn't support
		// pre-hashed ed25519.
		sigOpts := crypto.SHA512
		sig, err := crypto.SignMessage(priv, rand.Reader, msg, sigOpts)
		require.NoError(t, err)

		okVerify, err := v.Verify(msg, sig, sigOpts)
		require.Error(t, err, "Verify should return an error for ed25519ph")
		assert.Contains(t, err.Error(), "ed25519ph", "error should mention ed25519ph")
		assert.False(t, okVerify, "Verify should reject ed25519ph signatures")

		// VerifyMessage will hash the message before delegating to Verify,
		// but the verifier still rejects based on the non-zero HashFunc.
		okVerifyMessage, err := cryptoext.VerifyMessage(v, msg, sig, sigOpts)
		require.Error(t, err, "VerifyMessage should return an error for ed25519ph")
		assert.Contains(t, err.Error(), "ed25519ph", "error should mention ed25519ph")
		assert.False(t, okVerifyMessage, "VerifyMessage should reject ed25519ph signatures")
	})

	t.Run("RejectPreHashedContext", func(t *testing.T) {
		// The verifier checks Context before HashFunc, so this tests that
		// context rejection takes priority when both are set. The ed25519ph
		// rejection path is exercised by RejectPreHashed above.
		sigOpts := &ed25519.Options{
			Hash:    crypto.SHA512,
			Context: "some-context",
		}
		sig, err := crypto.SignMessage(priv, rand.Reader, msg, sigOpts)
		require.NoError(t, err)

		okVerify, err := v.Verify(msg, sig, sigOpts)
		require.Error(t, err, "Verify should return an error for ed25519ctx+ph")
		assert.Contains(t, err.Error(), "ed25519ctx", "context rejection should take priority over prehash")
		assert.False(t, okVerify, "Verify should reject ed25519ctx+ph signatures")

		okVerifyMessage, err := cryptoext.VerifyMessage(v, msg, sig, sigOpts)
		require.Error(t, err, "VerifyMessage should return an error for ed25519ctx+ph")
		assert.Contains(t, err.Error(), "ed25519ctx", "context rejection should take priority over prehash")
		assert.False(t, okVerifyMessage, "VerifyMessage should reject ed25519ctx+ph signatures")
	})
}

func TestVerify_ECDSA(t *testing.T) {
	pub, priv := generateECDSAKey(t)
	msg := []byte("test message")
	signOpts := crypto.SHA256

	sig, err := crypto.SignMessage(priv, rand.Reader, msg, signOpts)
	require.NoError(t, err)

	v, err := cryptoext.NewVerifier(pub)
	require.NoError(t, err)

	t.Run("Valid", func(t *testing.T) {
		// VerifyMessage hashes the message automatically -- should succeed.
		okVerifyMessage, err := cryptoext.VerifyMessage(v, msg, sig, signOpts)
		require.NoError(t, err, "VerifyMessage should not return an error")
		assert.True(t, okVerifyMessage, "VerifyMessage should accept a valid ECDSA signature")

		// Verify with the unhashed message should fail because the signature
		// was over the hashed message.
		okNohash, err := v.Verify(msg, sig, signOpts)
		require.NoError(t, err, "Verify with unhashed message should not return an error")
		assert.False(t, okNohash, "Verify should reject an unhashed message")

		// Verify with manually hashed message should succeed.
		okVerify, err := v.Verify(hashMessage(msg, signOpts), sig, signOpts)
		require.NoError(t, err, "Verify with hashed message should not return an error")
		assert.True(t, okVerify, "Verify should accept a manually hashed message")

		// VerifyMessage with an already-hashed message should fail because
		// VerifyMessage will double-hash.
		okDoubleHash, err := cryptoext.VerifyMessage(v, hashMessage(msg, signOpts), sig, signOpts)
		require.NoError(t, err, "VerifyMessage with pre-hashed message should not return an error")
		assert.False(t, okDoubleHash, "VerifyMessage should reject a pre-hashed message (double-hash)")
	})

	t.Run("WrongKey", func(t *testing.T) {
		_, otherPriv := generateECDSAKey(t)
		badSig, err := crypto.SignMessage(otherPriv, rand.Reader, msg, signOpts)
		require.NoError(t, err)

		okVerifyMessage, err := cryptoext.VerifyMessage(v, msg, badSig, signOpts)
		require.NoError(t, err, "VerifyMessage should not return an error for wrong-key signature")
		assert.False(t, okVerifyMessage, "VerifyMessage should reject a signature from a different key")

		okVerify, err := v.Verify(hashMessage(msg, signOpts), badSig, signOpts)
		require.NoError(t, err, "Verify should not return an error for wrong-key signature")
		assert.False(t, okVerify, "Verify should reject a signature from a different key")
	})

	t.Run("CorruptedSignature", func(t *testing.T) {
		corruptSig := slices.Clone(sig)
		corruptSig[0] ^= 0xff

		okVerifyMessage, err := cryptoext.VerifyMessage(v, msg, corruptSig, signOpts)
		require.NoError(t, err, "VerifyMessage should not return an error for corrupted signature")
		assert.False(t, okVerifyMessage, "VerifyMessage should reject a corrupted signature")

		okVerify, err := v.Verify(hashMessage(msg, signOpts), corruptSig, signOpts)
		require.NoError(t, err, "Verify should not return an error for corrupted signature")
		assert.False(t, okVerify, "Verify should reject a corrupted signature")
	})

	t.Run("WrongMessage", func(t *testing.T) {
		badMsg := []byte("different message")

		okVerifyMessage, err := cryptoext.VerifyMessage(v, badMsg, sig, signOpts)
		require.NoError(t, err, "VerifyMessage should not return an error for wrong message")
		assert.False(t, okVerifyMessage, "VerifyMessage should reject when message doesn't match signature")

		okVerify, err := v.Verify(hashMessage(badMsg, signOpts), sig, signOpts)
		require.NoError(t, err, "Verify should not return an error for wrong message")
		assert.False(t, okVerify, "Verify should reject when message doesn't match signature")
	})

	t.Run("HashMismatch", func(t *testing.T) {
		// Sign with SHA-256 but verify with SHA-512. The ecdsaVerifier ignores
		// opts but VerifyMessage hashes the message with the provided hash, so
		// the digest passed to VerifyASN1 won't match the one that was signed.
		ok, err := cryptoext.VerifyMessage(v, msg, sig, crypto.SHA512)
		require.NoError(t, err, "VerifyMessage should not return an error for hash mismatch")
		assert.False(t, ok, "VerifyMessage should reject when verify hash differs from sign hash")
	})
}

func TestVerify_RSA_PKCS1v15(t *testing.T) {
	pub, priv := generateRSAKey(t)
	msg := []byte("test message")
	signOpts := crypto.SHA256

	sig, err := crypto.SignMessage(priv, rand.Reader, msg, signOpts)
	require.NoError(t, err)

	v, err := cryptoext.NewVerifier(pub)
	require.NoError(t, err)

	t.Run("Valid", func(t *testing.T) {
		// VerifyMessage hashes the message automatically -- should succeed.
		okVerifyMessage, err := cryptoext.VerifyMessage(v, msg, sig, signOpts)
		require.NoError(t, err, "VerifyMessage should not return an error")
		assert.True(t, okVerifyMessage, "VerifyMessage should accept a valid RSA PKCS1v15 signature")

		// Verify with the unhashed message should fail because the digest
		// length won't match the expected hash size.
		// PKCS1v15 returns a non-ErrVerification error for wrong digest length.
		okNohash, err := v.Verify(msg, sig, signOpts)
		assert.False(t, okNohash, "Verify should reject an unhashed message")
		assert.Error(t, err, "Verify with wrong digest length should return an error") //nolint:testifylint // assert is fine for error path checks

		// Verify with manually hashed message should succeed.
		okVerify, err := v.Verify(hashMessage(msg, signOpts), sig, signOpts)
		require.NoError(t, err, "Verify with hashed message should not return an error")
		assert.True(t, okVerify, "Verify should accept a manually hashed message")

		// VerifyMessage with an already-hashed message should fail because
		// VerifyMessage will double-hash.
		okDoubleHash, err := cryptoext.VerifyMessage(v, hashMessage(msg, signOpts), sig, signOpts)
		require.NoError(t, err, "VerifyMessage with pre-hashed message should not return an error")
		assert.False(t, okDoubleHash, "VerifyMessage should reject a pre-hashed message (double-hash)")
	})

	t.Run("WrongKey", func(t *testing.T) {
		_, otherPriv := generateRSAKey(t)
		badSig, err := crypto.SignMessage(otherPriv, rand.Reader, msg, signOpts)
		require.NoError(t, err)

		okVerifyMessage, err := cryptoext.VerifyMessage(v, msg, badSig, signOpts)
		require.NoError(t, err, "VerifyMessage should not return an error for wrong-key signature")
		assert.False(t, okVerifyMessage, "VerifyMessage should reject a signature from a different key")

		okVerify, err := v.Verify(hashMessage(msg, signOpts), badSig, signOpts)
		require.NoError(t, err, "Verify should not return an error for wrong-key signature")
		assert.False(t, okVerify, "Verify should reject a signature from a different key")
	})

	t.Run("CorruptedSignature", func(t *testing.T) {
		corruptSig := slices.Clone(sig)
		corruptSig[0] ^= 0xff

		okVerifyMessage, err := cryptoext.VerifyMessage(v, msg, corruptSig, signOpts)
		require.NoError(t, err, "VerifyMessage should not return an error for corrupted signature")
		assert.False(t, okVerifyMessage, "VerifyMessage should reject a corrupted signature")

		okVerify, err := v.Verify(hashMessage(msg, signOpts), corruptSig, signOpts)
		require.NoError(t, err, "Verify should not return an error for corrupted signature")
		assert.False(t, okVerify, "Verify should reject a corrupted signature")
	})

	t.Run("WrongMessage", func(t *testing.T) {
		badMsg := []byte("different message")

		okVerifyMessage, err := cryptoext.VerifyMessage(v, badMsg, sig, signOpts)
		require.NoError(t, err, "VerifyMessage should not return an error for wrong message")
		assert.False(t, okVerifyMessage, "VerifyMessage should reject when message doesn't match signature")

		okVerify, err := v.Verify(hashMessage(badMsg, signOpts), sig, signOpts)
		require.NoError(t, err, "Verify should not return an error for wrong message")
		assert.False(t, okVerify, "Verify should reject when message doesn't match signature")
	})

	t.Run("HashMismatch", func(t *testing.T) {
		// Sign with SHA-256 but verify with SHA-512.
		ok, err := cryptoext.VerifyMessage(v, msg, sig, crypto.SHA512)
		require.NoError(t, err, "VerifyMessage should not return an error for hash mismatch")
		assert.False(t, ok, "VerifyMessage should reject when verify hash differs from sign hash")
	})
}

func TestVerify_RSA_PSS(t *testing.T) {
	pub, priv := generateRSAKey(t)
	msg := []byte("test message")
	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}

	sig, err := crypto.SignMessage(priv, rand.Reader, msg, pssOpts)
	require.NoError(t, err)

	v, err := cryptoext.NewVerifier(pub)
	require.NoError(t, err)

	t.Run("Valid", func(t *testing.T) {
		// VerifyMessage hashes the message automatically -- should succeed.
		okVerifyMessage, err := cryptoext.VerifyMessage(v, msg, sig, pssOpts)
		require.NoError(t, err, "VerifyMessage should not return an error")
		assert.True(t, okVerifyMessage, "VerifyMessage should accept a valid RSA PSS signature")

		// Verify with the unhashed message should fail because the signature
		// was over the hashed message.
		okNohash, err := v.Verify(msg, sig, pssOpts)
		require.NoError(t, err, "Verify with unhashed message should not return an error")
		assert.False(t, okNohash, "Verify should reject an unhashed message")

		// Verify with manually hashed message should succeed.
		okVerify, err := v.Verify(hashMessage(msg, pssOpts), sig, pssOpts)
		require.NoError(t, err, "Verify with hashed message should not return an error")
		assert.True(t, okVerify, "Verify should accept a manually hashed message")

		// VerifyMessage with an already-hashed message should fail because
		// VerifyMessage will double-hash.
		okDoubleHash, err := cryptoext.VerifyMessage(v, hashMessage(msg, pssOpts), sig, pssOpts)
		require.NoError(t, err, "VerifyMessage with pre-hashed message should not return an error")
		assert.False(t, okDoubleHash, "VerifyMessage should reject a pre-hashed message (double-hash)")
	})

	t.Run("WrongKey", func(t *testing.T) {
		_, otherPriv := generateRSAKey(t)
		badSig, err := crypto.SignMessage(otherPriv, rand.Reader, msg, pssOpts)
		require.NoError(t, err)

		okVerifyMessage, err := cryptoext.VerifyMessage(v, msg, badSig, pssOpts)
		require.NoError(t, err, "VerifyMessage should not return an error for wrong-key signature")
		assert.False(t, okVerifyMessage, "VerifyMessage should reject a signature from a different key")

		okVerify, err := v.Verify(hashMessage(msg, pssOpts), badSig, pssOpts)
		require.NoError(t, err, "Verify should not return an error for wrong-key signature")
		assert.False(t, okVerify, "Verify should reject a signature from a different key")
	})

	t.Run("CorruptedSignature", func(t *testing.T) {
		corruptSig := slices.Clone(sig)
		corruptSig[0] ^= 0xff

		okVerifyMessage, err := cryptoext.VerifyMessage(v, msg, corruptSig, pssOpts)
		require.NoError(t, err, "VerifyMessage should not return an error for corrupted signature")
		assert.False(t, okVerifyMessage, "VerifyMessage should reject a corrupted signature")

		okVerify, err := v.Verify(hashMessage(msg, pssOpts), corruptSig, pssOpts)
		require.NoError(t, err, "Verify should not return an error for corrupted signature")
		assert.False(t, okVerify, "Verify should reject a corrupted signature")
	})

	t.Run("WrongMessage", func(t *testing.T) {
		badMsg := []byte("different message")

		okVerifyMessage, err := cryptoext.VerifyMessage(v, badMsg, sig, pssOpts)
		require.NoError(t, err, "VerifyMessage should not return an error for wrong message")
		assert.False(t, okVerifyMessage, "VerifyMessage should reject when message doesn't match signature")

		okVerify, err := v.Verify(hashMessage(badMsg, pssOpts), sig, pssOpts)
		require.NoError(t, err, "Verify should not return an error for wrong message")
		assert.False(t, okVerify, "Verify should reject when message doesn't match signature")
	})

	t.Run("HashMismatch", func(t *testing.T) {
		// Sign with SHA-256 PSS but verify with SHA-512 PSS.
		verifyOpts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA512,
		}
		ok, err := cryptoext.VerifyMessage(v, msg, sig, verifyOpts)
		require.NoError(t, err, "VerifyMessage should not return an error for hash mismatch")
		assert.False(t, ok, "VerifyMessage should reject when verify hash differs from sign hash")
	})
}

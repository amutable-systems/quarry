// Copyright (C) 2026 Amutable GmbH

package keystore

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sync"

	"cyphar.com/go-pathrs"
	"golang.org/x/sys/unix"

	"go.amutable.dev/quarry/internal/pathrsext"
	"go.amutable.dev/quarry/internal/third_party/funchelpers"
)

var keyIDRegex = sync.OnceValue(func() *regexp.Regexp {
	return regexp.MustCompile(`^[0-9a-f]{64}$`)
})

// IsValid returns whether a [KeyID] is a valid key name. Invalid key names
// cannot be used for any [Store] operations and will always be rejected.
func (id KeyID) IsValid() bool {
	return keyIDRegex().MatchString(string(id))
}

func (id KeyID) subpath() (string, error) {
	if !id.IsValid() {
		return "", fmt.Errorf("invalid key id %q", id)
	}
	return string(id) + ".json", nil
}

// Store represents a quarry keystore, containing references to [GenericKey]s
// from any number of [Driver]s.
type Store struct {
	storeDir *pathrs.Root
}

// Close closes the keystore and releases the underlying file descriptor.
func (ks *Store) Close() error {
	return ks.storeDir.Close()
}

func (ks *Store) sync() (Err error) {
	// We can't call sync on storeDir directly (it's an O_PATH fd) so we need
	// to re-open it to do the flush.
	dir, err := ks.storeDir.OpenFile(".", unix.O_DIRECTORY)
	if err != nil {
		return fmt.Errorf("could not re-open keystore directory: %w", err)
	}
	defer funchelpers.VerifyClose(&Err, dir)

	err = dir.Sync()
	if err != nil {
		err = fmt.Errorf("could not flush directory metadata for key store: %w", err)
	}
	return err
}

// AddKey adds the given [GenericKey] to the key store and returns the [KeyID]
// of the key.
func (ks *Store) AddKey(_ context.Context, key *GenericKey) (_ KeyID, Err error) {
	keyID, err := key.ID()
	if err != nil {
		keyID = key.niceID()
		return BadKeyID, fmt.Errorf("could compute id for key %s", keyID)
	}

	keySubpath, err := keyID.subpath()
	if err != nil {
		return BadKeyID, fmt.Errorf("could not compute subpath for key %s: %w", keyID, err)
	}

	keyFile, err := ks.storeDir.Create(".", unix.O_TMPFILE|unix.O_RDWR, 0o600)
	if err != nil {
		return BadKeyID, fmt.Errorf("could not open temporary file for new key data: %w", err)
	}
	defer funchelpers.VerifyClose(&Err, keyFile)

	if err := json.NewEncoder(keyFile).Encode(key); err != nil {
		return BadKeyID, fmt.Errorf("could not marshal key %s: %w", keyID, err)
	}
	if err := keyFile.Sync(); err != nil {
		return BadKeyID, fmt.Errorf("could not flush key data for key %s: %w", keyID, err)
	}
	if err := pathrsext.AttachIntoRoot(ks.storeDir, keySubpath, keyFile); err != nil {
		// TODO: Detect EEXIST and return a custom error.
		return BadKeyID, fmt.Errorf("could not link keyfile to subpath %q: %w", keySubpath, err)
	}
	if err := ks.sync(); err != nil {
		return BadKeyID, err
	}
	return keyID, nil
}

// GetKey looks up the key with the given [KeyID] in the keystore and returns a
// [GenericKey] if the key exists.
func (ks *Store) GetKey(_ context.Context, keyID KeyID) (_ *GenericKey, Err error) {
	keySubpath, err := keyID.subpath()
	if err != nil {
		return nil, fmt.Errorf("could not compute subpath for key %s: %w", keyID, err)
	}

	keyFile, err := ks.storeDir.Open(keySubpath)
	if err != nil {
		// TODO: Detect ENOENT and return a custom error.
		return nil, fmt.Errorf("could not open key file for key %s: %w", keyID, err)
	}
	defer funchelpers.VerifyClose(&Err, keyFile)

	var key GenericKey
	if err := json.NewDecoder(keyFile).Decode(&key); err != nil {
		return nil, fmt.Errorf("parse key file for key %s: %w", keyID, err)
	}
	return &key, nil
}

// UnlinkKey removes the key with the given [KeyID] from the store. Note that
// for keys referencing external resources (such as HSM-based keys), this will
// not remove the underlying key material and simply unlinks it from the
// keystore.
func (ks *Store) UnlinkKey(_ context.Context, keyID KeyID) error {
	keySubpath, err := keyID.subpath()
	if err != nil {
		return fmt.Errorf("could not compute subpath for key %s: %w", keyID, err)
	}
	if err := ks.storeDir.RemoveFile(keySubpath); err != nil {
		// TODO: Detect ENOENT and return a custom error.
		return fmt.Errorf("failed to unlink key %s: %w", keyID, err)
	}
	return ks.sync()
}

// TODO: Do we need a DeleteKey which calls into the driver to also delete any
// backing key material (such as in HSMs or the exported keyfile for TPMs)?

// GetSigner is just a convenience wrapper around [Store.GetKey] and
// [GenericKey.GetSigner].
func (ks *Store) GetSigner(ctx context.Context, keyID KeyID) (crypto.Signer, error) {
	key, err := ks.GetKey(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key %s: %w", keyID, err)
	}
	return key.GetSigner(ctx)
}

// OpenStore opens a keystore [Store] that lives at the given directory.
func OpenStore(dirPath string) (_ *Store, Err error) {
	storeDir, err := pathrs.OpenRoot(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open store %q: %w", dirPath, err)
	}
	// TODO: Should we actually do this...?
	defer funchelpers.CloseOnError(Err, storeDir)

	return &Store{storeDir: storeDir}, nil
}

// StoreFromFd returns a keystore [Store] from the given directory [*os.File]
// handle. The original [*os.File] is not closed by this operation, so the
// caller should call [Close] themselves.
func StoreFromFd(dirFd *os.File) (_ *Store, Err error) {
	clonedFd, err := pathrs.RootFromFile(dirFd)
	if err != nil {
		return nil, fmt.Errorf("failed to convert store dirfd to pathrs root: %w", err)
	}
	// TODO: Should we actually do this...?
	defer funchelpers.CloseOnError(Err, clonedFd)

	return &Store{storeDir: clonedFd}, nil
}

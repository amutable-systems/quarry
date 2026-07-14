// Copyright (C) 2026 Amutable GmbH

package keystore

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"os"
	"regexp"
	"strings"
	"sync"

	"cyphar.com/go-pathrs"
	"golang.org/x/sys/unix"

	"go.amutable.dev/quarry/internal/generics"
	"go.amutable.dev/quarry/internal/pathrsext"
	"go.amutable.dev/quarry/internal/third_party/funchelpers"
)

var (
	// ErrNoSuchKey is returned by the key store if the given [KeyID] is
	// missing.
	ErrNoSuchKey = errors.New("key not found")

	// ErrKeyAlreadyExists is returned by the key store if a key being added
	// matches an existing [KeyID] in the store.
	ErrKeyAlreadyExists = errors.New("key already in store")
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

func keyidFromPath(path string) (KeyID, error) {
	id, hadSuffix := strings.CutSuffix(path, ".json")
	if !hadSuffix {
		return BadKeyID, fmt.Errorf("%q is not a valid keyid path: not a json file", path)
	}
	keyID := KeyID(id)
	if !keyID.IsValid() {
		return BadKeyID, fmt.Errorf("%q is not a valid keyid path: invalid key name %s", path, id)
	}
	return keyID, nil
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

// DefaultDriver is the fallback driver used by [Store.GenerateKey] when no
// [WithDriver] option is provided.
//
// TODO: This should be dynamic!
const DefaultDriver = "insecure"

// generateKey is the shared body of [Store.GenerateKey] and
// [Store.RotateKey]. The fallbackDriver is used if no [WithDriver] option
// was given.
func (ks *Store) generateKey(ctx context.Context, res *Resolver, fallbackDriver string) (KeyID, *GenericKey, error) {
	name := res.DriverName()
	if name == "" {
		name = fallbackDriver
	}
	driver, ok := GetDriver(name)
	if !ok {
		return BadKeyID, nil, fmt.Errorf("cannot generate key: unknown driver %s", name)
	}

	key, err := driver.GenerateKey(ctx, res)
	if err != nil {
		return BadKeyID, nil, err
	}
	if err := res.CheckUnconsumed(); err != nil {
		return BadKeyID, nil, err
	}

	keyID, err := ks.AddKey(ctx, key)
	if err != nil {
		return BadKeyID, nil, err
	}
	return keyID, key, nil
}

// GenerateKey generates a new key. The driver is selected with
// [WithDriver], falling back to [DefaultDriver]. This is mostly a
// shorthand for [Driver.GenerateKey] and [Store.AddKey].
func (ks *Store) GenerateKey(ctx context.Context, opts ...GenerateOption) (KeyID, *GenericKey, error) {
	res, err := NewGenerateResolver(opts)
	if err != nil {
		return BadKeyID, nil, err
	}
	return ks.generateKey(ctx, res, DefaultDriver)
}

// RotateKey generates a new key suitable as a replacement for the provided
// [KeyID]. By default the new key uses the same driver as the old key
// (pass [WithDriver] to override) with driver-default parameters.
//
// Since the underlying mechanism is to generate a fresh key, every
// [RotateOption] must also implement [GenerateOption].
//
// TODO: Implement copying of key options.
func (ks *Store) RotateKey(ctx context.Context, oldKeyID KeyID, opts ...RotateOption) (KeyID, *GenericKey, error) {
	oldKey, err := ks.GetKey(ctx, oldKeyID)
	if err != nil {
		return BadKeyID, nil, err
	}

	// Verify that every option can be used for key generation.
	user := make([]Option, 0, len(opts))
	for _, opt := range opts {
		if _, ok := opt.(GenerateOption); !ok {
			return BadKeyID, nil, fmt.Errorf("rotate option %v cannot be used to generate a new key", opt)
		}
		user = append(user, opt)
	}

	res, err := newResolver(user)
	if err != nil {
		return BadKeyID, nil, err
	}
	return ks.generateKey(ctx, res, oldKey.Driver)
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

	keyFile, err := ks.storeDir.Create(".", unix.O_TMPFILE|unix.O_NOFOLLOW|unix.O_RDWR, 0o600)
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
		// TODO: Should this be idempotent...? It's a bit ugly...
		err = fmt.Errorf("could not link keyfile to subpath %q: %w", keySubpath, err)
		if errors.Is(err, fs.ErrExist) {
			err = fmt.Errorf("%w: %w", ErrKeyAlreadyExists, err)
		}
		return BadKeyID, err
	}
	if err := ks.sync(); err != nil {
		return BadKeyID, err
	}
	return keyID, nil
}

// TODO: Should we add HasKey? There is no stat() for libpathrs (because it
// would be just as expensive as resolve), but it lets us avoid parsing
// JSON...?

// TODO: We probably want to have a way of just fetching a PublicKey from a
// keystore (maybe even having a way to store public-only keys...?).

// GetKey looks up the key with the given [KeyID] in the keystore and returns a
// [GenericKey] if the key exists.
func (ks *Store) GetKey(_ context.Context, keyID KeyID) (_ *GenericKey, Err error) {
	keySubpath, err := keyID.subpath()
	if err != nil {
		return nil, fmt.Errorf("could not compute subpath for key %s: %w", keyID, err)
	}

	keyFile, err := ks.storeDir.Open(keySubpath)
	if err != nil {
		err = fmt.Errorf("could not open key file for key %s: %w", keyID, err)
		if errors.Is(err, fs.ErrNotExist) {
			err = fmt.Errorf("%w: %w", ErrNoSuchKey, err)
		}
		return nil, err
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
		// TODO: Should this be idempotent...?
		err = fmt.Errorf("failed to unlink key %s: %w", keyID, err)
		if errors.Is(err, fs.ErrNotExist) {
			err = fmt.Errorf("%w: %w", ErrNoSuchKey, err)
		}
		return err
	}
	return ks.sync()
}

// ListKeyIDs returns an iterator over the set of [KeyID]s in the [Store].
func (ks *Store) ListKeyIDs(ctx context.Context) iter.Seq2[KeyID, error] {
	return generics.ErrorIter(func(yield func(KeyID) bool) (Err error) {
		seekFd, err := ks.storeDir.OpenFile(".", unix.O_DIRECTORY)
		if err != nil {
			return err
		}
		defer funchelpers.VerifyClose(&Err, seekFd)

		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			names, err := seekFd.Readdirnames(32)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return err
			}
			for _, name := range names {
				keyID, err := keyidFromPath(name)
				if err != nil {
					// TODO: Add logging...
					continue
				}
				if !yield(keyID) {
					return nil
				}
			}
		}
		return nil
	})
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
	defer funchelpers.CloseOnError(&Err, storeDir)

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
	defer funchelpers.CloseOnError(&Err, clonedFd)

	return &Store{storeDir: clonedFd}, nil
}

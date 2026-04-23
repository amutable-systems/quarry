// Copyright (C) 2026 Amutable GmbH

package keystore

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"iter"
	"sync"

	"go.amutable.dev/quarry/internal/keystore/keyopts"
)

// ErrUnsupportedKeyType is returned if a driver does not support the requested
// [KeyType].
var ErrUnsupportedKeyType = errors.New("key type not supported by driver")

// Driver is the top-level interface that all keystore drivers must implement.
type Driver interface {
	// Name returns the unique name of the keystore driver.
	Name() string

	// GenerateKey generates a new key using this driver.
	GenerateKey(ctx context.Context, opts ...keyopts.GenerateOption) (*GenericKey, error)

	// ImportKey imports an existing key into the driver. The type and format
	// of the "key" argument is dependent on the driver, and in most cases this
	// will come from some generated from an ExportKey clal.
	ImportKey(ctx context.Context, key any, opts ...keyopts.ImportOption) (*GenericKey, error)

	// ExportKey takes a given [GenericKey] and returns it in a format that can
	// be imported by [ImportKey]. Whether this can be used on a different
	// machine may depend on the driver and specified [keyopts.ExportOption]s.
	ExportKey(ctx context.Context, keyData *GenericKey, opts ...keyopts.ExportOption) (any, error)

	// GetSigner takes a given [GenericKey] and produces a [crypto.Signer]
	// which is backed by the driver.
	GetSigner(ctx context.Context, keyData *GenericKey) (crypto.Signer, error)
}

var drivers sync.Map

// RegisterDriver registers a driver for usage with the keystore module. Only
// one driver can be registered with a given name, and an error is returned if
// a driver with that name has already been loaded.
func RegisterDriver(driver Driver) error {
	name := driver.Name()
	if _, exists := drivers.LoadOrStore(name, driver); exists {
		return fmt.Errorf("keystore: key driver %q already registered", name)
	}
	return nil
}

// MustRegisterDriver is like [RegisterDriver] except that it panics if a
// driver with the same name is already registered.
func MustRegisterDriver(driver Driver) {
	if err := RegisterDriver(driver); err != nil {
		panic(err)
	}
}

// GetDriver looks up the driver with a given name and returns (driver, true)
// if it exists, otherwise it returns (nil, false).
func GetDriver(name string) (Driver, bool) {
	val, ok := drivers.Load(name)
	if !ok {
		return nil, ok
	}
	var driver Driver
	if ok {
		driver = val.(Driver) //nolint:forcetypeassert // guaranteed to be true
	}
	return driver, ok
}

// IterDrivers returns an iterator over the registered drivers.
func IterDrivers() iter.Seq2[string, Driver] {
	return func(yield func(string, Driver) bool) {
		drivers.Range(func(key, value any) bool {
			return yield(key.(string), value.(Driver)) //nolint:forcetypeassert // guaranteed to be true
		})
	}
}

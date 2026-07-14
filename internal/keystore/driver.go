// Copyright (C) 2026 Amutable GmbH

package keystore

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"iter"
	"sync"
)

// ErrUnsupportedKeyType is returned if a driver does not support the requested
// [KeyType].
var ErrUnsupportedKeyType = errors.New("key type not supported by driver")

// Driver is the top-level interface that all keystore drivers must implement.
//
// Drivers must run [ApplyOptions] on the [Resolver] passed to GenerateKey,
// ImportKey, and ExportKey for every state relevant to the operation --
// options left unconsumed by a skipped pass cause the operation to be
// rejected by the caller via [Resolver.CheckUnconsumed].
type Driver interface {
	// Name returns the unique name of the keystore driver.
	Name() string

	// GenerateKey generates a new key using this driver.
	GenerateKey(ctx context.Context, res *Resolver) (*GenericKey, error)

	// ImportKey imports an existing key into the driver. The type and format
	// of the "key" argument is dependent on the driver, and in most cases this
	// will come from a previous ExportKey call.
	ImportKey(ctx context.Context, key any, res *Resolver) (*GenericKey, error)

	// ExportKey takes a given [GenericKey] and returns it in a format that can
	// be imported by [ImportKey]. Whether this can be used on a different
	// machine may depend on the driver and specified [ExportOption]s.
	ExportKey(ctx context.Context, keyData *GenericKey, res *Resolver) (any, error)

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

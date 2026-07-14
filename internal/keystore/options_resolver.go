// Copyright (C) 2026 Amutable GmbH

package keystore

import (
	"fmt"
	"strings"
)

// genericState is the cross-driver state applied when the resolver is
// constructed. It is intentionally unexported -- driver selection and
// keytype resolution are owned by this package, and drivers only get read
// access through [Resolver.DriverName] and [Resolver.KeyTypeName].
type genericState struct {
	// driver is the requested driver name (empty if no [WithDriver] option
	// was given).
	driver string
}

// optionEntry is a single option tracked by a [Resolver].
type optionEntry struct {
	opt Option

	// consumed indicates that opt's Apply has matched at least one state.
	consumed bool
}

// Resolver tracks the options for a single key operation. The constructors
// ([NewGenerateResolver] and friends) do the marker-interface check at the
// API boundary and resolve the driver and keytype up-front, so a
// successfully-constructed resolver always has [Resolver.DriverName] and
// [Resolver.KeyTypeName] available.
type Resolver struct {
	entries []optionEntry

	driverName  string
	keyTypeName string
}

// asOptions converts a typed option slice to []Option.
func asOptions[T Option](opts []T) []Option {
	base := make([]Option, len(opts))
	for i, opt := range opts {
		base[i] = opt
	}
	return base
}

// newResolver constructs a [Resolver] with the given options and resolves
// the generic state.
func newResolver(opts []Option) (*Resolver, error) {
	r := &Resolver{
		entries: make([]optionEntry, 0, len(opts)),
	}
	for _, opt := range opts {
		r.entries = append(r.entries, optionEntry{opt: opt})
	}
	if err := r.resolveGeneric(); err != nil {
		return nil, err
	}
	return r, nil
}

// NewGenerateResolver constructs a [Resolver] for a key-generation
// operation.
func NewGenerateResolver(opts []GenerateOption) (*Resolver, error) {
	return newResolver(asOptions(opts))
}

// NewRotateResolver constructs a [Resolver] for a key-rotation operation.
func NewRotateResolver(opts []RotateOption) (*Resolver, error) {
	return newResolver(asOptions(opts))
}

// NewImportResolver constructs a [Resolver] for a key-import operation.
func NewImportResolver(opts []ImportOption) (*Resolver, error) {
	return newResolver(asOptions(opts))
}

// NewExportResolver constructs a [Resolver] for a key-export operation.
func NewExportResolver(opts []ExportOption) (*Resolver, error) {
	return newResolver(asOptions(opts))
}

// DriverName returns the driver name requested with [WithDriver], or an
// empty string if no driver was requested (in which case the caller picks
// a fallback).
func (r *Resolver) DriverName() string {
	return r.driverName
}

// KeyTypeName returns the TUF keytype requested by the options (explicitly
// with [WithKeyType], or implied by keytype-specific options), or an empty
// string if none was requested (in which case the driver picks a default).
//
// Note that TUF keytypes only name the key algorithm family -- despite the
// go-tuf constant name, [tufmetadata.KeyTypeECDSA_SHA2_P256] is just
// "ecdsa". Parameters beyond the algorithm family are handled by
// keytype-specific [ApplyOptions] passes in the driver.
func (r *Resolver) KeyTypeName() string {
	return r.keyTypeName
}

// resolveGeneric resolves the keytype and applies the generic-state
// options (such as [WithDriver]).
func (r *Resolver) resolveGeneric() error {
	keyType, err := r.resolveKeyType()
	if err != nil {
		return err
	}
	r.keyTypeName = keyType

	var gs genericState
	if err := ApplyOptions(r, &gs); err != nil {
		return err
	}
	r.driverName = gs.driver
	return nil
}

// resolveKeyType collects the keytype requested by every option and
// cross-checks them. Two options wanting different keytypes is a conflict,
// regardless of their order.
func (r *Resolver) resolveKeyType() (string, error) {
	type keyTypeSignal struct {
		opt     Option
		keyType string
	}
	var signals []keyTypeSignal
	for _, e := range r.entries {
		kt, ok := e.opt.(keyTypeParamer)
		if !ok {
			continue
		}
		val, err := kt.keyTypeParam()
		if err != nil {
			return "", err
		}
		signals = append(signals, keyTypeSignal{opt: e.opt, keyType: val})
	}
	if len(signals) == 0 {
		return "", nil
	}
	for _, signal := range signals[1:] {
		if signal.keyType != signals[0].keyType {
			return "", fmt.Errorf("conflicting keytypes: %v wants keytype %q but %v wants keytype %q",
				signals[0].opt, signals[0].keyType, signal.opt, signal.keyType)
		}
	}
	return signals[0].keyType, nil
}

// ApplyOptions applies every option that targets the given state type
// (i.e. implements Apply(*S) error) to the provided state, and marks them
// as consumed. Options targeting other state types are skipped. Drivers
// use this to fill their keytype- and driver-specific state structs.
func ApplyOptions[S any](r *Resolver, state *S) error {
	for i := range r.entries {
		entry := &r.entries[i]
		applier, ok := entry.opt.(interface{ Apply(*S) error })
		if !ok {
			continue
		}
		if err := applier.Apply(state); err != nil {
			return err
		}
		entry.consumed = true
	}
	return nil
}

// CheckUnconsumed returns an error listing all options that were not
// applied to any state. Callers (typically [Store]) should call this after
// the driver is finished, in order to detect unsupported options.
func (r *Resolver) CheckUnconsumed() error {
	var unused []string
	for _, e := range r.entries {
		if !e.consumed {
			unused = append(unused, fmt.Sprintf("%v", e.opt))
		}
	}
	if len(unused) == 0 {
		return nil
	}
	return fmt.Errorf("unsupported option(s): %s", strings.Join(unused, ", "))
}

// Copyright (C) 2026 Amutable GmbH

package keystore

import (
	"fmt"
	"strings"
)

// optionEntry is a single option tracked by a [Resolver].
type optionEntry struct {
	opt Option

	// consumed indicates that opt's Apply has matched at least one state.
	consumed bool
}

// Resolver tracks the options for a single key operation. The constructors
// ([NewGenerateResolver] and friends) do the marker-interface check at the
// API boundary.
type Resolver struct {
	entries []optionEntry
}

// asOptions converts a typed option slice to []Option.
func asOptions[T Option](opts []T) []Option {
	base := make([]Option, len(opts))
	for i, opt := range opts {
		base[i] = opt
	}
	return base
}

// newResolver constructs a [Resolver] with the given options.
func newResolver(opts []Option) *Resolver {
	r := &Resolver{
		entries: make([]optionEntry, 0, len(opts)),
	}
	for _, opt := range opts {
		r.entries = append(r.entries, optionEntry{opt: opt})
	}
	return r
}

// NewGenerateResolver constructs a [Resolver] for a key-generation
// operation.
func NewGenerateResolver(opts []GenerateOption) (*Resolver, error) {
	return newResolver(asOptions(opts)), nil
}

// NewRotateResolver constructs a [Resolver] for a key-rotation operation.
func NewRotateResolver(opts []RotateOption) (*Resolver, error) {
	return newResolver(asOptions(opts)), nil
}

// NewImportResolver constructs a [Resolver] for a key-import operation.
func NewImportResolver(opts []ImportOption) (*Resolver, error) {
	return newResolver(asOptions(opts)), nil
}

// NewExportResolver constructs a [Resolver] for a key-export operation.
func NewExportResolver(opts []ExportOption) (*Resolver, error) {
	return newResolver(asOptions(opts)), nil
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

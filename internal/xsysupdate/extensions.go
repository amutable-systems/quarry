// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

// Package xsysupdate implements extensions to systemd-sysupdate that are then
// implemented by the quarry-sysupdate runner. The long-term goal is for these
// extensions to provide practical experience for when designing improvements
// for systemd-sysupdate upstream.
package xsysupdate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"go.amutable.dev/quarry/internal/tufclient"
)

const (
	// ExtensionTargetPrefix is the path prefix used by quarry extension target
	// files to indicate they are a special kind of repository metadata.
	ExtensionTargetPrefix = ".quarry/"

	// legacyExtensionTargetPrefix is the old name for [ExtensionTargetPrefix],
	// still accepted for backward compatibility.
	// TODO: Drop this.
	legacyExtensionTargetPrefix = ".zzz-quarry-special/"
)

// CutExtensionTargetPrefix returns path without its [ExtensionTargetPrefix]
// with similar semantics to [strings.CutPrefix]. legacy is true if the prefix
// is actually the legacy (to-be-removed) prefix and should be used when
// deciding which version of an extension path should have priority.
func CutExtensionTargetPrefix(path string) (name string, legacy, ok bool) {
	for prefix, isLegacy := range map[string]bool{
		ExtensionTargetPrefix:       false,
		legacyExtensionTargetPrefix: true,
	} {
		if name, ok := strings.CutPrefix(path, prefix); ok {
			return name, isLegacy, ok
		}
	}
	return path, false, false
}

// Extension represents a Quarry extension that deal with special files in the
// repository.
type Extension interface {
	// Name returns the name of the extension, used for error messages.
	Name() string

	// Init is called at the start of quarry-sysupdate and does any preparatory
	// work needed for the extension. If an error is returned, the update is
	// aborted. The returned context will be passed to all other methods, which
	// is useful for storing per-extension state.
	Init(context.Context) (context.Context, error)

	// ApplyTarget actually applies the extension file. If the extension file
	// is not managed by this extension (false, nil) is returned. If an error
	// is returned, the update is aborted via [DoAbort].
	ApplyTarget(context.Context, *tufclient.TargetInfo) (bool, error)

	// BeforeUpdate is called after all extension targets have been applied but
	// before systemd-sysupdate is spawned. If an error is returned, the update
	// is aborted via [DoAbort].
	BeforeUpdate(context.Context) error

	// Abort is called if another extension returned an error during [Init],
	// [ApplyTarget], or [BeforeUpdate] and is intended to allow extensions to
	// do some kind of clean-up. Note that this is *not* called if an
	// extension's [Final] method returns an error!
	//
	// Be aware that Abort can be called for an extension that has never had
	// any extensions applied. For that reason, extensions are recommended to
	// store state information in the passed [context.Context] using a [Before]
	// callback.
	Abort(context.Context, error) error

	// Close is called at the end of quarry-sysupdate's execution, after all
	// extensions have been applied and systemd-sysupdate has completed. It is
	// primarily used to close any resources and do any remaining cleanup.
	//
	// Note that any errors returned at this stage will not revert the applied
	// updates! If you need to do some pre-flight checks, do so in [Before].
	Close() error
}

// ExtensionSet is a set of sysupdate extensions to apply.
type ExtensionSet []Extension

// String returns a [fmt.Printf]-friendly string of the extension set.
func (exts ExtensionSet) String() string {
	names := make([]string, 0, len(exts))
	for _, ext := range exts {
		names = append(names, ext.Name())
	}
	return fmt.Sprintf("%v", names)
}

func (exts ExtensionSet) abortOnError(ctx context.Context, Err error, logArgs ...any) {
	if Err != nil {
		logArgs = append(logArgs, "err", Err.Error())
		slog.Error("[xsysupdate] Error occurred during sysupdate extension operation.",
			logArgs...)
		// This abort may have been triggered by cancellation but it must complete
		// so drop the cancel but keep everything else.
		ctx = context.WithoutCancel(ctx)
		if err := exts.DoAbort(ctx, Err); err != nil {
			logArgs = append(logArgs, "abortErr", err.Error())
			slog.Error("[xsysupdate] Extension abort failed while handling operational error.",
				logArgs...)
			// TODO: Should we merge the errors?
		}
	}
}

// DoAbort aborts the previous application of sysupdate extensions.
func (exts ExtensionSet) DoAbort(ctx context.Context, srcErr error) error {
	var errs []error
	for _, ext := range exts {
		if err := ext.Abort(ctx, srcErr); err != nil {
			if errs == nil {
				errs = make([]error, 0, len(exts))
			}
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// TODO: Figure out how to unify this calling logic?

// DoInit runs the [Extension.Init] callback for all registered extensions.
// If an error occurs, [DoAbort] will be called automatically.
func (exts ExtensionSet) DoInit(ctx context.Context) (_ context.Context, Err error) {
	logArgs := []any{"operation", "DoInit"}
	defer func(logArgs *[]any) { exts.abortOnError(ctx, Err, (*logArgs)...) }(&logArgs)

	for _, ext := range exts {
		newCtx, err := ext.Init(ctx)
		if err != nil {
			logArgs = append(logArgs, "extension", ext.Name())
			return nil, err
		}
		if newCtx != nil {
			ctx = newCtx
		} else {
			// Should never happen.
			// TODO: Should we panic instead...?
			slog.Error("[xsysupdate] Extension returned nil context from Init.",
				"extension", ext.Name())
		}
	}
	return ctx, nil
}

// DoApplyTarget runs the [Extension.ApplyTarget] callback for all registered
// extensions. If an error occurs, [DoAbort] will be called automatically.
func (exts ExtensionSet) DoApplyTarget(ctx context.Context, info *tufclient.TargetInfo) (Err error) {
	logArgs := []any{"operation", "DoApplyTarget"}
	defer func(logArgs *[]any) { exts.abortOnError(ctx, Err, (*logArgs)...) }(&logArgs)

	var known bool
	for _, ext := range exts {
		if applied, err := ext.ApplyTarget(ctx, info); err != nil {
			logArgs = append(logArgs, "extension", ext.Name())
			return err
		} else if applied {
			known = true
		}
	}
	if !known {
		logArgs = append(logArgs, "extensions", exts.String())
		return fmt.Errorf("unsupported extension target file %s", info.Path)
	}
	return nil
}

// DoBeforeUpdate runs the [Extension.BeforeUpdate] callback for all registered
// extensions. If an error occurs, [DoAbort] will be called automatically.
func (exts ExtensionSet) DoBeforeUpdate(ctx context.Context) (Err error) {
	logArgs := []any{"operation", "DoBeforeUpdate"}
	defer func(logArgs *[]any) { exts.abortOnError(ctx, Err, (*logArgs)...) }(&logArgs)

	for _, ext := range exts {
		if err := ext.BeforeUpdate(ctx); err != nil {
			logArgs = append(logArgs, "extension", ext.Name())
			return err
		}
	}
	return nil
}

// Close runs the [Extension.Close] callback for all registered extensions.
func (exts ExtensionSet) Close() error {
	var errs []error
	for _, ext := range exts {
		if err := ext.Close(); err != nil {
			slog.Error("[xsysupdate] Post-installation extension failed.",
				"afterErr", err, "extension", ext.Name())
			if errs == nil {
				errs = make([]error, 0, len(exts))
			}
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

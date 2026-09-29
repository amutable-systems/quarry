// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package xsysupdate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"cyphar.com/go-pathrs"

	"go.amutable.dev/quarry/internal/ctxext"
	"go.amutable.dev/quarry/internal/third_party/funchelpers"
)

// DefaultRootDir is the default path where xsysupdate data is stored.
const DefaultRootDir = "/var/lib/quarry-sysupdate/xsysupdate"

// ctxKey is a package-local type used for [context.WithValue] keys.
type ctxKey string

// RootDirCtxKey stores a [pathrs.Root] handle to the root of the xsysupdate
// directory. This must live on non-volatile writable storage, and the default
// path is [DefaultRootDir] (/var/lib/quarry-sysupdate/xsysupdate).
const RootDirCtxKey ctxKey = "[" + DefaultRootDir + "]"

// CtxRootDir fetches the [RootDirCtxKey] from the context. This is just
// shorthand for [ctxext.Value].
func CtxRootDir(ctx context.Context) *pathrs.Root {
	return ctxext.Value[*pathrs.Root](ctx, RootDirCtxKey)
}

func extStoreDirCtxKey(ext Extension) ctxKey {
	return ctxKey(fmt.Sprintf("[%s/%s]", DefaultRootDir, ext.Name()))
}

func makeExtStoreDir(ctx context.Context, ext Extension) (_ context.Context, Err error) {
	var storeDir *pathrs.Root
	if rootDir := CtxRootDir(ctx); rootDir != nil {
		storeDirHandle, err := rootDir.MkdirAll(ext.Name(), 0o755)
		if err != nil {
			return nil, err
		}
		defer funchelpers.VerifyClose(&Err, storeDirHandle)
		root, err := pathrs.RootFromFile(storeDirHandle.IntoFile())
		if err != nil {
			return nil, err
		}
		storeDir = root
	} else {
		subdir := filepath.Join(DefaultRootDir, ext.Name()) //nolint:forbidigo // fixed host-controlled path
		if err := os.MkdirAll(subdir, 0o755); err != nil {  //nolint:forbidigo // fixed host-controlled path
			return nil, err
		}
		root, err := pathrs.OpenRoot(subdir)
		if err != nil {
			return nil, err
		}
		storeDir = root
	}
	key := extStoreDirCtxKey(ext)
	ctx = context.WithValue(ctx, key, storeDir)
	return ctx, nil
}

func ctxExtStoreDir(ctx context.Context, ext Extension) *pathrs.Root {
	key := extStoreDirCtxKey(ext)
	return ctxext.Value[*pathrs.Root](ctx, key)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

// Package uapi16ext implements Quarry's UAPI.16 vendor extensions, as well as
// the conversion of TUF target files into UAPI.16 file objects.
//
// UAPI.16 has no way of expressing most of what TUF stores about a target
// file, so everything that would otherwise be lost in the conversion is
// preserved in vendor extensions.
package uapi16ext

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

// Package uapi16 provides a minimal implementation of the [UAPI.16 file
// manifest] specification (enough for us to be able to map TUF repo metadata
// and data fetch URLs to a format understood by sysupdate).
//
// A manifest is an [RFC7464 JSON-SEQ] stream of file objects, the first of
// which describes the enveloping directory. Use [Writer] to generate one.
//
// [UAPI.16 file manifest]: https://github.com/uapi-group/specifications/pull/213
// [RFC7464 JSON-SEQ]: https://datatracker.ietf.org/doc/html/rfc7464
package uapi16

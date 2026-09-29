//go:build insecure

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package main

// Enable insecure driver if build with "insecure" tag.
import _ "go.amutable.dev/quarry/internal/keystore/insecure"

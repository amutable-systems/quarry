// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

// quarry is a multi-call binary containing all of the quarry-* applets, so
// systems shipping both only pay for one copy of the (mostly shared) code. The
// applet is selected based on the name the binary was invoked with (usually a
// symlink), with "quarry <applet>" as a fallback.
package main

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	client "go.amutable.dev/quarry/cmd/quarry-client"
	sysupdate "go.amutable.dev/quarry/cmd/quarry-sysupdate"
)

var applets = map[string]func(args []string) error{
	"quarry-client":    client.Main,
	"quarry-sysupdate": sysupdate.Main,
}

func appletNames() []string {
	return slices.Sorted(maps.Keys(applets))
}

func lookupApplet(name string) (func(args []string) error, bool) {
	// Accept both "quarry-client" and plain "client".
	if !strings.HasPrefix(name, "quarry-") {
		name = "quarry-" + name
	}
	applet, ok := applets[name]
	return applet, ok
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("cannot detect applet: empty argv")
	}
	name := filepath.Base(args[0]) //nolint:forbidigo // lexical pathname

	if applet, ok := lookupApplet(name); ok {
		return applet(args)
	}

	// Fall back to busybox-style "quarry <applet> [arguments]...".
	if len(args) > 1 {
		if applet, ok := lookupApplet(args[1]); ok {
			return applet(args[1:])
		}
		name = args[1]
	}
	return fmt.Errorf("unknown applet %q: usage is \"quarry <applet> [arguments]...\" or a symlink named after one of the applets (%s)",
		name, strings.Join(appletNames(), ", "))
}

func main() {
	if err := run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package expand

import (
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

func noEscapeChar(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') ||
		(ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9') ||
		ch == ':' || ch == '_' || ch == '.'
}

func escapeChar(buf *strings.Builder, ch rune) {
	for _, b := range utf8.AppendRune(nil, ch) {
		fmt.Fprintf(buf, "\\x%.2x", b)
	}
}

func systemdEscape(path string) (string, error) {
	// TODO: systemd-escape does not strip intermediate ".." components.
	str := filepath.Clean(path) //nolint:forbidigo // lexical pathname
	str = strings.TrimPrefix(str, "/")

	if str == "" || str == "." {
		return "-", nil
	}

	var buf strings.Builder
	buf.Grow(len(str))

	// Leading "."s are always escaped.
	if str[:1] == "." {
		escapeChar(&buf, '.')
		str = str[1:]
	}
	for _, ch := range str {
		switch {
		case ch == '/':
			buf.WriteRune('-')
		case noEscapeChar(ch):
			buf.WriteRune(ch)
		default:
			escapeChar(&buf, ch)
		}
	}
	return buf.String(), nil
}

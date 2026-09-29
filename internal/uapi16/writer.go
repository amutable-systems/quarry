// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package uapi16

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// recordSeparator is the ASCII RS byte that every JSON-SEQ record is prefixed
// with.
const recordSeparator = 0x1e

// Writer writes out a UAPI.16 manifest as a JSON-SEQ stream of file objects.
// The root file object always comes first -- use [Writer.WriteRoot] if you
// need to configure it, otherwise [Writer.WriteFile] will write a default root
// file object for you.
//
// Note that manifests require [File.Name] to be unique within a manifest, but
// as a Writer does not buffer the file objects it writes, it is up to the
// caller to ensure this.
//
// A Writer is not safe for concurrent use -- concurrent writes will interleave
// and corrupt the manifest, so callers must serialise access themselves.
type Writer struct {
	w         io.Writer
	buf       bytes.Buffer
	enc       *json.Encoder
	wroteRoot bool
}

// NewWriter returns a [Writer] that writes a manifest to the given
// [io.Writer].
func NewWriter(w io.Writer) *Writer {
	writer := &Writer{w: w}
	writer.enc = json.NewEncoder(&writer.buf)
	// Manifests are full of URLs, which are far more readable with real
	// ampersands in them.
	writer.enc.SetEscapeHTML(false)
	return writer
}

// writeRecord writes a single JSON-SEQ record.
func (writer *Writer) writeRecord(file *File) error {
	writer.buf.Reset()
	writer.buf.WriteByte(recordSeparator)
	// json.Encoder.Encode terminates its output with the same newline that
	// JSON-SEQ wants, so the buffer contains a complete record afterwards. We
	// buffer the whole record so that a failed encode cannot emit a truncated
	// record.
	if err := writer.enc.Encode(file); err != nil {
		return fmt.Errorf("encode manifest record: %w", err)
	}
	if _, err := writer.w.Write(writer.buf.Bytes()); err != nil {
		return fmt.Errorf("write manifest record: %w", err)
	}
	return nil
}

// WriteRoot writes the root file object of the manifest, which describes the
// directory the manifest as a whole is for and must be the first object in the
// stream. [File.MediaType] is filled in automatically.
//
// This only needs to be called if the root file object needs to contain
// something more than the defaults (such as an expiry), as [Writer.WriteFile]
// writes a default root file object if one is missing.
func (writer *Writer) WriteRoot(root *File) error {
	if writer.wroteRoot {
		return errors.New("root file object has already been written")
	}
	if root.Name != "" {
		return fmt.Errorf("root file object cannot have a name (got %q)", root.Name)
	}
	rootCopy := *root
	rootCopy.MediaType = MediaType
	if err := writer.writeRecord(&rootCopy); err != nil {
		return err
	}
	writer.wroteRoot = true
	return nil
}

// WriteFile writes a single non-root file object. If the root file object has
// not been written yet, a default one (a never-expiring directory) is written
// first. A wrapped [ErrInvalidName] error is returned if [File.Name] cannot be
// represented in a manifest.
func (writer *Writer) WriteFile(file *File) error {
	if file.MediaType != "" {
		return fmt.Errorf("non-root file object %q cannot have a mediaType (got %q)", file.Name, file.MediaType)
	}
	if err := ValidateName(file.Name); err != nil {
		return err
	}
	// Emit a default root object if the user did not explicitly define one.
	if !writer.wroteRoot {
		if err := writer.WriteRoot(&File{}); err != nil {
			return fmt.Errorf("write implied root file object: %w", err)
		}
	}
	return writer.writeRecord(file)
}

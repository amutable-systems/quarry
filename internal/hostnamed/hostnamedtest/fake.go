// Copyright (C) 2026 Amutable GmbH

package hostnamedtest

import (
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"snai.pe/go-varlink"
)

// StartFake serves a minimal in-process fake of the io.systemd.Hostname
// varlink service for the duration of the test, returning the varlink URI to
// connect to.
//
// A very minimal implementation of SetTags and Describe are included, with no
// real validation. errs maps method names (i.e., "Describe", "SetTags") to the
// error reply the fake sends for that method.
func StartFake(t *testing.T, errs map[string]varlink.Error) string {
	t.Helper()
	for method := range errs {
		if method != "Describe" && method != "SetTags" {
			t.Fatalf("StartFake: unknown method %q", method)
		}
	}

	uri := "unix:" + filepath.Join(t.TempDir(), "io.systemd.Hostname") //nolint:forbidigo // test code
	listener, err := varlink.Listen(uri)
	if err != nil {
		t.Fatalf("listen on fake hostnamed socket %s: %v", uri, err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	// Pinned in closures to track the current tags list.
	var liveTagsLock sync.RWMutex
	liveTags := make(map[string]struct{}, 256)

	var mux varlink.ServeMux
	mux.HandleFunc("io.systemd.Hostname.Describe", func(w varlink.ReplyWriter, _ *varlink.Call) {
		if err := errs["Describe"]; err != nil {
			_ = w.WriteError(err)
			return
		}

		liveTagsLock.RLock()
		currentTags := slices.Sorted(maps.Keys(liveTags))
		liveTagsLock.RUnlock()

		_ = w.WriteReply(map[string]any{
			"Hostname":  "fakehost",
			"MachineID": "0123456789abcdef0123456789abcdef",
			"MachineInformationData": []string{
				"TAGS=" + strings.Join(currentTags, ":"),
			},
			"MachineTags": currentTags,
		})
	})
	mux.HandleFunc("io.systemd.Hostname.SetTags", func(w varlink.ReplyWriter, c *varlink.Call) {
		if err := errs["SetTags"]; err != nil {
			_ = w.WriteError(err)
			return
		}

		var args struct {
			Add    []string `json:"add"`
			Remove []string `json:"remove"`
			// We don't use Set but (*varlink.Call).Unmarshal sets
			// DisallowUnknownFields and so we need to set it to avoid causing
			// spurious errors.
			Set []string `json:"set"`
		}
		if err := c.Unmarshal(&args); err != nil {
			_ = w.WriteError(err)
			return
		}

		liveTagsLock.Lock()
		// NOTE: hostnamed treats "null" as also indicating that the set should
		// be cleared but this would require a custom unmarshaller in Go so
		// just do it the easy way -- quarry doesn't use args.Set anyway.
		if args.Set != nil {
			clear(liveTags)
			for _, tag := range args.Set {
				liveTags[tag] = struct{}{}
			}
		}
		for _, tag := range args.Add {
			liveTags[tag] = struct{}{}
		}
		for _, tag := range args.Remove {
			delete(liveTags, tag)
		}
		liveTagsLock.Unlock()

		_ = w.WriteReply(nil)
	})

	srv := &varlink.Server{Handler: &mux}
	go func() { _ = srv.Serve(listener) }()

	return uri
}

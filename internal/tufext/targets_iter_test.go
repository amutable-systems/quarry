// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package tufext_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"iter"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/generics"
	"go.amutable.dev/quarry/internal/tufext"
)

// tf returns a [tufmetadata.TargetFiles] with the given Length, used as a
// distinctive identity to round-trip through the iterator.
func tf(size int64) *tufmetadata.TargetFiles {
	return &tufmetadata.TargetFiles{Length: size}
}

// dr builds a [tufmetadata.DelegatedRole]. Keys/threshold are zero-valued --
// [tufext.IterTargetFiles] does not consult them.
func dr(name string, terminating bool, paths ...string) tufmetadata.DelegatedRole {
	return tufmetadata.DelegatedRole{
		Name:        name,
		Threshold:   1,
		Terminating: terminating,
		Paths:       paths,
	}
}

// signedTargets builds a [tufext.SignedTargets]. Pass nil for delegatedRoles
// to omit the Delegations field entirely.
func signedTargets(targets map[string]*tufmetadata.TargetFiles, delegatedRoles []tufmetadata.DelegatedRole) *tufext.SignedTargets {
	st := &tufext.SignedTargets{
		Signed: tufmetadata.TargetsType{
			Type:        tufmetadata.TARGETS,
			SpecVersion: tufmetadata.SPECIFICATION_VERSION,
			Version:     1,
			Targets:     targets,
		},
	}
	if delegatedRoles != nil {
		st.Signed.Delegations = &tufmetadata.Delegations{
			Roles: delegatedRoles,
		}
	}
	return st
}

// pathsFrom collects iterator output as a path-to-metadata map, asserting no
// duplicates.
func pathsFrom(t *testing.T, targets map[string]*tufext.SignedTargets) map[string]*tufmetadata.TargetFiles {
	t.Helper()
	out := make(map[string]*tufmetadata.TargetFiles)
	got, err := generics.CollectErrorSeq(tufext.IterTargetFiles(t.Context(), tufext.TargetsMapFetcher(targets)))
	require.NoError(t, err)
	for _, td := range got {
		_, dup := out[td.Path]
		require.False(t, dup, "iterator yielded duplicate path %q", td.Path)
		out[td.Path] = td.TargetFiles
	}
	return out
}

// orderedPathsFrom returns the paths in yield order. Cross-role order is the
// pre-order DFS of the delegation tree; within-role order is unspecified.
func orderedPathsFrom(t *testing.T, targets map[string]*tufext.SignedTargets) []string {
	t.Helper()
	got, err := generics.CollectErrorSeq(tufext.IterTargetFiles(t.Context(), tufext.TargetsMapFetcher(targets)))
	require.NoError(t, err)
	out := make([]string, 0, len(got))
	for _, td := range got {
		out = append(out, td.Path)
	}
	return out
}

func TestIterTargetFiles_NoTargetsRole(t *testing.T) {
	// The algorithm starts at the "targets" role; missing it must error.
	_, err := generics.CollectErrorSeq(tufext.IterTargetFiles(t.Context(), tufext.TargetsMapFetcher(nil)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), tufmetadata.TARGETS)
}

func TestIterTargetFiles_OnlyTargets_Empty(t *testing.T) {
	got := pathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, nil),
	})
	assert.Empty(t, got)
}

func TestIterTargetFiles_OnlyTargets_Some(t *testing.T) {
	a, b := tf(1), tf(2)
	got := pathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(
			map[string]*tufmetadata.TargetFiles{"a": a, "b": b},
			nil,
		),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"a": a, "b": b}, got)
}

func TestIterTargetFiles_SimpleDelegation(t *testing.T) {
	a, b := tf(1), tf(2)
	got := pathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(
			map[string]*tufmetadata.TargetFiles{"top": a},
			[]tufmetadata.DelegatedRole{dr("d1", false, "d1/*")},
		),
		"d1": signedTargets(
			map[string]*tufmetadata.TargetFiles{"d1/file": b},
			nil,
		),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{
		"top":     a,
		"d1/file": b,
	}, got)
}

func TestIterTargetFiles_PathOutsideOwnRoleSkipped(t *testing.T) {
	// A target whose path doesn't match its own role's paths is unreachable
	// via TUF lookup and must be skipped.
	got := pathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("d1", false, "d1/*"),
		}),
		"d1": signedTargets(map[string]*tufmetadata.TargetFiles{
			"d1/in":          tf(1),
			"elsewhere/file": tf(2),
		}, nil),
	})
	assert.Equal(t, []string{"d1/in"}, keysOf(got))
}

func TestIterTargetFiles_PathMatchesAncestorButNotOwnRole(t *testing.T) {
	// Per-layer AND matching: a target that matches an ancestor's pattern but
	// not its own role's must be skipped. A flat-OR check across the whole
	// chain would wrongly accept "a/bar/y" because it matches d1's "a/*/*".
	got := pathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("d1", false, "a/*/*"),
		}),
		"d1": signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("d2", false, "a/foo/*"),
		}),
		"d2": signedTargets(map[string]*tufmetadata.TargetFiles{
			"a/bar/y": tf(1),
			"a/foo/y": tf(2),
		}, nil),
	})
	assert.Equal(t, []string{"a/foo/y"}, keysOf(got))
}

func TestIterTargetFiles_PathHitsAllAncestorPatterns(t *testing.T) {
	// Same chain but the target matches every layer's pattern.
	yielded := tf(42)
	got := pathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("d1", false, "a/*/*"),
		}),
		"d1": signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("d2", false, "a/foo/*"),
		}),
		"d2": signedTargets(map[string]*tufmetadata.TargetFiles{
			"a/foo/file": yielded,
		}, nil),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"a/foo/file": yielded}, got)
}

func TestIterTargetFiles_GlobPatterns(t *testing.T) {
	// Spec s4.5: '*' and '?' are wildcards, but neither matches '/'.
	got := pathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("d_star", false, "star/*.tgz"),
			dr("d_qmark", false, "qmark/foo-?.bin"),
		}),
		"d_star": signedTargets(map[string]*tufmetadata.TargetFiles{
			"star/foo.tgz":     tf(1), // matches
			"star/bar.tgz":     tf(2), // matches
			"star/foo.txt":     tf(3), // wrong extension
			"star/sub/foo.tgz": tf(4), // crosses path separator: must NOT match
		}, nil),
		"d_qmark": signedTargets(map[string]*tufmetadata.TargetFiles{
			"qmark/foo-1.bin":  tf(10), // matches
			"qmark/foo-a.bin":  tf(11), // matches
			"qmark/foo-ab.bin": tf(12), // ? is single-char, must NOT match
			"qmark/foo-1.txt":  tf(13), // wrong extension
		}, nil),
	})
	assert.Equal(t, map[string]struct{}{
		"star/foo.tgz":    {},
		"star/bar.tgz":    {},
		"qmark/foo-1.bin": {},
		"qmark/foo-a.bin": {},
	}, asSet(keysOf(got)))
}

func TestIterTargetFiles_LiteralPath(t *testing.T) {
	got := pathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("d1", false, "exact/file.bin"),
		}),
		"d1": signedTargets(map[string]*tufmetadata.TargetFiles{
			"exact/file.bin":   tf(1), // matches
			"exact/other.bin":  tf(2), // doesn't match
			"exact/file.bin/x": tf(3), // doesn't match
		}, nil),
	})
	assert.Equal(t, []string{"exact/file.bin"}, keysOf(got))
}

func TestIterTargetFiles_MultiplePathPatterns(t *testing.T) {
	got := pathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("d1", false, "a/*", "b/*"),
		}),
		"d1": signedTargets(map[string]*tufmetadata.TargetFiles{
			"a/foo": tf(1),
			"b/bar": tf(2),
			"c/baz": tf(3), // not in either pattern
		}, nil),
	})
	assert.Equal(t, map[string]struct{}{
		"a/foo": {},
		"b/bar": {},
	}, asSet(keysOf(got)))
}

func TestIterTargetFiles_EmptyDelegationPaths(t *testing.T) {
	// A delegation with no paths is unreachable in TUF lookup; its targets
	// must not be yielded.
	got := pathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("d1", false /* no paths */),
		}),
		"d1": signedTargets(map[string]*tufmetadata.TargetFiles{
			"anything": tf(1),
		}, nil),
	})
	assert.Empty(t, got)
}

func TestIterTargetFiles_TargetsRoleShadowsDelegated(t *testing.T) {
	// "targets" outranks any delegation: same path in both, top-level wins.
	topMeta := tf(1)
	delegMeta := tf(2)
	got := pathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(
			map[string]*tufmetadata.TargetFiles{"shared": topMeta},
			[]tufmetadata.DelegatedRole{dr("d1", false, "shared")},
		),
		"d1": signedTargets(map[string]*tufmetadata.TargetFiles{
			"shared": delegMeta,
		}, nil),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"shared": topMeta}, got)
}

func TestIterTargetFiles_EarlierDelegationShadowsLater(t *testing.T) {
	// Spec s5.6.7: delegations are processed in declared order, "which
	// implicitly orders trustworthiness".
	d1Meta := tf(1)
	d2Meta := tf(2)
	got := pathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("d1", false, "shared"),
			dr("d2", false, "shared"),
		}),
		"d1": signedTargets(map[string]*tufmetadata.TargetFiles{"shared": d1Meta}, nil),
		"d2": signedTargets(map[string]*tufmetadata.TargetFiles{"shared": d2Meta}, nil),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"shared": d1Meta}, got)
}

func TestIterTargetFiles_TerminatingBlocksLaterSiblings(t *testing.T) {
	// After a terminating delegation's subtree, no later role may claim a
	// target matching its paths. "control" is a positive control: it must
	// still appear, so a drop-everything regression can't pass this test.
	control := tf(99)
	got := pathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(
			map[string]*tufmetadata.TargetFiles{"control": control},
			[]tufmetadata.DelegatedRole{
				dr("d1", true, "a/*"),
				dr("d2", false, "a/*"),
			},
		),
		"d1": signedTargets(nil, nil),
		"d2": signedTargets(map[string]*tufmetadata.TargetFiles{
			"a/x": tf(1),
		}, nil),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"control": control}, got)
}

func TestIterTargetFiles_TerminatingDoesNotBlockUnrelatedPaths(t *testing.T) {
	bx := tf(7)
	got := pathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("d1", true, "a/*"),
			dr("d2", false, "b/*"),
		}),
		"d1": signedTargets(nil, nil),
		"d2": signedTargets(map[string]*tufmetadata.TargetFiles{"b/x": bx}, nil),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"b/x": bx}, got)
}

func TestIterTargetFiles_TerminatingAllowsDescendants(t *testing.T) {
	// Spec s4.5: a terminating role's own descendants are still processed and
	// may match paths the terminating role claimed.
	leaf := tf(99)
	got := pathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("d1", true, "a/*/*"),
		}),
		"d1": signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("e1", false, "a/foo/*"),
		}),
		"e1": signedTargets(map[string]*tufmetadata.TargetFiles{"a/foo/leaf": leaf}, nil),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"a/foo/leaf": leaf}, got)
}

func TestIterTargetFiles_TerminatingPropagatesAcrossSubtree(t *testing.T) {
	// A terminating role nested inside a non-terminating parent still blocks
	// later roles outside its parent's subtree. "control" is the positive
	// control to detect a drop-everything regression.
	control := tf(99)
	got := pathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(
			map[string]*tufmetadata.TargetFiles{"control": control},
			[]tufmetadata.DelegatedRole{
				dr("d1", false, "a/*/*"),
				dr("d2", false, "a/foo/*"),
			},
		),
		"d1": signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("e1", true, "a/foo/*"),
		}),
		"e1": signedTargets(nil, nil),
		"d2": signedTargets(map[string]*tufmetadata.TargetFiles{
			"a/foo/leaf": tf(1),
		}, nil),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"control": control}, got)
}

func TestIterTargetFiles_TerminatingDoesNotApplyWhenChainMismatchedAtRoot(t *testing.T) {
	// e1's paths don't subset its parent d1's, so a TUF lookup for "a/x"
	// would never reach e1. The terminating effect must be scoped by the
	// full ancestor chain, not just e1's own Paths -- otherwise d2's "a/x"
	// would be wrongly suppressed.
	yielded := tf(42)
	got := pathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("d1", false, "b/*"),
			dr("d2", false, "a/*"),
		}),
		"d1": signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("e1", true, "a/x"),
		}),
		"e1": signedTargets(nil, nil),
		"d2": signedTargets(map[string]*tufmetadata.TargetFiles{"a/x": yielded}, nil),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"a/x": yielded}, got)
}

func TestIterTargetFiles_TerminatingDoesNotApplyWhenChainMismatchedMidway(t *testing.T) {
	// Like the at-root variant, but the chain breaks at an intermediate
	// ancestor (d2's "b/*"), proving the chain check spans every layer, not
	// only the root.
	yielded := tf(42)
	got := pathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("d1", false, "a/*/*"),
			dr("d3", false, "a/*/*"),
		}),
		"d1": signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("d2", false, "b/*"),
		}),
		"d2": signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("e1", true, "a/foo/x"),
		}),
		"e1": signedTargets(nil, nil),
		"d3": signedTargets(map[string]*tufmetadata.TargetFiles{"a/foo/x": yielded}, nil),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"a/foo/x": yielded}, got)
}

func TestIterTargetFiles_TerminatingChainBlocksWhenFullyMatched(t *testing.T) {
	// Companion to the chain-mismatch tests: in a well-formed chain, the
	// terminating effect still fires. "control" guards against a regression
	// that drops everything.
	control := tf(99)
	got := pathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(
			map[string]*tufmetadata.TargetFiles{"control": control},
			[]tufmetadata.DelegatedRole{
				dr("d1", false, "a/*/*"),
				dr("d2", false, "a/*/*"),
			},
		),
		"d1": signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("e1", true, "a/foo/*"),
		}),
		"e1": signedTargets(nil, nil),
		"d2": signedTargets(map[string]*tufmetadata.TargetFiles{
			"a/foo/x": tf(1),
		}, nil),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"control": control}, got)
}

func TestIterTargetFiles_MultipleTerminatingChainsTrackedIndependently(t *testing.T) {
	// Two terminating delegations in disjoint subtrees: each suppresses only
	// targets matching its own chain.
	yielded := tf(7)
	got := pathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			// First subtree: terminating on "a/*".
			dr("ta", true, "a/*"),
			// Second subtree: nested terminating on "b/foo/*".
			dr("db", false, "b/*/*"),
			// Sibling that should be blocked by ta but only for its own paths.
			dr("ta-sibling", false, "a/*"),
			// Sibling that should be blocked by the nested terminating.
			dr("db-sibling", false, "b/foo/*"),
			// Wholly unrelated sibling; nothing should suppress it.
			dr("c-sibling", false, "c/*"),
		}),
		"ta": signedTargets(nil, nil),
		"db": signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("eb", true, "b/foo/*"),
		}),
		"eb":         signedTargets(nil, nil),
		"ta-sibling": signedTargets(map[string]*tufmetadata.TargetFiles{"a/blocked": tf(1)}, nil),
		"db-sibling": signedTargets(map[string]*tufmetadata.TargetFiles{"b/foo/blocked": tf(2)}, nil),
		"c-sibling":  signedTargets(map[string]*tufmetadata.TargetFiles{"c/yielded": yielded}, nil),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"c/yielded": yielded}, got)
}

func TestIterTargetFiles_CycleSelfReference(t *testing.T) {
	// d1 delegates to itself; the seen-set must prevent re-entry.
	d1Meta := tf(1)
	got := pathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("d1", false, "x/*"),
		}),
		"d1": signedTargets(
			map[string]*tufmetadata.TargetFiles{"x/file": d1Meta},
			[]tufmetadata.DelegatedRole{dr("d1", false, "x/*")},
		),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"x/file": d1Meta}, got)
}

func TestIterTargetFiles_CycleTwoRoles(t *testing.T) {
	got := pathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("d1", false, "x/*"),
		}),
		"d1": signedTargets(map[string]*tufmetadata.TargetFiles{"x/in-d1": tf(1)},
			[]tufmetadata.DelegatedRole{dr("d2", false, "x/*")},
		),
		"d2": signedTargets(map[string]*tufmetadata.TargetFiles{"x/in-d2": tf(2)},
			[]tufmetadata.DelegatedRole{dr("d1", false, "x/*")}, // closes the cycle
		),
	})
	assert.Equal(t, map[string]struct{}{
		"x/in-d1": {},
		"x/in-d2": {},
	}, asSet(keysOf(got)))
}

func TestIterTargetFiles_DiamondGraph(t *testing.T) {
	// Two parents delegate to "shared"; the seen-set ensures it's processed
	// once via whichever path reaches it first.
	got := pathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("a", false, "x/*"),
			dr("b", false, "x/*"),
		}),
		"a": signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("shared", false, "x/*"),
		}),
		"b": signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("shared", false, "x/*"),
		}),
		"shared": signedTargets(map[string]*tufmetadata.TargetFiles{
			"x/file": tf(1),
		}, nil),
	})
	assert.Equal(t, []string{"x/file"}, keysOf(got))
}

func TestIterTargetFiles_PreOrderDepthFirst(t *testing.T) {
	// Spec s5.6.7: pre-order DFS in declared order. One target per role
	// keeps within-role map-iteration randomness from scrambling the order.
	got := orderedPathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(
			map[string]*tufmetadata.TargetFiles{"top": tf(0)},
			[]tufmetadata.DelegatedRole{
				dr("a", false, "a/*"),
				dr("b", false, "b/*"),
			},
		),
		"a": signedTargets(
			map[string]*tufmetadata.TargetFiles{"a/self": tf(0)},
			[]tufmetadata.DelegatedRole{
				dr("a-1", false, "a/1"),
				dr("a-2", false, "a/2"),
			},
		),
		"a-1": signedTargets(map[string]*tufmetadata.TargetFiles{"a/1": tf(0)}, nil),
		"a-2": signedTargets(map[string]*tufmetadata.TargetFiles{"a/2": tf(0)}, nil),
		"b":   signedTargets(map[string]*tufmetadata.TargetFiles{"b/self": tf(0)}, nil),
	})
	assert.Equal(t, []string{
		"top",
		"a/self",
		"a/1",
		"a/2",
		"b/self",
	}, got)
}

func TestIterTargetFiles_MissingDelegatedRole(t *testing.T) {
	_, err := generics.CollectErrorSeq(tufext.IterTargetFiles(t.Context(), tufext.TargetsMapFetcher(map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("missing", false, "x/*"),
		}),
	})))
	require.Error(t, err)
	assert.ErrorIs(t, err, fs.ErrNotExist) //nolint:testifylint // assert is fine for error path checks
	assert.Contains(t, err.Error(), "missing")
}

func TestIterTargetFiles_PathHashPrefixes(t *testing.T) {
	role := dr("d1", false)
	role.PathHashPrefixes = []string{"abcd"}
	_, err := generics.CollectErrorSeq(tufext.IterTargetFiles(t.Context(), tufext.TargetsMapFetcher(map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{role}),
		"d1":                signedTargets(nil, nil),
	})))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "uses path prefixes")
}

func TestIterTargetFiles_SuccinctRoles(t *testing.T) {
	st := signedTargets(nil, nil)
	st.Signed.Delegations = &tufmetadata.Delegations{
		SuccinctRoles: &tufmetadata.SuccinctRoles{BitLength: 4, NamePrefix: "bin"},
	}
	_, err := generics.CollectErrorSeq(tufext.IterTargetFiles(t.Context(), tufext.TargetsMapFetcher(map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: st,
	})))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "succinct roles")
}

func TestIterTargetFiles_MaxDelegationsCap(t *testing.T) {
	// Linear chain of 130 delegations exceeds the 128 cap. To match go-tuf
	// and avoid DoS amplification on long-chain inputs, hitting the cap
	// stops iteration cleanly without an error. Targets beyond the cap are
	// silently dropped; targets within it are still yielded.
	//
	// TARGETS is the 1st role processed; r_i is the (i+2)th. The cap permits
	// processing while len(seen) < 128, so r126 is the last role processed
	// (seen=127 on entry, seen=128 after) and r127 onwards are skipped.
	const linearLen = 130
	all := make(map[string]*tufext.SignedTargets, linearLen+1)
	all[tufmetadata.TARGETS] = signedTargets(
		map[string]*tufmetadata.TargetFiles{"x/start": tf(1)},
		[]tufmetadata.DelegatedRole{dr("r0", false, "x/*")},
	)
	for i := 0; i < linearLen-1; i++ {
		var targets map[string]*tufmetadata.TargetFiles
		switch i {
		case 126:
			targets = map[string]*tufmetadata.TargetFiles{"x/at-cap": tf(2)}
		case 127:
			targets = map[string]*tufmetadata.TargetFiles{"x/over-cap": tf(3)}
		}
		all[fmt.Sprintf("r%d", i)] = signedTargets(targets, []tufmetadata.DelegatedRole{
			dr(fmt.Sprintf("r%d", i+1), false, "x/*"),
		})
	}
	all[fmt.Sprintf("r%d", linearLen-1)] = signedTargets(nil, nil)

	got, err := generics.CollectErrorSeq(tufext.IterTargetFiles(t.Context(), tufext.TargetsMapFetcher(all)))
	require.NoError(t, err, "exceeding the cap must not produce an error")

	paths := make(map[string]struct{}, len(got))
	for _, td := range got {
		paths[td.Path] = struct{}{}
	}
	assert.Contains(t, paths, "x/start")
	assert.Contains(t, paths, "x/at-cap")
	assert.NotContains(t, paths, "x/over-cap")
}

func TestIterTargetFiles_Reusable(t *testing.T) {
	// The returned iter.Seq2 must be safe to range over more than once.
	a, b := tf(1), tf(2)
	seq := tufext.IterTargetFiles(t.Context(), tufext.TargetsMapFetcher(map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(map[string]*tufmetadata.TargetFiles{
			"a": a,
			"b": b,
		}, nil),
	}))
	for range 2 {
		got, err := generics.CollectErrorSeq(seq)
		require.NoError(t, err)
		gotMap := make(map[string]*tufmetadata.TargetFiles, len(got))
		for _, td := range got {
			gotMap[td.Path] = td.TargetFiles
		}
		assert.Equal(t, map[string]*tufmetadata.TargetFiles{"a": a, "b": b}, gotMap)
	}
}

func TestIterTargetFiles_EarlyTermination(t *testing.T) {
	// Wrapper counts producer yields. If the producer ignores the stop
	// signal after the consumer breaks, the counter would exceed 1; the
	// 5-target input gives it plenty of values to overrun on.
	in := map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(map[string]*tufmetadata.TargetFiles{
			"a": tf(1), "b": tf(2), "c": tf(3), "d": tf(4), "e": tf(5),
		}, nil),
	}

	underlying := tufext.IterTargetFiles(t.Context(), tufext.TargetsMapFetcher(in))
	var producerYields int
	counted := iter.Seq2[tufext.TargetFileData, error](func(yield func(tufext.TargetFileData, error) bool) {
		for td, err := range underlying {
			producerYields++
			if !yield(td, err) {
				return
			}
		}
	})

	for td, err := range counted {
		_ = td
		require.NoError(t, err)
		break
	}
	assert.Equal(t, 1, producerYields, "producer must stop after the consumer breaks")
}

func TestIterTargetFiles_DeepDelegationsWithSiblings(t *testing.T) {
	// Regression for a patternChain aliasing bug: when a parent's slice has
	// cap > len, two siblings' appends share a backing array and the second
	// clobbers the first. Whether cap > len holds at a given depth is a Go
	// runtime detail, so we sweep several depths to stay robust against
	// growth-strategy changes (today, depths 3/5/6/7 trigger; 4/8/16 don't).
	for _, depth := range []int{2, 3, 4, 5, 6, 7, 8, 16} {
		t.Run(fmt.Sprintf("depth=%d", depth), func(t *testing.T) {
			leafA := tf(int64(depth)*10 + 1)
			leafB := tf(int64(depth)*10 + 2)
			all := map[string]*tufext.SignedTargets{}

			// targets -> r0 -> r1 -> ... -> r(depth-1) -> {leafA, leafB}.
			all[tufmetadata.TARGETS] = signedTargets(nil, []tufmetadata.DelegatedRole{
				dr("r0", false, "shared/*"),
			})
			for i := 0; i < depth-1; i++ {
				all[fmt.Sprintf("r%d", i)] = signedTargets(nil, []tufmetadata.DelegatedRole{
					dr(fmt.Sprintf("r%d", i+1), false, "shared/*"),
				})
			}
			all[fmt.Sprintf("r%d", depth-1)] = signedTargets(nil, []tufmetadata.DelegatedRole{
				dr("leafA", false, "shared/A"),
				dr("leafB", false, "shared/B"),
			})
			all["leafA"] = signedTargets(map[string]*tufmetadata.TargetFiles{"shared/A": leafA}, nil)
			all["leafB"] = signedTargets(map[string]*tufmetadata.TargetFiles{"shared/B": leafB}, nil)

			got := pathsFrom(t, all)
			assert.Equal(t, map[string]*tufmetadata.TargetFiles{
				"shared/A": leafA,
				"shared/B": leafB,
			}, got)
		})
	}
}

func TestIterTargetFiles_BreakAfterError(t *testing.T) {
	// Breaking after an error yield must be safe, and the seq must remain
	// reusable on a fresh range loop. ErrorIter yields the error once and
	// returns, so observed == 1 in both passes.
	in := map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("missing", false, "x/*"),
		}),
	}
	seq := tufext.IterTargetFiles(t.Context(), tufext.TargetsMapFetcher(in))

	// First pass: break immediately after the error.
	var sawError bool
	var observed int
	for _, err := range seq {
		observed++
		if err != nil {
			sawError = true
			break
		}
	}
	require.True(t, sawError)
	assert.Equal(t, 1, observed, "ErrorIter delivers the error in a single yield")

	// Second pass: do not break, confirm no further values appear.
	sawError = false
	observed = 0
	for _, err := range seq {
		observed++
		if err != nil {
			sawError = true
		}
	}
	require.True(t, sawError)
	assert.Equal(t, 1, observed)
}

func TestIterTargetFiles_PathFieldMatchesMapKey(t *testing.T) {
	// Without going through pathsFrom: yielded Path equals the input map
	// key and the embedded pointer is the same *TargetFiles the caller put in.
	a, b := tf(1), tf(2)
	in := map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(map[string]*tufmetadata.TargetFiles{
			"alpha": a,
			"b/eta": b,
		}, nil),
	}
	got, err := generics.CollectErrorSeq(tufext.IterTargetFiles(t.Context(), tufext.TargetsMapFetcher(in)))
	require.NoError(t, err)
	require.Len(t, got, 2)

	for _, td := range got {
		switch td.Path {
		case "alpha":
			assert.Same(t, a, td.TargetFiles)
		case "b/eta":
			assert.Same(t, b, td.TargetFiles)
		default:
			t.Errorf("yielded unexpected path %q", td.Path)
		}
	}
}

func TestIterTargetFiles_FetcherReceivesDelegatorContext(t *testing.T) {
	// The fetcher receives (roleName, delegatorName) pairs. Per s5.6.7, the
	// top-level "targets" role is delegated by "root"; each subsequent role
	// names its parent delegator. The order also follows pre-order DFS.
	type call struct{ role, delegator string }
	var calls []call
	fetch := func(_ context.Context, roleName, delegatorName string) (*tufext.SignedTargets, error) {
		calls = append(calls, call{roleName, delegatorName})
		switch roleName {
		case tufmetadata.TARGETS:
			return signedTargets(nil, []tufmetadata.DelegatedRole{dr("d1", false, "x/y")}), nil
		case "d1":
			return signedTargets(nil, []tufmetadata.DelegatedRole{dr("d2", false, "x/y")}), nil
		case "d2":
			return signedTargets(map[string]*tufmetadata.TargetFiles{"x/y": tf(1)}, nil), nil
		}
		return nil, fmt.Errorf("unexpected fetch %q", roleName)
	}
	_, err := generics.CollectErrorSeq(tufext.IterTargetFiles(t.Context(), fetch))
	require.NoError(t, err)
	assert.Equal(t, []call{
		{tufmetadata.TARGETS, tufmetadata.ROOT},
		{"d1", tufmetadata.TARGETS},
		{"d2", "d1"},
	}, calls)
}

func TestIterTargetFiles_FetcherErrorSurfaces(t *testing.T) {
	// A fetcher error must be returned to the caller, wrapped with the role
	// name for context.
	sentinel := errors.New("fetcher boom")
	fetch := func(_ context.Context, roleName, _ string) (*tufext.SignedTargets, error) {
		if roleName == tufmetadata.TARGETS {
			return signedTargets(nil, []tufmetadata.DelegatedRole{dr("d1", false, "x/*")}), nil
		}
		return nil, sentinel
	}
	_, err := generics.CollectErrorSeq(tufext.IterTargetFiles(t.Context(), fetch))
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel) //nolint:testifylint // assert is fine for error path checks
	assert.Contains(t, err.Error(), "d1", "wrapped error must name the failing role")
}

func TestIterTargetFiles_FetcherSeesContext(t *testing.T) {
	// The context passed to IterTargetFiles is plumbed through to the
	// fetcher. Cancellation surfaced by the fetcher propagates as the
	// iterator's error.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	fetch := func(ctx context.Context, _, _ string) (*tufext.SignedTargets, error) {
		return nil, ctx.Err()
	}
	_, err := generics.CollectErrorSeq(tufext.IterTargetFiles(ctx, fetch))
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestIterTargetFiles_FetcherCalledOncePerRole(t *testing.T) {
	// Diamond graph: "shared" is delegated by both "a" and "b". The seen-set
	// must ensure the fetcher is invoked at most once per distinct role.
	counts := map[string]int{}
	fetch := func(_ context.Context, roleName, _ string) (*tufext.SignedTargets, error) {
		counts[roleName]++
		switch roleName {
		case tufmetadata.TARGETS:
			return signedTargets(nil, []tufmetadata.DelegatedRole{
				dr("a", false, "x/*"),
				dr("b", false, "x/*"),
			}), nil
		case "a", "b":
			return signedTargets(nil, []tufmetadata.DelegatedRole{dr("shared", false, "x/*")}), nil
		case "shared":
			return signedTargets(map[string]*tufmetadata.TargetFiles{"x/file": tf(1)}, nil), nil
		}
		return nil, fmt.Errorf("unexpected fetch %q", roleName)
	}
	got, err := generics.CollectErrorSeq(tufext.IterTargetFiles(t.Context(), fetch))
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, map[string]int{
		tufmetadata.TARGETS: 1,
		"a":                 1,
		"b":                 1,
		"shared":            1,
	}, counts)
}

// keysOf returns the sorted keys. The iterator's within-role order is
// unspecified, so most tests compare sorted slices or sets.
func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func asSet(s []string) map[string]struct{} {
	out := make(map[string]struct{}, len(s))
	for _, v := range s {
		out[v] = struct{}{}
	}
	return out
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package tufext_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"iter"
	"slices"
	"strings"
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

func TestIterTargetFiles_MalformedPatternNeverMatches(t *testing.T) {
	// See TestDelegationChain_MalformedPatternNeverMatches. A target whose
	// delegation pattern is a malformed glob must not be yielded, even when
	// the path is byte-for-byte equal to the pattern. "control" guards
	// against a drop-everything regression.
	control := tf(99)
	got := pathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(
			map[string]*tufmetadata.TargetFiles{"control": control},
			[]tufmetadata.DelegatedRole{dr("d1", false, "a/[b")},
		),
		"d1": signedTargets(map[string]*tufmetadata.TargetFiles{
			"a/[b": tf(1),
			"a/b":  tf(2),
		}, nil),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"control": control}, got)
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

func TestIterTargetFiles_TerminatingAppliesEvenIfRoleSkippedByCycle(t *testing.T) {
	// go-tuf stops considering later roles the moment it *encounters* a
	// matching terminating delegation in a parent's list (s5.6.7.2.1), before
	// visiting the role. So the marker must be pushed when the delegation is
	// seen, not when the role is processed. Here "a" delegates terminatingly
	// to itself: the second visit is skipped as a cycle, and "b" must still
	// be blocked. "control" and "x/in-a" are positive controls.
	control, inA := tf(99), tf(1)
	got := pathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(
			map[string]*tufmetadata.TargetFiles{"control": control},
			[]tufmetadata.DelegatedRole{
				dr("a", false, "x/*"),
				dr("b", false, "x/*"),
			},
		),
		"a": signedTargets(
			map[string]*tufmetadata.TargetFiles{"x/in-a": inA},
			[]tufmetadata.DelegatedRole{dr("a", true, "x/*")},
		),
		"b": signedTargets(map[string]*tufmetadata.TargetFiles{"x/from-b": tf(2)}, nil),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"control": control, "x/in-a": inA}, got)
}

func TestIterTargetFiles_TerminatingOnSecondPathBlocksLaterSiblings(t *testing.T) {
	// Diamond variant of the above: "shared" is reached via "a"
	// (non-terminating) and again via "b" (terminating); cycle detection is
	// per path, so the second visit is walked rather than skipped. A go-tuf
	// lookup for x/from-c clears its stack on encountering b's terminating
	// delegation, so "c" is never consulted, and the marker must apply after
	// the second visit's subtree however that visit is handled.
	control := tf(99)
	got := pathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(
			map[string]*tufmetadata.TargetFiles{"control": control},
			[]tufmetadata.DelegatedRole{
				dr("a", false, "x/*"),
				dr("b", false, "x/*"),
				dr("c", false, "x/*"),
			},
		),
		"a":      signedTargets(nil, []tufmetadata.DelegatedRole{dr("shared", false, "x/*")}),
		"b":      signedTargets(nil, []tufmetadata.DelegatedRole{dr("shared", true, "x/*")}),
		"shared": signedTargets(nil, nil),
		"c":      signedTargets(map[string]*tufmetadata.TargetFiles{"x/from-c": tf(1)}, nil),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"control": control}, got)
}

func TestIterTargetFiles_TerminatingAppliesEvenIfRoleSkippedByDepthCap(t *testing.T) {
	// Companion to TerminatingAppliesEvenIfRoleSkippedByCycle for the other
	// reason a role can be skipped: r31 delegates terminatingly to r32, which
	// sits past the depth cap and is never walked. go-tuf clears its stack on
	// encountering the terminating delegation (and gives up at its own cap
	// right after), so the later top-level sibling "b" must still be blocked
	// for x/*. "control" is the positive control.
	const depth = 33 // r32 has a chain of length 33 > maxDelegationDepth
	control := tf(99)
	all := map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(
			map[string]*tufmetadata.TargetFiles{"control": control},
			[]tufmetadata.DelegatedRole{
				dr("r0", false, "x/*"),
				dr("b", false, "x/*"),
			},
		),
		"b": signedTargets(map[string]*tufmetadata.TargetFiles{"x/from-b": tf(2)}, nil),
	}
	for i := 0; i < depth-1; i++ {
		all[fmt.Sprintf("r%d", i)] = signedTargets(nil, []tufmetadata.DelegatedRole{
			dr(fmt.Sprintf("r%d", i+1), i == depth-2, "x/*"), // only r31 -> r32 terminates
		})
	}
	all[fmt.Sprintf("r%d", depth-1)] = signedTargets(map[string]*tufmetadata.TargetFiles{"x/deep": tf(3)}, nil)

	got := pathsFrom(t, all)
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"control": control}, got)
}

func TestIterTargetFiles_CycleSelfReference(t *testing.T) {
	// d1 delegates to itself; the per-path cycle check must prevent re-entry.
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
	// Two parents delegate to "shared". It is walked once per delegation
	// path, but the target is yielded once: the first path to reach it wins.
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

func TestIterTargetFiles_DiamondDifferentPatterns(t *testing.T) {
	// "shared" is reachable via "a" (x/*) and via "b" (y/*). A real lookup
	// for "y/file" never descends into "a", so it reaches "shared" through
	// "b" and succeeds. A global visited set would have walked "shared" via
	// "a" only, rejected "y/file" against a's chain and never come back;
	// per-path cycle detection walks it again via "b".
	xf, yf := tf(1), tf(2)
	got := pathsFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("a", false, "x/*"),
			dr("b", false, "y/*"),
		}),
		"a": signedTargets(nil, []tufmetadata.DelegatedRole{dr("shared", false, "x/*", "y/*")}),
		"b": signedTargets(nil, []tufmetadata.DelegatedRole{dr("shared", false, "x/*", "y/*")}),
		"shared": signedTargets(map[string]*tufmetadata.TargetFiles{
			"x/file": xf,
			"y/file": yf,
		}, nil),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"x/file": xf, "y/file": yf}, got)
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

func TestIterTargetFiles_PathHashPrefixes_Rejected(t *testing.T) {
	// DelegationChain.IsTargetPermitted can evaluate hash-bin delegations (see
	// TestDelegationChain_PathHashPrefixes_Smoke), but IterTargetFiles
	// refuses to walk them while go-tuf's digest encoding is non-conformant
	// (see the NOTE on hashPrefix): a conformant repository would otherwise
	// be mis-binned identically by us and by the go-tuf client. The error
	// must fire wherever the delegation appears, not only at the top level.
	bin := dr("bin", false /* no paths */)
	bin.PathHashPrefixes = []string{hashPrefix("bins/x")}

	for _, tc := range []struct {
		name    string
		targets map[string]*tufext.SignedTargets
	}{
		{
			name: "top-level",
			targets: map[string]*tufext.SignedTargets{
				tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{bin}),
				"bin":               signedTargets(nil, nil),
			},
		},
		{
			name: "nested",
			targets: map[string]*tufext.SignedTargets{
				tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{dr("d1", false, "bins/*")}),
				"d1":                signedTargets(nil, []tufmetadata.DelegatedRole{bin}),
				"bin":               signedTargets(nil, nil),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := generics.CollectErrorSeq(tufext.IterTargetFiles(t.Context(), tufext.TargetsMapFetcher(tc.targets)))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "uses path prefixes")
			assert.Contains(t, err.Error(), "bin", "error must name the offending role")
		})
	}
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

func TestIterTargetFiles_MaxDelegationDepth(t *testing.T) {
	// A chain deeper than go-tuf's default MaxDelegations (32) can never be
	// reached by a real lookup, so roles past that depth are skipped without
	// an error. go-tuf's loop runs while visited <= 32, so it walks 33 roles
	// down a pure chain: "targets" plus r0..r31. r_i has a chain of length
	// i+1 and is skipped once that exceeds 32, so r31 is the last role walked
	// and r32 onwards are dropped.
	//
	// The depth cap only prunes the over-deep branch: a sibling declared
	// after it must still be walked, unlike the total cap (see
	// TestIterTargetFiles_MaxDelegationsTotal).
	const linearLen = 40
	all := make(map[string]*tufext.SignedTargets, linearLen+2)
	all[tufmetadata.TARGETS] = signedTargets(
		map[string]*tufmetadata.TargetFiles{"x/start": tf(1)},
		[]tufmetadata.DelegatedRole{
			dr("r0", false, "x/*"),
			dr("shallow", false, "y/*"),
		},
	)
	for i := 0; i < linearLen-1; i++ {
		var targets map[string]*tufmetadata.TargetFiles
		switch i {
		case 31:
			targets = map[string]*tufmetadata.TargetFiles{"x/at-cap": tf(2)}
		case 32:
			targets = map[string]*tufmetadata.TargetFiles{"x/over-cap": tf(3)}
		}
		all[fmt.Sprintf("r%d", i)] = signedTargets(targets, []tufmetadata.DelegatedRole{
			dr(fmt.Sprintf("r%d", i+1), false, "x/*"),
		})
	}
	all[fmt.Sprintf("r%d", linearLen-1)] = signedTargets(nil, nil)
	all["shallow"] = signedTargets(map[string]*tufmetadata.TargetFiles{"y/shallow": tf(4)}, nil)

	got, err := generics.CollectErrorSeq(tufext.IterTargetFiles(t.Context(), tufext.TargetsMapFetcher(all)))
	require.NoError(t, err, "exceeding the depth cap must not produce an error")

	paths := make(map[string]struct{}, len(got))
	for _, td := range got {
		paths[td.Path] = struct{}{}
	}
	assert.Contains(t, paths, "x/start")
	assert.Contains(t, paths, "x/at-cap")
	assert.NotContains(t, paths, "x/over-cap")
	assert.Contains(t, paths, "y/shallow", "the depth cap must only prune the deep branch")
}

func TestIterTargetFiles_MaxDelegationsTotal(t *testing.T) {
	// Roles are no longer deduplicated globally, so a repository could make
	// the walk revisit a modest tree an enormous number of times. A hard cap
	// on fetched roles stops the walk, without an error, once reached. Unlike
	// the depth cap this ends the whole walk: nothing declared after the
	// cut-off is visited. The fetcher synthesises roles on demand so the
	// fixture stays small.
	const (
		totalCap = 4096
		fanOut   = totalCap + 100
	)
	roles := make([]tufmetadata.DelegatedRole, 0, fanOut)
	for i := range fanOut {
		roles = append(roles, dr(fmt.Sprintf("c%d", i), false, "c/*"))
	}
	var fetches int
	fetch := func(_ context.Context, roleName, _ string) (*tufext.SignedTargets, error) {
		fetches++
		if roleName == tufmetadata.TARGETS {
			return signedTargets(nil, roles), nil
		}
		if !strings.HasPrefix(roleName, "c") {
			return nil, fmt.Errorf("unexpected fetch %q", roleName)
		}
		return signedTargets(map[string]*tufmetadata.TargetFiles{"c/" + roleName: tf(1)}, nil), nil
	}
	got, err := generics.CollectErrorSeq(tufext.IterTargetFiles(t.Context(), fetch))
	require.NoError(t, err, "hitting the total cap must not produce an error")

	// "targets" is the first fetch, so totalCap-1 children are walked, in
	// declared order, before the cap trips.
	assert.Equal(t, totalCap, fetches)
	assert.Len(t, got, totalCap-1)
	paths := make(map[string]struct{}, len(got))
	for _, td := range got {
		paths[td.Path] = struct{}{}
	}
	assert.Contains(t, paths, "c/c0")
	assert.Contains(t, paths, fmt.Sprintf("c/c%d", totalCap-2))
	assert.NotContains(t, paths, fmt.Sprintf("c/c%d", totalCap-1))
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
	// Regression for a chain aliasing bug: siblings derived from the same
	// parent shared the parent's backing storage (a slice with cap > len at
	// the time), so the second sibling clobbered the first. The chain is now
	// map-backed, but the depth sweep is cheap and guards the property
	// regardless of representation.
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

func TestIterTargetFiles_FetcherCalledOncePerDelegationPath(t *testing.T) {
	// Diamond graph: "shared" is delegated by both "a" and "b". Cycle
	// detection is per delegation path (spec issue 321), not global, so
	// "shared" is fetched once per path, each time naming the delegator that
	// path came through, in pre-order DFS order. The target is still yielded
	// once: the first path wins.
	type call struct{ role, delegator string }
	var calls []call
	fetch := func(_ context.Context, roleName, delegatorName string) (*tufext.SignedTargets, error) {
		calls = append(calls, call{roleName, delegatorName})
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
	assert.Equal(t, []call{
		{tufmetadata.TARGETS, tufmetadata.ROOT},
		{"a", tufmetadata.TARGETS},
		{"shared", "a"},
		{"b", tufmetadata.TARGETS},
		{"shared", "b"},
	}, calls)
}

// chainOf builds a [tufext.DelegationChain] from the given delegations,
// ordered from the delegation closest to "targets" down to the leaf. Each
// link is recorded under the role that made the delegation: "targets" for the
// first, then the previous link's role name, mirroring how IterTargetFiles
// builds chains.
func chainOf(delegations ...tufmetadata.DelegatedRole) tufext.DelegationChain {
	var chain tufext.DelegationChain
	fromRole := tufmetadata.TARGETS
	for _, delegation := range delegations {
		chain = chain.Extend(fromRole, &delegation)
		fromRole = delegation.Name
	}
	return chain
}

// hashPrefixLen is long enough that two arbitrary test paths landing in the
// same bin is not a realistic concern.
const hashPrefixLen = 8

// hashPrefix returns a PathHashPrefixes entry that go-tuf will treat as
// covering path: the first hashPrefixLen characters of the base64url-encoded
// SHA-256 digest of path.
//
// NOTE: base64url mirrors go-tuf's IsDelegatedPath, which deviates from the
// TUF specification (s4.5 says PATH_HASH_PREFIXES are prefixes of the
// hexadecimal digest, which is what python-tuf and go-tuf v1 implement). If
// go-tuf is fixed to use hex, this helper must change with it.
// <https://github.com/theupdateframework/go-tuf/security/advisories/GHSA-3r3c-54j3-3j69>
func hashPrefix(path string) string {
	sum := sha256.Sum256([]byte(path))
	return base64.URLEncoding.EncodeToString(sum[:])[:hashPrefixLen]
}

func TestDelegationChain_ZeroValueMatchesEverything(t *testing.T) {
	// An empty chain represents the top-level "targets" role, which has
	// authority over every path.
	var chain tufext.DelegationChain
	for _, path := range []string{"", "a", "a/b", "deep/er/path.bin"} {
		assert.True(t, chain.IsTargetPermitted(path), "path %q", path)
	}
}

func TestDelegationChain_SingleLink(t *testing.T) {
	chain := chainOf(dr("d1", false, "a/*"))
	assert.True(t, chain.IsTargetPermitted("a/x"))
	assert.False(t, chain.IsTargetPermitted("b/x"), "wrong directory")
	assert.False(t, chain.IsTargetPermitted("a/x/y"), "'*' must not cross '/'")
	assert.False(t, chain.IsTargetPermitted("a"), "component count must match")
}

func TestDelegationChain_PatternsWithinLinkAreOr(t *testing.T) {
	chain := chainOf(dr("d1", false, "a/*", "b/*"))
	assert.True(t, chain.IsTargetPermitted("a/x"))
	assert.True(t, chain.IsTargetPermitted("b/x"))
	assert.False(t, chain.IsTargetPermitted("c/x"))
}

func TestDelegationChain_LinksAreAnd(t *testing.T) {
	// Every link in the chain must match: a path that satisfies the ancestor
	// but not the leaf (or vice versa) is not authorised.
	chain := chainOf(
		dr("d1", false, "a/*/*"),
		dr("d2", false, "a/foo/*"),
	)
	assert.True(t, chain.IsTargetPermitted("a/foo/x"))
	assert.False(t, chain.IsTargetPermitted("a/bar/x"), "matches ancestor only")
	assert.False(t, chain.IsTargetPermitted("b/foo/x"), "matches neither")

	// A leaf whose patterns are wider than its parent's is clamped by the
	// parent.
	wide := chainOf(
		dr("d1", false, "a/foo/*"),
		dr("d2", false, "a/*/*"),
	)
	assert.True(t, wide.IsTargetPermitted("a/foo/x"))
	assert.False(t, wide.IsTargetPermitted("a/bar/x"), "matches leaf only")
}

func TestDelegationChain_LinkWithoutPathsMatchesNothing(t *testing.T) {
	// Unlike an empty chain, a chain containing a delegation with no paths
	// (and no hash prefixes) can never match: that role was delegated
	// nothing.
	chain := chainOf(dr("d1", false /* no paths */))
	assert.False(t, chain.IsTargetPermitted(""))
	assert.False(t, chain.IsTargetPermitted("a"))
	assert.False(t, chain.IsTargetPermitted("a/b"))

	// This holds even when sandwiched between links that do match.
	middle := chainOf(
		dr("d1", false, "a/*"),
		dr("d2", false /* no paths */),
		dr("d3", false, "a/*"),
	)
	assert.False(t, middle.IsTargetPermitted("a/x"))
}

func TestDelegationChain_ExtendNarrowsAuthority(t *testing.T) {
	// Each appended link is one more pattern the path must satisfy, so a
	// longer chain never authorises more than the chain it was derived from.
	// Chains are immutable: Extend derives a new one and leaves the
	// receiver untouched.
	var root tufext.DelegationChain
	require.True(t, root.IsTargetPermitted("b/x"))

	d1 := dr("d1", false, "a/*")
	one := root.Extend(tufmetadata.TARGETS, &d1)
	assert.True(t, one.IsTargetPermitted("a/x"))
	assert.False(t, one.IsTargetPermitted("b/x"))
	assert.True(t, root.IsEmpty(), "receiver must be untouched")
	assert.True(t, root.IsTargetPermitted("b/x"), "receiver must be untouched")

	d2 := dr("d2", false, "a/y")
	two := one.Extend("d1", &d2)
	assert.True(t, two.IsTargetPermitted("a/y"))
	assert.False(t, two.IsTargetPermitted("a/x"))
	assert.Equal(t, 2, two.Length())
	assert.Equal(t, 1, one.Length(), "receiver must be untouched")
	assert.True(t, one.IsTargetPermitted("a/x"), "receiver must be untouched")
}

func TestDelegationChain_IsEmpty(t *testing.T) {
	// Only the root "targets" role has an empty chain, so IsEmpty is how a
	// consumer tells "unrestricted" apart from "restricted to these paths".
	var chain tufext.DelegationChain
	assert.True(t, chain.IsEmpty(), "zero value")

	d1 := dr("d1", false, "a/*")
	child := chain.Extend(tufmetadata.TARGETS, &d1)
	assert.False(t, child.IsEmpty(), "Extend result")
	assert.True(t, chain.IsEmpty(), "Extend must not touch the receiver")
	assert.False(t, child.Extend("d1", &d1).IsEmpty(), "extending a non-empty chain")
}

func TestDelegationChain_ContainsAndLength(t *testing.T) {
	// A chain records the roles that *delegated* along the path, keyed by
	// delegator, so the leaf itself is never a member. IterTargetFiles relies
	// on exactly this for cycle detection: a role is skipped only if it has
	// already delegated on the current path.
	var chain tufext.DelegationChain
	assert.Equal(t, 0, chain.Length())
	assert.False(t, chain.Contains(tufmetadata.TARGETS))

	chain = chainOf(dr("d1", false, "a/*"), dr("d2", false, "a/*")) // targets -> d1 -> d2
	assert.Equal(t, 2, chain.Length())
	assert.True(t, chain.Contains(tufmetadata.TARGETS))
	assert.True(t, chain.Contains("d1"))
	assert.False(t, chain.Contains("d2"), "the leaf has not delegated anything on this path")
	assert.False(t, chain.Contains("unrelated"))
}

func TestDelegationChain_DuplicateDelegatorPanics(t *testing.T) {
	// A path can only pass through a delegator once, so a second delegation
	// under the same role is a programming error rather than a metadata
	// error, and the failed append must leave the receiver untouched.
	d1 := dr("d1", false, "a/*")
	d2 := dr("d2", false, "a/*")
	chain := chainOf(d1) // {targets: d1}
	assert.Panics(t, func() { _ = chain.Extend(tufmetadata.TARGETS, &d2) })
	assert.Equal(t, 1, chain.Length())

	// A different delegator is fine.
	var longer tufext.DelegationChain
	assert.NotPanics(t, func() { longer = chain.Extend("d1", &d2) })
	assert.Equal(t, 2, longer.Length())
	assert.Equal(t, 1, chain.Length())
}

func TestDelegationChain_ExtendNilIsNoop(t *testing.T) {
	// A nil delegation is dropped rather than stored, so Match never has to
	// dereference it (which would panic inside go-tuf) and the chain's
	// authority is unchanged. The nil check also precedes the duplicate
	// delegator check, so a nil under an already-used delegator must not
	// panic either.
	var empty tufext.DelegationChain
	stillEmpty := empty.Extend(tufmetadata.TARGETS, nil)
	assert.True(t, stillEmpty.IsEmpty())
	assert.True(t, stillEmpty.IsTargetPermitted("anything/at/all"))

	d1 := dr("d1", false, "a/*")
	restricted := chainOf(d1) // {targets: d1}
	var same tufext.DelegationChain
	assert.NotPanics(t, func() { same = restricted.Extend(tufmetadata.TARGETS, nil) })
	assert.Equal(t, 1, same.Length())
	assert.True(t, same.IsTargetPermitted("a/x"))
	assert.False(t, same.IsTargetPermitted("b/x"))

	// A nil in the middle of a sequence of appends must not poison the
	// links either side of it.
	d2 := dr("d2", false, "a/y")
	longer := restricted.Extend("d1", nil).Extend("d1", &d2)
	assert.Equal(t, 2, longer.Length())
	assert.True(t, longer.IsTargetPermitted("a/y"))
	assert.False(t, longer.IsTargetPermitted("a/x"))
}

func TestDelegationChain_ExtendDoesNotAliasSiblings(t *testing.T) {
	// Companion to TestIterTargetFiles_DeepDelegationsWithSiblings at the
	// DelegationChain level: two siblings derived from the same parent get
	// their own storage and the parent is untouched. Both siblings are
	// appended under the same delegator, so shared storage would either
	// clobber one leaf or trip the duplicate-delegator check. This is also
	// what exercises the unexported clone: Extend clones before
	// appending, so a clone that shared the map would fail here.
	parent := chainOf(dr("p", false, "shared/*")) // {targets: p}
	leafA := dr("leafA", false, "shared/A")
	leafB := dr("leafB", false, "shared/B")
	a := parent.Extend("p", &leafA)
	b := parent.Extend("p", &leafB)

	assert.True(t, a.IsTargetPermitted("shared/A"))
	assert.False(t, a.IsTargetPermitted("shared/B"), "sibling B clobbered A's leaf")
	assert.True(t, b.IsTargetPermitted("shared/B"))
	assert.False(t, b.IsTargetPermitted("shared/A"), "sibling A clobbered B's leaf")

	// The parent has no leaf restriction and must accept both.
	assert.Equal(t, 1, parent.Length())
	assert.True(t, parent.IsTargetPermitted("shared/A"))
	assert.True(t, parent.IsTargetPermitted("shared/B"))
}

func TestDelegationChain_MalformedPatternNeverMatches(t *testing.T) {
	// go-tuf treats a pattern that filepath.IsTargetPermitted rejects as matching
	// nothing. The matcher that DelegationChain replaced had a
	// literal-equality fast path which would have accepted "a/[b" for
	// itself. We must not diverge from go-tuf here: a mismatch between what
	// the TUF client resolves and what we iterate is exactly the class of
	// bug this type exists to prevent.
	chain := chainOf(dr("d1", false, "a/[b"))
	assert.False(t, chain.IsTargetPermitted("a/[b"))
	assert.False(t, chain.IsTargetPermitted("a/b"))
}

func TestDelegationChain_PathHashPrefixes_Smoke(t *testing.T) {
	// We don't use hash-bin delegations, but DelegationChain.IsTargetPermitted must at
	// least honour them the way go-tuf does, so that a chain containing one
	// can't silently accept everything (or nothing).
	const (
		covered   = "bins/covered.bin"
		uncovered = "bins/uncovered.bin"
	)
	prefix := hashPrefix(covered)
	require.NotEqual(t, prefix, hashPrefix(uncovered), "test paths must land in different bins")

	bin := dr("bin", false /* no paths */)
	bin.PathHashPrefixes = []string{prefix}

	chain := chainOf(bin)
	assert.True(t, chain.IsTargetPermitted(covered))
	assert.False(t, chain.IsTargetPermitted(uncovered))

	// Hash-bin links compose with pattern links like any other link.
	nested := chainOf(dr("d1", false, "bins/*"), bin)
	assert.True(t, nested.IsTargetPermitted(covered))
	assert.False(t, nested.IsTargetPermitted(uncovered))
}

func TestDelegationChain_BothPathsAndHashPrefixes_PathsWin(t *testing.T) {
	// Spec s4.5 requires exactly one of "paths" and "path_hash_prefixes".
	// go-tuf only enforces that when marshalling, so a delegation that
	// arrives with both set is accepted on parse; IsDelegatedPath then
	// consults Paths and ignores PathHashPrefixes entirely. Pin that so a
	// change in go-tuf's precedence (or a hex fix, see hashPrefix) shows up
	// here rather than as a silent change in which role is authorised.
	const hashed = "b/x"
	both := dr("both", false, "a/*")
	both.PathHashPrefixes = []string{hashPrefix(hashed)}

	chain := chainOf(both)
	assert.True(t, chain.IsTargetPermitted("a/x"), "Paths must still be honoured")
	assert.False(t, chain.IsTargetPermitted(hashed), "PathHashPrefixes must be ignored when Paths is set")
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

// Copyright (C) 2026 Amutable GmbH

package tufext

import (
	"fmt"
	"iter"
	"path/filepath"
	"slices"
	"strings"

	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/generics"
)

// TargetFileData is a tuple of (name, *[tufmetadata.TargetFiles]), mainly used
// as an iterator value for [IterTargetFiles].
type TargetFileData struct {
	// Path is the logical pathname for this target file.
	Path string

	// TargetFiles is the TUF target file metadata.
	*tufmetadata.TargetFiles
}

func pathMatchesPattern(pattern, targetPath string) bool {
	if targetPath == pattern {
		return true // fast path for literal patterns
	}
	targetParts := strings.Split(targetPath, "/")
	patternParts := strings.Split(pattern, "/")
	if len(targetParts) != len(patternParts) {
		return false
	}
	for i := range targetParts {
		// TODO: filepath.Match is used by go-tuf but it supports more patterns
		// than the TUF specification (this is almost certainly wrong and could
		// even be a security bug if someone depends on the paths not being
		// matched that way).
		if ok, _ := filepath.Match(patternParts[i], targetParts[i]); !ok {
			return false
		}
	}
	return true
}

func pathMatchesPatternChain(patternChain [][]string, targetPath string) bool {
	unmatched := len(patternChain)
stack:
	for _, patterns := range patternChain {
		for _, pattern := range patterns {
			if pathMatchesPattern(pattern, targetPath) {
				unmatched--
				continue stack
			}
		}
		return false // early break
	}
	return unmatched == 0
}

// IterTargetFiles iterates over all target files, matching the equivalent
// algorithm used by TUF to search for the correct target file. Note that the
// order of files yielded is not stable.
//
// TODO(links): This will need callbacks and a lot more infrastructure once we
// add cross-repository links. (Arguably even today it's a little less than
// ideal because we need to pre-fetch all of the targets which the default
// updater doesn't do.)
func IterTargetFiles(targets map[string]*SignedTargets) iter.Seq2[TargetFileData, error] {
	const maxDelegations = 128

	return generics.ErrorIter(func(yield func(TargetFileData) bool) error {
		seenTargets := make(map[string]struct{}, 256)

		// roleTodo indicates that we need to walk into the given role.
		type roleTodo struct {
			name string
			// If non-nil, this is the delegation information for this role.
			delegation *tufmetadata.DelegatedRole
			// The stack of patterns which be matched for a path in this role
			// to be valid (this includes all ancestor patterns as well as the
			// patterns for this DelegatedRole). If delegation is nil, then
			// this field is ignored.
			patternChain [][]string
		}

		// Once we hit a terminating delegation we need to make sure that the
		// paths it matches cannot be yielded afterwards.
		terminatedPatternChains := make([][][]string, 0, 128)
		// terminationTodo is a marker to indicate that terminatedPatternChains
		// needs to be updated. This is needed because s4.5 of the TUF spec
		// allows for children of a terminating pattern to match terminating
		// paths, requiring deferred terminatedPatternChains updates.
		type terminationTodo struct {
			chain [][]string
		}

		// Queue and seen-list to avoid re-iterating on a role.
		seen := make(map[string]struct{}, len(targets))
		todo := []any{roleTodo{name: tufmetadata.TARGETS}}
	roles:
		for len(todo) > 0 {
			next := todo[len(todo)-1]
			todo = todo[:len(todo)-1]

			var thisRole roleTodo
			switch next := next.(type) {
			case terminationTodo:
				terminatedPatternChains = append(terminatedPatternChains, next.chain)
				continue roles
			case roleTodo:
				thisRole = next
			default:
				panic(fmt.Sprintf("unexpected type %T", next))
			}

			if len(seen) >= maxDelegations {
				// In order to avoid a DoS by some role creating a long chain,
				// we have a limit but we do not
				// TODO(log): Add logging...
				return nil
			}
			if _, ok := seen[thisRole.name]; ok {
				// As per TUF specification s5.6.7.1.
				continue roles
			}
			role, ok := targets[thisRole.name]
			if !ok {
				return fmt.Errorf("target file walk aborted: role %s does not exist", thisRole.name)
			}
			seen[thisRole.name] = struct{}{}

			// First, yield all of the immediate target files.
		targets:
			for path, meta := range role.Signed.Targets {
				// If we already saw this target path before, it was provided
				// by a higher-priority (i.e., earlier in the chain) target
				// file.
				if _, ok := seenTargets[path]; ok {
					// TODO(log): Add logging?
					continue targets
				}
				// Make sure we don't yield entires that were already covered
				// by an earlier terminating delegation.
				for _, patternChain := range terminatedPatternChains {
					if pathMatchesPatternChain(patternChain, path) {
						// TODO(log): Add logging.
						continue targets
					}
				}
				// If this is a delegated role, make sure that the target path
				// matches one of the patterns specified by the delegator.
				if delegation := thisRole.delegation; delegation != nil {
					if !pathMatchesPatternChain(thisRole.patternChain, path) {
						// TODO(log): Add logging.
						continue targets
					}
				}
				if !yield(TargetFileData{Path: path, TargetFiles: meta}) {
					return nil
				}
				seenTargets[path] = struct{}{}
			}

			// If this is a terminating role, we need to make sure that any
			// roles higher up on the todo stack cannot match the same paths.
			// However, for descendants of this role (those about to be pushed
			// onto the stack) s4.5 says that they are also permitted to match
			// against the terminating patterns. So we defer this to after any
			// children added below are processed.
			if delegation := thisRole.delegation; delegation != nil && delegation.Terminating {
				todo = append(todo, terminationTodo{chain: thisRole.patternChain})
			}

			// Now append the set of delegations to the todo queue.
			if delegations := role.Signed.Delegations; delegations != nil {
				if delegations.SuccinctRoles != nil {
					return fmt.Errorf("role %s uses succinct roles: unsupported feature", thisRole.name)
				}

				// Append the delegations in reverse order so the first entry
				// ends up at the top of the stack (tail of todo), to match
				// s5.6.7 of the TUF spec.
				for delegatedRole := range generics.ReverseIter(delegations.Roles) {
					if len(delegatedRole.PathHashPrefixes) > 0 {
						return fmt.Errorf("role %s uses path prefixes: unsupported feature", delegatedRole.Name)
					}
					todo = append(todo, roleTodo{
						name:         delegatedRole.Name,
						delegation:   &delegatedRole,
						patternChain: append(slices.Clone(thisRole.patternChain), delegatedRole.Paths),
					})
				}
			}
		}
		return nil
	})
}

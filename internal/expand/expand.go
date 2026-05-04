// Copyright (C) 2026 Amutable GmbH

// Package expand provides printf-style format expansion with custom
// user-defined predicates.
package expand

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"unicode/utf8"
)

// PredicateFunc represents a %-expand prefix that does some processing to a %
// expansion produced by a [SourceFunc].
type PredicateFunc func(str string) (string, error)

// SourceFunc represents the source of a %-expando. If this expando consumes
// one (or more) arguments, it should re-slice the given argument slice.
type SourceFunc func(args *[]any) (string, error)

// Expansions represents a set of supported %-expansions that can be then used
// to expand some given text.
type Expansions struct {
	predicates map[rune]PredicateFunc
	sources    map[rune]SourceFunc
}

// NewExpansions allocates a new [Expansions] with a default set of expansions.
func NewExpansions() *Expansions {
	return &Expansions{
		predicates: maps.Clone(defaultPredicates),
		sources:    maps.Clone(defaultSources),
	}
}

// Clone makes a distinct copy of [Expansions] that can be independently
// operated on.
func (exp *Expansions) Clone() *Expansions {
	return &Expansions{
		predicates: maps.Clone(exp.predicates),
		sources:    maps.Clone(exp.sources),
	}
}

// WithPredicate adds a [PredicateFunc] for the given prefix character.
// Predicates can stack and are applied in LIFO order. If a source with the
// same character was defined using [Expansions.WithSource], this method
// implicitly removes it.
func (exp *Expansions) WithPredicate(char rune, fn PredicateFunc) *Expansions {
	if char == '%' {
		panic("cannot use WithPredicate with % as an expando")
	}
	exp.predicates[char] = fn
	delete(exp.sources, char) // make sure there are no duplicate rules
	return exp
}

// WithSource adds a [SourceFunc] for the given %-expand character. If a
// predicate with the same character was defined using
// [Expansions.WithPredicate], this method implicitly removes it.
func (exp *Expansions) WithSource(char rune, fn SourceFunc) *Expansions {
	if char == '%' {
		panic("cannot use WithSource with % as an expando")
	}
	exp.sources[char] = fn
	delete(exp.predicates, char) // make sure there are no duplicate rules
	return exp
}

func isHex(ch rune) bool {
	return (ch >= '0' && ch <= '9') ||
		(ch >= 'a' && ch <= 'f') ||
		(ch >= 'A' && ch <= 'F')
}

func httpPercentPassthrough(wtr io.Writer, fmtRdr *strings.Reader) error {
	var expando strings.Builder
	expando.WriteRune('%')
	for range 2 {
		ch, _, err := fmtRdr.ReadRune()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("truncated http expando %q at end of string", expando.String())
		} else if err != nil {
			return fmt.Errorf("read next rune: %w", err)
		}
		expando.WriteRune(ch)
		if !isHex(ch) {
			return fmt.Errorf("invalid char %c in http expando %q", ch, expando.String())
		}
	}
	if _, err := io.WriteString(wtr, expando.String()); err != nil {
		return fmt.Errorf("write http expando %q: %w", expando.String(), err)
	}
	return nil
}

func (exp Expansions) expandPercent(wtr io.Writer, fmtRdr *strings.Reader, args *[]any) error {
	if ch, _, err := fmtRdr.ReadRune(); errors.Is(err, io.EOF) {
		return errors.New("trailing % at end of string")
	} else if err != nil {
		return fmt.Errorf("read next rune: %w", err)
	} else if ch == '%' {
		if _, err := wtr.Write([]byte("%")); err != nil {
			return fmt.Errorf("write escaped %%: %w", err)
		}
		return nil
	}
	if err := fmtRdr.UnreadRune(); err != nil {
		return fmt.Errorf("unread rune: %w", err)
	}
	var (
		expando      strings.Builder
		predFns      []PredicateFunc
		srcFn        SourceFunc
		seenExpandos = make(map[rune]struct{})
	)
	expando.WriteRune('%')
	for fmtRdr.Len() > 0 {
		ch, _, err := fmtRdr.ReadRune()
		if err != nil {
			return fmt.Errorf("read next rune: %w", err)
		}
		expando.WriteRune(ch)
		if _, ok := seenExpandos[ch]; ok {
			return fmt.Errorf("duplicate predicate %c in expando %q", ch, expando.String())
		}
		seenExpandos[ch] = struct{}{}
		if fn, ok := exp.predicates[ch]; ok {
			predFns = append(predFns, fn)
			continue
		}
		if fn, ok := exp.sources[ch]; ok {
			srcFn = fn
			break // source comes last
		}
		// Permit %-based URL encoding to be output as-is (as long as there
		// were no predicates, otherwise the behaviour doesn't make sense).
		if isHex(ch) && len(predFns) == 0 {
			if err := fmtRdr.UnreadRune(); err != nil {
				return fmt.Errorf("unread rune: %w", err)
			}
			return httpPercentPassthrough(wtr, fmtRdr)
		}
		return fmt.Errorf("invalid predicate %c in expando %q", ch, expando.String())
	}
	if srcFn == nil {
		return fmt.Errorf("incomplete expando %q at end of string", expando.String())
	}
	expanded, err := srcFn(args)
	if err != nil {
		return fmt.Errorf("error during %q expansion: %w", expando.String(), err)
	}
	slices.Reverse(predFns) // apply them in LIFO order
	for _, fn := range predFns {
		var err error
		expanded, err = fn(expanded)
		if err != nil {
			return fmt.Errorf("error during %q expansion: %w", expando.String(), err)
		}
	}
	if _, err := io.WriteString(wtr, expanded); err != nil {
		return fmt.Errorf("write expand %q (%s): %w", expando.String(), expanded, err)
	}
	return nil
}

func (exp Expansions) expand(wtr io.Writer, fmtStr string, args []any) error {
	fmtRdr := strings.NewReader(fmtStr)
	for fmtRdr.Len() > 0 {
		ch, _, _ := fmtRdr.ReadRune()
		if ch == '%' {
			if err := exp.expandPercent(wtr, fmtRdr, &args); err != nil {
				return fmt.Errorf("expand %%: %w", err)
			}
			continue
		}
		// TODO: It'd probably be better for us to do an IndexRune to find
		// the % character here.
		runeBytes := utf8.AppendRune(nil, ch)
		if _, err := wtr.Write(runeBytes); err != nil {
			return fmt.Errorf("write literal %c: %w", ch, err)
		}
	}
	if len(args) > 0 {
		return fmt.Errorf("unexpanded trailing arguments: %v", args)
	}
	return nil
}

// Expand expands a format string using the set of defined predicates and
// %-expansions to the given [io.Writer], akin to [fmt.Fprintf].
func (exp Expansions) Expand(wtr io.Writer, fmt string, args ...any) error {
	return exp.expand(wtr, fmt, args)
}

// ExpandString expands a format string using the set of defined predicates and
// %-expansions to a string that is then returned, akin to [fmt.Sprintf].
func (exp Expansions) ExpandString(fmt string, args ...any) (string, error) {
	var buf strings.Builder
	buf.Grow(len(fmt))
	err := exp.Expand(&buf, fmt, args...)
	return buf.String(), err
}

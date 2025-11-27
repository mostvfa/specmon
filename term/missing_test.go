package term_test

import (
	"testing"

	"github.com/specmon/specmon/term"
)

func toSet(xs []term.Term) map[string]term.Term {
	m := make(map[string]term.Term)
	for _, t := range xs {
		m[t.String()] = t
	}
	return m
}

// ----------------------------------------
// 1. Basic behavior
// ----------------------------------------

func TestMissingTerms_Basic(t *testing.T) {
	x := term.NewVariable("x")
	y := term.NewVariable("y")

	target := term.NewFunction("pair", []term.Term{x, y})

	known := []term.Term{x}
	missing := term.MissingTerms(target, known)
	s := toSet(missing)

	expected := []term.Term{
		y,
		term.NewFunction("pair", []term.Term{x, y}),
	}

	if len(s) != len(expected) {
		t.Fatalf("expected %v missing, got %v", expected, missing)
	}

	for _, e := range expected {
		if _, ok := s[e.String()]; !ok {
			t.Errorf("expected missing term %v, got %v", e, missing)
		}
	}
}

// ----------------------------------------
// 2. Empty target
// ----------------------------------------

func TestMissingTerms_EmptyTarget(t *testing.T) {
	var target term.Term = nil
	known := []term.Term{}

	missing := term.MissingTerms(target, known)
	if len(missing) != 0 {
		t.Errorf("expected empty missing set, got %v", missing)
	}
}

// ----------------------------------------
// 3. Empty known (everything is missing)
// ----------------------------------------

func TestMissingTerms_AllMissing(t *testing.T) {
	x := term.NewVariable("x")
	y := term.NewVariable("y")

	target := term.NewFunction("pair", []term.Term{x, y})
	missing := term.MissingTerms(target, nil)
	s := toSet(missing)

	expected := []term.Term{
		x, y,
		term.NewFunction("pair", []term.Term{x, y}),
	}

	if len(s) != len(expected) {
		t.Fatalf("expected missing=%v, got=%v", expected, missing)
	}

	for _, e := range expected {
		if _, ok := s[e.String()]; !ok {
			t.Errorf("expected %v, got %v", e, missing)
		}
	}
}

// ----------------------------------------
// 4. Deep nesting with repeated subterms
// ----------------------------------------

func TestMissingTerms_DeepRepeated(t *testing.T) {
	a := term.NewVariable("a")
	b := term.NewVariable("b")

	target := term.NewFunction("f", []term.Term{
		term.NewFunction("g", []term.Term{
			a,
			term.NewFunction("h", []term.Term{a, b}),
		}),
	})

	known := []term.Term{a}

	missing := term.MissingTerms(target, known)
	s := toSet(missing)

	expected := []term.Term{
		b,
		term.NewFunction("h", []term.Term{a, b}),
		term.NewFunction("g", []term.Term{
			a,
			term.NewFunction("h", []term.Term{a, b}),
		}),
		term.NewFunction("f", []term.Term{
			term.NewFunction("g", []term.Term{
				a,
				term.NewFunction("h", []term.Term{a, b}),
			}),
		}),
	}

	if len(s) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, missing)
	}

	for _, e := range expected {
		if _, ok := s[e.String()]; !ok {
			t.Errorf("missing expected term %v, got %v", e, missing)
		}
	}
}

// ----------------------------------------
// 5. Constants of different types
// ----------------------------------------

// func TestMissingTerms_Constants(t *testing.T) {
// 	i := term.NewConstant:contentReference[oaicite:0]{index=0}
// 	bs := term.NewConstant[[]byte]([]byte{0xde, 0xad})
// 	s := term.NewConstant[string]("hello")

// 	target := term.NewFunction("mix", []term.Term{i, bs, s})

// 	known := []term.Term{bs}

// 	missing := term.MissingTerms(target, known)
// 	set := toSet(missing)

// 	expected := []term.Term{
// 		i, s,
// 		term.NewFunction("mix", []term.Term{i, bs, s}),
// 	}

// 	if len(set) != len(expected) {
// 		t.Fatalf("expected %v missing, got %v", expected, missing)
// 	}

// 	for _, e := range expected {
// 		if _, ok := set[e.String()]; !ok {
// 			t.Errorf("expected %v in missing set, got %v", e, missing)
// 		}
// 	}
// }

// ----------------------------------------
// 6. Known contains bigger term than target
// ----------------------------------------

func TestMissingTerms_KnownBigger(t *testing.T) {
	x := term.NewVariable("x")

	known := []term.Term{
		term.NewFunction("big", []term.Term{
			term.NewFunction("small", []term.Term{x}),
		}),
	}

	target := term.NewFunction("small", []term.Term{x})

	missing := term.MissingTerms(target, known)

	// small(x) is a subterm of big(small(x)), so missing = {}
	if len(missing) != 0 {
		t.Errorf("expected no missing terms, got %v", missing)
	}
}

// ----------------------------------------
// 7. Known contains entire target (missing empty)
// ----------------------------------------

func TestMissingTerms_TargetFullyKnown(t *testing.T) {
	x := term.NewVariable("x")
	y := term.NewVariable("y")

	target := term.NewFunction("pair", []term.Term{x, y})
	known := []term.Term{
		term.NewFunction("pair", []term.Term{x, y}),
	}

	missing := term.MissingTerms(target, known)

	if len(missing) != 0 {
		t.Errorf("expected empty missing set, got %v", missing)
	}
}

// ----------------------------------------
// 8. Target includes itself recursively (self-similar)
// ----------------------------------------

// func TestMissingTerms_SelfSimilar(t *testing.T) {
// 	x := term.NewVariable("x")

// 	// t = node(x, node(x, x))
// 	t := term.NewFunction("node", []term.Term{
// 		x,
// 		term.NewFunction("node", []term.Term{x, x}),
// 	})

// 	missing := term.MissingTerms(t, []term.Term{x})
// 	set := toSet(missing)

// 	expected := []term.Term{
// 		term.NewFunction("node", []term.Term{x, x}),
// 		term.NewFunction("node", []term.Term{
// 			x,
// 			term.NewFunction("node", []term.Term{x, x}),
// 		}),
// 	}

// 	if len(set) != len(expected) {
// 		t.Fatalf("expected %v, got %v", expected, missing)
// 	}

// 	for _, e := range expected {
// 		if _, ok := set[e.String()]; !ok {
// 			t.Errorf("missing expected term %v, got %v", e, missing)
// 		}
// 	}
// }

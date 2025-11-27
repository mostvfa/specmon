package monitor_test

import (
	"testing"

	"github.com/specmon/specmon/monitor"
	"github.com/specmon/specmon/term"
)

// -------------------------------------------------------------
// 1. Test resolving a single term
// -------------------------------------------------------------
func TestResolveTerm_Exp(t *testing.T) {
	base := term.NewConstant([]byte{0x02})
	exp  := term.NewConstant([]byte{0x03})

	f := term.NewFunction("exp", []term.Term{base, exp})

	val, err := monitor.ResolveTerm(f)
	if err != nil {
		t.Fatalf("ResolveTerm failed: %v", err)
	}

	if _, err := term.AsBytes(val); err != nil {
		t.Fatalf("returned exp() is not bytes: %v", err)
	}
}

// -------------------------------------------------------------
// 2. Test resolving missing terms list
// -------------------------------------------------------------
func TestResolveMissingTerms_List(t *testing.T) {
	randTerm := term.NewFunction("rand", []term.Term{})
	hashTerm := term.NewFunction("hash", []term.Term{randTerm})

	missing := []term.Term{randTerm, hashTerm}

	values, err := monitor.ResolveMissingTerms(missing)
	if err != nil {
		t.Fatalf("ResolveMissingTerms error: %v", err)
	}

	if len(values) != 2 {
		t.Fatalf("expected 2 results, got %d", len(values))
	}
}

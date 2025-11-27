package monitor_test

import (
	"testing"

	"github.com/specmon/specmon/monitor"
	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

//     knownCat = cat(
//         byte(0xff,  1),
//         byte(0x02,  1),
//         byte(0xcafe, 2)
//     )
//
//     target = cat(
//         byte(0xff, 1),
//         byte(0x02, 1),
//         byte(0xcafe, 2),
//         byte(exp("g", rand()), 32)
//     )
//
// EXPECTED MISSING TERMS:
//
//   r        = rand()
//   t4       = exp("g", rand())
//   t4Byte   = byte(exp("g", rand()), 32)
//   target   = full cat(...)
//
func TestMissingTermsFromConfig_FormatExpansion(t *testing.T) {
    // SpecMon-style format terms: byte(value, length)
    bFF   := term.NewConstant([]byte{0xff})
    b02   := term.NewConstant([]byte{0x02})
    bCAFE := term.NewConstant([]byte{0xca, 0xfe})
    cG    := term.NewConstant("g")

    t1 := term.NewFunction("byte", []term.Term{
        bFF,
        term.NewConstant(1),
    })

    t2 := term.NewFunction("byte", []term.Term{
        b02,
        term.NewConstant(1),
    })

    t3 := term.NewFunction("byte", []term.Term{
        bCAFE,
        term.NewConstant(2),
    })

    // rand()
    r := term.NewFunction("rand", []term.Term{})

    // exp('g', rand())
    t4 := term.NewFunction("exp", []term.Term{
        cG,
        r,
    })

    // byte(exp(...), 32)
    t4Byte := term.NewFunction("byte", []term.Term{
        t4,
        term.NewConstant(32),
    })

    // TARGET = cat(t1, t2, t3, t4Byte)
    target := term.NewFunction("cat", []term.Term{t1, t2, t3, t4Byte})

    knownCat := term.NewFunction("cat", []term.Term{t1, t2, t3})

    cfg := monitor.NewConfig()
    cfg.AddFact(&rule.Fact{
        Name: "KnownFullCat",
        Args: []term.Term{knownCat},
    })

    missing := monitor.MissingTermsFromConfiguration(target, cfg)
    s := termSet(missing)

    // Expected missing subterms:
    expected := []term.Term{
        r,        // rand()
        t4,       // exp('g', rand())
        t4Byte,   // byte(exp('g', rand()), 32)
        target,   // full cat(... t4Byte)
    }

    if len(s) != len(expected) {
        t.Fatalf("expected %d missing terms, got %d\nMissing: %v",
            len(expected), len(s), missing)
    }

    for _, e := range expected {
        if !s[e.String()] {
            t.Errorf("expected missing term %v but not found in %v",
                e, missing)
        }
    }
}

// -----------------------------------------------------------------------------
// 8. simple Example:
//     m  = cat(byte(t1), byte(t2))
//     m' = cat(byte(t2), byte(t1), byte(t3))
//     Config knows all subterms of m (so t1, t2 known)
//     Missing terms must be: t3, byte(t3), and full m'
// -----------------------------------------------------------------------------

func TestMissingTermsFromConfig_simple(t *testing.T) {
    // t1, t2, t3 are variables (unknown initially)
    t1 := term.NewVariable("t1")
    t2 := term.NewVariable("t2")
    t3 := term.NewVariable("t3")

    // m = cat(byte(t1), byte(t2))
    m := term.NewFunction("cat", []term.Term{
        term.NewFunction("byte", []term.Term{t1}),
        term.NewFunction("byte", []term.Term{t2}),
    })

    // m' = cat(byte(t2), byte(t1), byte(t3))
    target := term.NewFunction("cat", []term.Term{
        term.NewFunction("byte", []term.Term{t2}),
        term.NewFunction("byte", []term.Term{t1}),
        term.NewFunction("byte", []term.Term{t3}),
    })

    // Config knows m, so it knows all subterms: t1, t2, byte(t1), byte(t2)
    cfg := monitor.NewConfig()
    cfg.AddFact(&rule.Fact{Name: "F", Args: []term.Term{m}})

    missing := monitor.MissingTermsFromConfiguration(target, cfg)
    s := termSet(missing)

    expected := []term.Term{
        t3,                                      // new variable
        term.NewFunction("byte", []term.Term{t3}), // wrapper for new variable
        target,                                  // full target
    }

    if len(s) != len(expected) {
        t.Fatalf("expected %d missing, got %d\nMissing: %v",
            len(expected), len(s), missing)
    }

    for _, e := range expected {
        if !s[e.String()] {
            t.Errorf("expected missing %v but not found in %v", e, missing)
        }
    }
}


func termSet(xs []term.Term) map[string]bool {
	m := make(map[string]bool)
	for _, t := range xs {
		m[t.String()] = true
	}
	return m
}

// ----------------------------------------
// 1. Basic config extraction
// ----------------------------------------

func TestMissingTermsFromConfig_Basic(t *testing.T) {
	x := term.NewVariable("x")
	y := term.NewVariable("y")
	z := term.NewVariable("z")

	cfg := monitor.NewConfig()

	cfg.AddFact(&rule.Fact{Name: "F", Args: []term.Term{x}})
	cfg.AddSeen(y)

	target := term.NewFunction("pair", []term.Term{x, y, z})

	missing := monitor.MissingTermsFromConfiguration(target, cfg)
	s := termSet(missing)

	expected := []term.Term{
		z,
		term.NewFunction("pair", []term.Term{x, y, z}),
	}

	if len(s) != len(expected) {
		t.Fatalf("expected missing=%v, got=%v", expected, missing)
	}

	for _, e := range expected {
		if !s[e.String()] {
			t.Errorf("missing expected %v, got %v", e, missing)
		}
	}
}

// ----------------------------------------
// 2. Config knows everything through facts and seen
// ----------------------------------------

func TestMissingTermsFromConfig_CompleteKnowledge(t *testing.T) {
	x := term.NewVariable("x")
	y := term.NewVariable("y")

	cfg := monitor.NewConfig()
	cfg.AddSeen(x)
	cfg.AddFact(&rule.Fact{Name: "G", Args: []term.Term{y}})

	target := term.NewFunction("pair", []term.Term{x, y})

	missing := monitor.MissingTermsFromConfiguration(target, cfg)
	if len(missing) != 1 ||
		!missing[0].Equal(term.NewFunction("pair", []term.Term{x, y})) {
		t.Errorf("expected only composite term missing, got %v", missing)
	}
}

// ----------------------------------------
// 3. Config with irrelevant facts (should not affect missing)
// ----------------------------------------

func TestMissingTermsFromConfig_IrrelevantFacts(t *testing.T) {
	x := term.NewVariable("x")
	y := term.NewVariable("y")
	z := term.NewVariable("z")

	cfg := monitor.NewConfig()
	cfg.AddFact(&rule.Fact{Name: "Unrelated", Args: []term.Term{z}})

	target := term.NewFunction("pair", []term.Term{x, y})

	missing := monitor.MissingTermsFromConfiguration(target, cfg)
	s := termSet(missing)

	expected := []term.Term{
		x, y,
		term.NewFunction("pair", []term.Term{x, y}),
	}

	if len(s) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, missing)
	}
}

// ----------------------------------------
// 4. Deep nested config facts
// ----------------------------------------

func TestMissingTermsFromConfig_DeepFacts(t *testing.T) {
	a := term.NewVariable("a")
	b := term.NewVariable("b")
	c := term.NewVariable("c")

	cfg := monitor.NewConfig()
	cfg.AddFact(&rule.Fact{
		Name: "Nested",
		Args: []term.Term{
			term.NewFunction("pair", []term.Term{a, b}),
		},
	})

	target := term.NewFunction("triple", []term.Term{
		a,
		b,
		c,
	})

	missing := monitor.MissingTermsFromConfiguration(target, cfg)
	s := termSet(missing)

	expected := []term.Term{c, term.NewFunction("triple", []term.Term{a, b, c})}

	if len(s) != len(expected) {
		t.Fatalf("expected %v missing, got %v", expected, missing)
	}
	for _, e := range expected {
		if !s[e.String()] {
			t.Errorf("expected missing term %v, got %v", e, missing)
		}
	}
}

// ----------------------------------------
// 5. Facts override seen (fact is known first)
// ----------------------------------------

func TestMissingTermsFromConfig_FactOverridesSeen(t *testing.T) {
	x := term.NewVariable("x")

	cfg := monitor.NewConfig()
	cfg.AddSeen(x)
	cfg.AddFact(&rule.Fact{Name: "F", Args: []term.Term{x}})

	target := x
	missing := monitor.MissingTermsFromConfiguration(target, cfg)

	if len(missing) != 0 {
		t.Errorf("expected no missing terms, got %v", missing)
	}
}

// -----------------------------------------------------------------------------
// 6. Crypto example:
//   m   = encrypt(key_42, pair(nonce_13, ciphertext_99))
//   mac = blake2s(m)
//   m'  = pair(mac, m)
// -----------------------------------------------------------------------------

func TestMissingTermsFromConfig_CryptoExample(t *testing.T) {
	key42 := term.NewVariable("key_42")
	nonce13 := term.NewVariable("nonce_13")
	cipher99 := term.NewVariable("ciphertext_99")

	pairNonceCipher := term.NewFunction("pair", []term.Term{
		nonce13,
		cipher99,
	})

	m := term.NewFunction("encrypt", []term.Term{
		key42,
		pairNonceCipher,
	})

	mac := term.NewFunction("blake2s", []term.Term{
		m,
	})

	target := term.NewFunction("pair", []term.Term{
		mac,
		m,
	})

	cfg := monitor.NewConfig()
	cfg.AddSeen(key42)
	cfg.AddFact(&rule.Fact{
		Name: "KnownNonce",
		Args: []term.Term{nonce13},
	})

	missing := monitor.MissingTermsFromConfiguration(target, cfg)
	s := setMap(missing)

	expected := []term.Term{
		cipher99,
		pairNonceCipher,
		m,
		mac,
		target,
	}

	if len(s) != len(expected) {
		t.Fatalf("expected %d missing terms, got %d\nMissing: %v",
			len(expected), len(s), missing)
	}

	for _, e := range expected {
		if !s[e.String()] {
			t.Errorf("expected missing term %v but not found in %v", e, missing)
		}
	}
}

// -----------------------------------------------------------------------------
// 7. FULL REAL CONFIGURATION TEST
//     Target = <exp(rand(), X), Y>
//     Uses real hex bitstrings from your ProcessEvent dump.
// -----------------------------------------------------------------------------

func TestMissingTermsFromConfig_ExpExample(t *testing.T) {
	X := term.NewConstant("0x20e66ec7f9af497e949bc81bb63d34363eae7f951a99439168558d8a19f79244")
	r := term.NewFunction("rand", []term.Term{})

	target := term.NewFunction("exp", []term.Term{r, X})

	cfg := monitor.NewConfig()
	cfg.AddFact(&rule.Fact{Name: "KnownX", Args: []term.Term{X}})

	missing := monitor.MissingTermsFromConfiguration(target, cfg)
	s := termSet(missing)

	expected := []term.Term{
		r,
		target,
	}

	if len(s) != len(expected) {
		t.Fatalf("expected %d missing, got %d\nMissing: %v", len(expected), len(s), missing)
	}

	for _, e := range expected {
		if !s[e.String()] {
			t.Errorf("expected missing term %v but not found in %v", e, missing)
		}
	}
}


func setMap(xs []term.Term) map[string]bool {
	m := make(map[string]bool)
	for _, t := range xs {
		m[t.String()] = true
	}
	return m
}


package monitor

import "github.com/specmon/specmon/term"

// MissingTermsFromConfiguration extracts all known terms from a Config
// and calls term.MissingTerms(target, knownTerms).
func MissingTermsFromConfiguration(target term.Term, cfg *Config) []term.Term {
	if cfg == nil {
		return term.MissingTerms(target, nil)
	}
	known := extractKnownFromConfig(cfg)
	return term.MissingTerms(target, known)
}

// extractKnownFromConfig collects all terms present in:
// - cfg.facts (Fact.Args)
// - cfg.seen  ([]term.Term])
// - cfg.trace (Fact.Args)
func extractKnownFromConfig(cfg *Config) []term.Term {
	var known []term.Term

	// seen events
	for _, t := range cfg.seen {
		known = append(known, t)
	}

	// state facts
	for _, f := range cfg.facts {
		for _, arg := range f.Args {
			known = append(known, arg)
		}
	}

	// trace action facts
	for _, f := range cfg.trace {
		for _, arg := range f.Args {
			known = append(known, arg)
		}
	}

	return known
}

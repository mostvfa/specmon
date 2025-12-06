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
	known = append(known, cfg.seen...)

	// state facts
	for _, f := range cfg.facts {
		known = append(known, f.Args...)
	}

	// trace action facts
	for _, f := range cfg.trace {
		known = append(known, f.Args...)
	}

	return known
}

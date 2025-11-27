package term

// MissingTerms returns all subterms of `target` that are not present among
// subterms of any of the provided `known` terms.
//
// missing = Subterms(target) − Subterms(known)
func MissingTerms(target Term, known []Term) []Term {
	if target == nil {
		return nil
	}

	targetSubs := collectSubterms(target)

	// collect subterms of known
	var knownSubs []Term
	for _, k := range known {
		for _, s := range collectSubterms(k) {
			if !containsTerm(knownSubs, s) {
				knownSubs = append(knownSubs, s)
			}
		}
	}

	var missing []Term
	for _, s := range targetSubs {
		if _, err := AsConstant[[]byte](s); err == nil {
			continue
		}
		if _, err := AsConstant[string](s); err == nil {
			continue
		}
		if _, err :=  AsConstant[int](s); err == nil {
			continue
		}
		if !containsTerm(knownSubs, s) {
			missing = append(missing, s)
		}
	}

	return missing
}

// collectSubterms returns all subterms of t (including t itself), deduplicated.
func collectSubterms(t Term) []Term {
	var out []Term

	var visit func(Term)
	visit = func(x Term) {
		if x == nil {
			return
		}

		if !containsTerm(out, x) {
			out = append(out, x)
		}

		if f, err := AsFunction(x); err == nil && f != nil {
			for _, arg := range f.Args {
				visit(arg)
			}
		}
	}

	visit(t)
	return out
}

// containsTerm checks structural equality via Term.Equal
func containsTerm(slice []Term, t Term) bool {
	for _, s := range slice {
		if s.Equal(t) {
			return true
		}
	}
	return false
}

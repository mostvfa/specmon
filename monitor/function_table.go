package monitor


import (
	"fmt"
	"github.com/specmon/specmon/term"
)

func init() {
    RegisterFunction("exp", ExpImpl)
    RegisterFunction("hash", HashImpl)
    RegisterFunction("rand", RandImpl)
    RegisterFunction("hmac", HMACImpl)
}

/*
   =============================================================
      FUNCTION TABLE FRAMEWORK FOR REPAIRING MISSING TERMS
   =============================================================
   This maps model-level function symbols (e.g., "exp", "hash")
   to actual implementation functions.

   MissingTermsFromConfiguration() tells us WHAT is missing.
   This table tells us HOW to compute it.
*/

// Implementation function prototype
// Input: slice of arguments as SpecMon terms
// Output: computed term or error
type ImplFunc func(args []term.Term) (term.Term, error)

// Global registry
var FunctionTable = map[string]ImplFunc{}

// Registration API
func RegisterFunction(name string, impl ImplFunc) {
	if name == "" {
		panic("RegisterFunction: name cannot be empty")
	}
	if impl == nil {
		panic("RegisterFunction: implementation cannot be nil")
	}
	FunctionTable[name] = impl
}

// ResolveTerm takes a symbolic term f(x1, x2,...) and calls its
// concrete implementation from FunctionTable.
func ResolveTerm(t term.Term) (term.Term, error) {
	f, err := term.AsFunction(t)
	if err != nil {
		return nil, fmt.Errorf("ResolveTerm: expected function, got %v", t)
	}

	impl, ok := FunctionTable[f.Name]
	if !ok {
		return nil, fmt.Errorf("no registered implementation for %s", f.Name)
	}

	return impl(f.Args)
}

/*
   =============================================================
      HELPERS FOR REPAIR ENGINE
   =============================================================
*/

// ResolveMissingTerms resolves all missing terms using the function table.
// Known terms are constants, variables, or functions that do not appear in FunctionTable.
func ResolveMissingTerms(missing []term.Term) ([]term.Term, error) {
    var resolved []term.Term

    for _, t := range missing {
        rt, err := resolveTermRecursive(t)
        if err != nil {
            return nil, err
        }
        resolved = append(resolved, rt)
    }

    return resolved, nil
}

func resolveTermRecursive(t term.Term) (term.Term, error) {
    // constants and variables resolve to themselves
    if _, err := term.AsFunction(t); err != nil {
        return t, nil
    }

    f, _ := term.AsFunction(t)

    // First resolve all arguments
    resolvedArgs := make([]term.Term, len(f.Args))
    for i, a := range f.Args {
        ra, err := resolveTermRecursive(a)
        if err != nil {
            return nil, err
        }
        resolvedArgs[i] = ra
    }

    // Then evaluate the function using the table
    impl, ok := FunctionTable[f.Name]
    if !ok {
        return nil, fmt.Errorf("no implementation for %s", f.Name)
    }

    return impl(resolvedArgs)
}



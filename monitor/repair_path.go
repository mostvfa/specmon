// Copyright (C) 2025 CISPA Helmholtz Center for Information Security
//
// This file is part of SpecMon.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with program. If not, see <https://www.gnu.org/licenses/>.

package monitor

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

// MaxRepairDepth is the maximum recursion depth for repair
const MaxRepairDepth = 1000

// RepairResult represents the result of the repair algorithm
type RepairResult struct {
	OriginalEvent term.Term         // The illegal event
	LegalEvent    term.Term         // The repaired event (with nested function calls)
	RuleName      string            // The rule used for repair
	AcceptedArgs  map[int]term.Term // Args that were accepted from config/model
	ResolvedArgs  map[int]term.Term // Args that were resolved to nested function calls
}

// RepairAndTellMeWhatToDo implements the formal repair algorithm
//
// Algorithm:
//  1. If e.name is not a trigger in any rule, return no repair
//  2. Find candidate rules that have e.name as a trigger
//  3. For each candidate rule r:
//     a. For each arg in event, check if it can be "accepted" (exists in config or matches rule pattern)
//     b. For unaccepted args, trace through MSRs:
//     - Find which LHS fact contains this arg
//     - Find which rule produces that fact
//     - Determine if the value comes from trigger OUTPUT or INPUT:
//     * OUTPUT (second of pair): Snd(<trigger>)
//     * INPUT (argument position): pick_arg(Fst(<trigger>), position)
//     c. Recursively resolve until we hit rules with empty LHS
func (m *Monitor) RepairAndTellMeWhatToDo(illegalEvent term.Term, cfg *Config) ([]RepairResult, error) {
	// Extract event structure
	eventFirst, eventSecond := splitPair(illegalEvent)
	if eventFirst == nil {
		return nil, fmt.Errorf("invalid event structure")
	}

	eventFn, err := term.AsFunction(eventFirst)
	if err != nil {
		return nil, fmt.Errorf("event is not a function: %v", err)
	}

	// Step 1: Check if e.name is a trigger in any rule
	candidateRules := m.findRulesWithTrigger(eventFn.Name)
	if len(candidateRules) == 0 {
		return nil, fmt.Errorf("no rules have %s as a trigger - cannot repair", eventFn.Name)
	}

	var results []RepairResult

	// Step 2: For each configuration (if unspecified, iterate all) and each candidate rule, try to build a repair
	configs := []*Config{cfg}
	if cfg == nil {
		configs = m.configs.Values()
		if len(configs) == 0 {
			return nil, fmt.Errorf("no configurations available")
		}
	}

	for _, c := range configs {
		for _, r := range candidateRules {
			result := m.computeRepairForRule(illegalEvent, eventFn, eventSecond, r, c)
			if result != nil {
				results = append(results, *result)
			}
		}
	}

	// Deduplicate results that are identical across configurations
	results = m.deduplicateRepairResults(results)

	return results, nil
}

// findRulesWithTrigger finds all rules that have the given function name as a trigger
func (m *Monitor) findRulesWithTrigger(funcName string) []*rule.Rule {
	var candidates []*rule.Rule
	seen := make(map[*rule.Rule]bool)

	for _, rules := range m.rules {
		for _, r := range rules {
			if seen[r] {
				continue
			}
			for _, trigger := range r.Triggers() {
				if splitPairFirstName(trigger) == funcName {
					candidates = append(candidates, r)
					seen[r] = true
					break
				}
			}
		}
	}
	return candidates
}

// computeRepairForRule computes a repair plan for a specific rule
func (m *Monitor) computeRepairForRule(
	illegalEvent term.Term,
	eventFn *term.Function,
	eventOutput term.Term,
	r *rule.Rule,
	cfg *Config,
) *RepairResult {
	result := &RepairResult{
		OriginalEvent: illegalEvent,
		RuleName:      r.Name,
		AcceptedArgs:  make(map[int]term.Term),
		ResolvedArgs:  make(map[int]term.Term),
	}

	// Get the trigger pattern for this rule
	var triggerPattern term.Term
	for _, trigger := range r.Triggers() {
		if splitPairFirstName(trigger) == eventFn.Name {
			triggerPattern = trigger
			break
		}
	}

	// Try to unify the event with the rule's trigger to get bindings
	binding := m.unifyEventWithRuleTrigger(illegalEvent, r)

	// For each arg in event, determine if accepted or needs resolution
	for i, arg := range eventFn.Args {
		// Check if this arg is accepted (exists in config facts matching the rule's LHS)
		if m.isArgAcceptedInContext(arg, i, r, cfg, binding, triggerPattern) {
			result.AcceptedArgs[i] = arg
		} else {
			// Resolve this arg by walking MSRs backward
			visited := make(map[string]bool)
			resolved := m.resolveArgumentFormal(arg, i, r, cfg, binding, triggerPattern, visited, 0)
			result.ResolvedArgs[i] = resolved
		}
	}

	// Build the legal event with resolved args
	result.LegalEvent = m.buildLegalEvent(eventFn, eventOutput, result)

	// If the function part did not change (ignoring return/output), skip this plan.
	illegalFirst, _ := splitPair(illegalEvent)
	legalFirst, _ := splitPair(result.LegalEvent)
	if illegalFirst != nil && legalFirst != nil && legalFirst.String() == illegalFirst.String() {
		return nil
	}

	return result
}

// isArgAcceptedInContext checks if an argument is accepted in the context of the rule
// An arg is accepted if it appears in a LHS fact that exists in the configuration
func (m *Monitor) isArgAcceptedInContext(
	arg term.Term,
	argIndex int,
	r *rule.Rule,
	cfg *Config,
	binding *term.Binding,
	triggerPattern term.Term,
) bool {
	// Get the variable name for this argument position from the trigger pattern
	var expectedVar *term.Variable
	if triggerPattern != nil {
		triggerFirst, _ := splitPair(triggerPattern)
		if triggerFirst != nil {
			if triggerFn, err := term.AsFunction(triggerFirst); err == nil {
				if argIndex < len(triggerFn.Args) {
					if v, err := term.AsVariable(triggerFn.Args[argIndex]); err == nil {
						expectedVar = v
					}
				}
			}
		}
	}

	// Check each LHS fact
	for _, lhsFact := range r.LHS {
		// Check if the fact contains this arg (or the variable that should bind to it)
		containsArg := false
		for _, factArg := range lhsFact.Args {
			if factArg.String() == arg.String() {
				containsArg = true
				break
			}
			if expectedVar != nil {
				if v, err := term.AsVariable(factArg); err == nil && v.String() == expectedVar.String() {
					containsArg = true
					break
				}
			}
		}

		if containsArg {
			// Instantiate the fact with binding and check if it exists in config
			instFact := lhsFact
			if binding != nil {
				instFact = lhsFact.Subst(binding)
			}
			if m.configHasFact(cfg, instFact) {
				return true
			}
		}
	}

	return false
}

// resolveArgumentFormal formally resolves an argument by walking MSRs backward
// Returns the term representing how to compute this argument
func (m *Monitor) resolveArgumentFormal(
	arg term.Term,
	argIndex int,
	currentRule *rule.Rule,
	cfg *Config,
	binding *term.Binding,
	triggerPattern term.Term,
	visited map[string]bool,
	depth int,
) term.Term {
	if depth > MaxRepairDepth {
		return arg
	}

	argKey := fmt.Sprintf("%s@%d@%s", arg.String(), argIndex, currentRule.Name)
	if visited[argKey] {
		return arg
	}
	visited[argKey] = true
	defer func() { delete(visited, argKey) }()

	// Find the variable/pattern in the trigger pattern that corresponds to this argument
	var triggerArgPattern term.Term
	var triggerVar *term.Variable
	if triggerPattern != nil {
		triggerFirst, _ := splitPair(triggerPattern)
		if triggerFirst != nil {
			if triggerFn, err := term.AsFunction(triggerFirst); err == nil {
				if argIndex < len(triggerFn.Args) {
					triggerArgPattern = triggerFn.Args[argIndex]
					if v, err := term.AsVariable(triggerArgPattern); err == nil {
						triggerVar = v
					}
				}
			}
		}
	}

	// Find LHS facts that contain this argument (or the corresponding variable)
	foundInLHS := false
	for _, lhsFact := range currentRule.LHS {
		// Find the position of the arg/variable in this fact
		argPosInFact := -1
		for i, factArg := range lhsFact.Args {
			if factArg.String() == arg.String() {
				argPosInFact = i
				break
			}
			if triggerVar != nil {
				if v, err := term.AsVariable(factArg); err == nil && v.String() == triggerVar.String() {
					argPosInFact = i
					break
				}
			}
		}

		if argPosInFact < 0 {
			continue
		}

		foundInLHS = true
		// Found a fact containing this arg - now find rules that produce this fact
		producingRules := m.findRulesProducingFact(lhsFact)
		for _, prodRule := range producingRules {
			// Find how the value flows from the producing rule's trigger
			resolved := m.traceValueFromRule(lhsFact, argPosInFact, prodRule, cfg, visited, depth+1)
			if resolved != nil {
				return resolved
			}
		}
	}

	// If not found in LHS facts, check if trigger pattern has a format requirement
	// (e.g., data('0x02', $m) or In(p))
	if !foundInLHS && triggerArgPattern != nil {
		// If the trigger pattern has a function structure, resolve its args and return it
		if patternFn, err := term.AsFunction(triggerArgPattern); err == nil {
			// This is a format pattern like data('0x02', $m) - resolve its variables
			bindings := make(map[string]term.Term)
			resolved := m.resolvePatternArgs(patternFn, currentRule, cfg, visited, depth+1, bindings)
			return resolved
		}
		// If it's a variable, look for it in LHS facts
		if triggerVar != nil {
			// Look for facts that might produce this variable's value
			for _, lhsFact := range currentRule.LHS {
				for argPos, factArg := range lhsFact.Args {
					if v, err := term.AsVariable(factArg); err == nil && v.String() == triggerVar.String() {
						// Found the variable in a fact - trace where it comes from
						producingRules := m.findRulesProducingFact(lhsFact)
						for _, prodRule := range producingRules {
							resolved := m.traceValueFromRule(lhsFact, argPos, prodRule, cfg, visited, depth+1)
							if resolved != nil {
								return resolved
							}
						}
					}
				}
			}
		}
	}

	// If we couldn't trace it, return the original arg
	return arg
}

// resolvePatternArgs resolves arguments within a pattern function.
// bindings accumulates resolved values for variables (e.g., lengths derived from data).
func (m *Monitor) resolvePatternArgs(
	patternFn *term.Function,
	currentRule *rule.Rule,
	cfg *Config,
	visited map[string]bool,
	depth int,
	bindings map[string]term.Term,
) term.Term {
	if depth > MaxRepairDepth {
		return patternFn
	}

	resolvedArgs := make([]term.Term, len(patternFn.Args))
	for i, arg := range patternFn.Args {
		if v, err := term.AsVariable(arg); err == nil {
			// Variable - try to resolve from LHS facts
			resolved := m.resolveVariableFromLHS(v, currentRule, cfg, visited, depth+1)
			if resolved != nil {
				resolvedArgs[i] = resolved
				bindings[v.String()] = resolved
			} else if val, ok := bindings[v.String()]; ok {
				resolvedArgs[i] = val
			} else {
				// Keep the variable - it's a free input (like $m in data('0x02', $m))
				resolvedArgs[i] = arg
			}
		} else if subFn, err := term.AsFunction(arg); err == nil {
			// Nested function - recurse
			resolvedArgs[i] = m.resolvePatternArgs(subFn, currentRule, cfg, visited, depth+1, bindings)
		} else {
			// Constant - keep as is
			resolvedArgs[i] = arg
		}
	}

	// If this pattern encodes a length, synthesize len() when appropriate.
	switch patternFn.Name {
	case "string":
		// string(data, lenVar)
		if len(patternFn.Args) >= 2 {
			if _, err := term.AsVariable(patternFn.Args[1]); err == nil {
				resolvedArgs[1] = term.NewFunction("len", []term.Term{resolvedArgs[0]})
			}
		}
	case "int":
		// int(lenVar, size)
		if len(patternFn.Args) >= 1 {
			if v, err := term.AsVariable(patternFn.Args[0]); err == nil {
				if val, ok := bindings[v.String()]; ok {
					resolvedArgs[0] = val
				}
			}
		}
	}

	return term.NewFunction(patternFn.Name, resolvedArgs)
}

// traceValueFromRule traces how a value flows from a rule's trigger to a fact argument
func (m *Monitor) traceValueFromRule(
	targetFact *rule.Fact,
	argPosInFact int,
	prodRule *rule.Rule,
	cfg *Config,
	visited map[string]bool,
	depth int,
) term.Term {
	if depth > MaxRepairDepth {
		return nil
	}

	// Find the RHS fact that matches our target fact
	var rhsFact *rule.Fact
	for _, rf := range prodRule.RHS {
		if rf.Name == targetFact.Name {
			rhsFact = rf
			break
		}
	}
	if rhsFact == nil {
		return nil
	}

	// Get the variable/term at the corresponding position in the RHS fact
	if argPosInFact >= len(rhsFact.Args) {
		return nil
	}
	rhsArg := rhsFact.Args[argPosInFact]

	// Now determine where this rhsArg comes from in the rule's trigger
	for _, trigger := range prodRule.Triggers() {
		triggerFirst, triggerSecond := splitPair(trigger)
		if triggerFirst == nil {
			continue
		}

		triggerFn, err := term.AsFunction(triggerFirst)
		if err != nil {
			continue
		}

		// Check if rhsArg comes from the trigger OUTPUT (second element of pair)
		if triggerSecond != nil && m.termsMatch(rhsArg, triggerSecond) {
			// Value comes from output - use Snd(<trigger>)
			return m.buildSndExpression(trigger, prodRule, cfg, visited, depth)
		}

		// Check if rhsArg comes from a trigger INPUT argument
		for i, triggerArg := range triggerFn.Args {
			if m.termsMatch(rhsArg, triggerArg) {
				// Value comes from input argument position i
				// Build: pick_arg(<trigger>, i)
				return m.buildPickArgExpression(trigger, i, prodRule, cfg, visited, depth)
			}
		}
	}

	return nil
}

// termsMatch checks if two terms match (either equal or same variable name)
func (m *Monitor) termsMatch(t1, t2 term.Term) bool {
	if t1.String() == t2.String() {
		return true
	}
	// Check if both are the same variable
	if v1, err1 := term.AsVariable(t1); err1 == nil {
		if v2, err2 := term.AsVariable(t2); err2 == nil {
			return v1.String() == v2.String()
		}
	}
	return false
}

// buildSndExpression builds Snd(<trigger>) expression
// This means: execute the trigger and get the output (second element of pair)
func (m *Monitor) buildSndExpression(
	trigger term.Term,
	prodRule *rule.Rule,
	cfg *Config,
	visited map[string]bool,
	depth int,
) term.Term {
	// Recursively resolve the trigger's arguments (keeping pair structure)
	resolvedTrigger := m.resolveTriggersArgs(trigger, prodRule, cfg, visited, depth)
	return term.NewFunction("Snd", []term.Term{resolvedTrigger})
}

// buildPickArgExpression builds pick_arg(<trigger>, position) expression
// This means: execute the trigger and pick the argument at the given position
func (m *Monitor) buildPickArgExpression(
	trigger term.Term,
	position int,
	prodRule *rule.Rule,
	cfg *Config,
	visited map[string]bool,
	depth int,
) term.Term {
	// Recursively resolve the trigger's arguments (keeping pair structure)
	resolvedTrigger := m.resolveTriggersArgs(trigger, prodRule, cfg, visited, depth)

	// If the trigger is a pair, get its first component; otherwise use it directly
	triggerFirst, _ := splitPair(resolvedTrigger)
	var funcTerm term.Term
	if triggerFirst != nil {
		funcTerm = triggerFirst
	} else {
		funcTerm = resolvedTrigger
	}

	positionTerm := term.NewConstant(position)
	return term.NewFunction("pick_arg", []term.Term{funcTerm, positionTerm})
}

// resolveTriggersArgs recursively resolves the arguments of a trigger
func (m *Monitor) resolveTriggersArgs(
	trigger term.Term,
	prodRule *rule.Rule,
	cfg *Config,
	visited map[string]bool,
	depth int,
) term.Term {
	if depth > MaxRepairDepth {
		return trigger
	}

	triggerFirst, triggerSecond := splitPair(trigger)
	if triggerFirst == nil {
		return trigger
	}

	triggerFn, err := term.AsFunction(triggerFirst)
	if err != nil {
		return trigger
	}

	// For each argument in the trigger, check if it needs resolution
	resolvedArgs := make([]term.Term, len(triggerFn.Args))
	for i, arg := range triggerFn.Args {
		// Check if this arg is a variable that needs resolution
		if _, err := term.AsVariable(arg); err == nil {
			// Variable - try to resolve it from the rule's LHS facts
			resolved := m.resolveVariableFromLHS(arg, prodRule, cfg, visited, depth+1)
			if resolved != nil {
				resolvedArgs[i] = resolved
			} else {
				resolvedArgs[i] = arg
			}
		} else {
			// Constant or function - keep as is but recurse into functions
			if fn, err := term.AsFunction(arg); err == nil {
				// Recursively resolve function arguments
				resolvedArgs[i] = m.resolveFunctionArgs(fn, prodRule, cfg, visited, depth+1)
			} else {
				resolvedArgs[i] = arg
			}
		}
	}

	// Rebuild the trigger with resolved arguments
	newTriggerFirst := term.NewFunction(triggerFn.Name, resolvedArgs)
	if triggerSecond != nil {
		return term.NewFunction("pair", []term.Term{newTriggerFirst, triggerSecond})
	}
	return newTriggerFirst
}

// resolveVariableFromLHS resolves a variable by looking at LHS facts
// Searches both direct arguments and nested structures
func (m *Monitor) resolveVariableFromLHS(
	v term.Term,
	r *rule.Rule,
	cfg *Config,
	visited map[string]bool,
	depth int,
) term.Term {
	if depth > MaxRepairDepth {
		return nil
	}

	varStr := v.String()

	// Find LHS facts containing this variable (including nested)
	for _, lhsFact := range r.LHS {
		// Check direct arguments first
		for argPos, factArg := range lhsFact.Args {
			if factArg.String() == varStr {
				// Found the variable directly - find rules that produce this fact
				producingRules := m.findRulesProducingFact(lhsFact)
				for _, prodRule := range producingRules {
					resolved := m.traceValueFromRule(lhsFact, argPos, prodRule, cfg, visited, depth+1)
					if resolved != nil {
						return resolved
					}
				}
			}

			// Check if variable is nested inside this argument (e.g., In(payload('0x02', m, h)))
			if nestedPos := m.findVariableInTerm(factArg, varStr); nestedPos != nil {
				// Variable is nested - we need to trace the containing fact and extract
				producingRules := m.findRulesProducingFact(lhsFact)
				for _, prodRule := range producingRules {
					// First get how the fact arg is produced
					resolved := m.traceValueFromRule(lhsFact, argPos, prodRule, cfg, visited, depth+1)
					// If the fact argument is a function pattern, resolve it to preserve format structure
					var patternResolved term.Term
					if fn, err := term.AsFunction(factArg); err == nil {
						bindings := make(map[string]term.Term)
						patternResolved = m.resolvePatternArgs(fn, prodRule, cfg, visited, depth+1, bindings)
						// If resolved is Snd(<pair>), replace the second element with the pattern to keep format
						if resolved != nil {
							if sndFn, err := term.AsFunction(resolved); err == nil && sndFn.Name == "Snd" && len(sndFn.Args) == 1 {
								if pairFn, err := term.AsFunction(sndFn.Args[0]); err == nil && pairFn.Name == "pair" && len(pairFn.Args) == 2 {
									newPair := term.NewFunction("pair", []term.Term{pairFn.Args[0], patternResolved})
									resolved = term.NewFunction("Snd", []term.Term{newPair})
								}
							}
						}
					}
					if resolved != nil {
						// Now build extraction with pick_arg chain
						return m.buildNestedSelection(resolved, nestedPos)
					}
				}
			}
		}
	}

	return nil
}

// findVariableInTerm finds a variable inside a term and returns the path to it
// Returns nil if not found, otherwise returns slice of positions
func (m *Monitor) findVariableInTerm(t term.Term, varStr string) []int {
	if t.String() == varStr {
		return []int{} // Found at this level
	}

	fn, err := term.AsFunction(t)
	if err != nil {
		return nil
	}

	for i, arg := range fn.Args {
		if subPath := m.findVariableInTerm(arg, varStr); subPath != nil {
			return append([]int{i}, subPath...)
		}
	}

	return nil
}

// buildNestedSelection builds nested pick_arg(...) projections along positions.
// This stays generic and uses only the helper function pick_arg(func(args), idx).
func (m *Monitor) buildNestedSelection(base term.Term, positions []int) term.Term {
	result := base
	for _, pos := range positions {
		result = term.NewFunction("pick_arg", []term.Term{result, term.NewConstant(pos)})
	}
	return result
}

// resolveFunctionArgs recursively resolves arguments of a function term
func (m *Monitor) resolveFunctionArgs(
	fn *term.Function,
	r *rule.Rule,
	cfg *Config,
	visited map[string]bool,
	depth int,
) term.Term {
	if depth > MaxRepairDepth {
		return fn
	}

	resolvedArgs := make([]term.Term, len(fn.Args))
	for i, arg := range fn.Args {
		if _, err := term.AsVariable(arg); err == nil {
			resolved := m.resolveVariableFromLHS(arg, r, cfg, visited, depth+1)
			if resolved != nil {
				resolvedArgs[i] = resolved
			} else {
				resolvedArgs[i] = arg
			}
		} else if subFn, err := term.AsFunction(arg); err == nil {
			resolvedArgs[i] = m.resolveFunctionArgs(subFn, r, cfg, visited, depth+1)
		} else {
			resolvedArgs[i] = arg
		}
	}

	return term.NewFunction(fn.Name, resolvedArgs)
}

// findRulesProducingFact finds rules whose RHS contains a fact with the given name
func (m *Monitor) findRulesProducingFact(targetFact *rule.Fact) []*rule.Rule {
	var rules []*rule.Rule

	for _, ruleSet := range m.rules {
		for _, r := range ruleSet {
			for _, rhsFact := range r.RHS {
				if rhsFact.Name == targetFact.Name {
					rules = append(rules, r)
					break
				}
			}
		}
	}

	return rules
}

// unifyEventWithRuleTrigger attempts to unify an event with a rule's trigger
func (m *Monitor) unifyEventWithRuleTrigger(event term.Term, r *rule.Rule) *term.Binding {
	for _, trigger := range r.Triggers() {
		binding, err := m.safeUnify(trigger, event)
		if err == nil && binding != nil {
			return binding
		}
	}

	// Try partial unification
	eventFirst, _ := splitPair(event)
	if eventFirst != nil {
		for _, trigger := range r.Triggers() {
			triggerFirst, _ := splitPair(trigger)
			if triggerFirst != nil {
				if binding, err := m.partialUnify(eventFirst, triggerFirst); err == nil && binding != nil {
					return binding
				}
			}
		}
	}

	return nil
}

// buildLegalEvent builds the legal event from accepted and resolved args
func (m *Monitor) buildLegalEvent(
	eventFn *term.Function,
	eventOutput term.Term,
	result *RepairResult,
) term.Term {
	args := make([]term.Term, len(eventFn.Args))
	for i := range eventFn.Args {
		if accepted, ok := result.AcceptedArgs[i]; ok {
			args[i] = accepted
		} else if resolved, ok := result.ResolvedArgs[i]; ok {
			args[i] = resolved
		} else {
			args[i] = eventFn.Args[i]
		}
	}

	newEventFn := term.NewFunction(eventFn.Name, args)
	// Build placeholder output if original event had an output
	if eventOutput != nil {
		// Use a variable placeholder named from the concatenated letters of the expression
		placeholder := term.NewVariable(m.placeholderFromTerm(newEventFn))
		return term.NewFunction("pair", []term.Term{newEventFn, placeholder})
	}
	return newEventFn
}

// placeholderFromTerm generates a placeholder name by concatenating only letters
// from the string representation of a term, removing brackets, spaces, commas, digits, etc.
func (m *Monitor) placeholderFromTerm(t term.Term) string {
	s := t.String()
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "result"
	}
	return b.String()
}

// deduplicateRepairResults removes duplicate repair results (e.g., from multiple configurations)
// Keyed by rule name + legal event string.
func (m *Monitor) deduplicateRepairResults(results []RepairResult) []RepairResult {
	seen := make(map[string]bool)
	var unique []RepairResult

	for _, res := range results {
		key := res.RuleName + "|" + res.LegalEvent.String()
		if !seen[key] {
			seen[key] = true
			unique = append(unique, res)
		}
	}

	return unique
}

// configHasFact checks if config has a fact
func (m *Monitor) configHasFact(cfg *Config, target *rule.Fact) bool {
	for _, f := range cfg.facts {
		if f.Name == target.Name {
			if _, err := f.Unify(target); err == nil {
				return true
			}
		}
	}
	return false
}

// safeUnify wraps Unify with panic recovery
func (m *Monitor) safeUnify(pattern, event term.Term) (binding *term.Binding, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("[safeUnify] PANIC recovered: %v", r)
			err = fmt.Errorf("unification failed: %v", r)
			binding = nil
		}
	}()
	binding, err = pattern.Unify(event)
	return
}

// partialUnify attempts partial unification
func (m *Monitor) partialUnify(event, pattern term.Term) (*term.Binding, error) {
	eventFn, err1 := term.AsFunction(event)
	patternFn, err2 := term.AsFunction(pattern)

	if err1 != nil || err2 != nil || eventFn.Name != patternFn.Name {
		return nil, fmt.Errorf("cannot partially unify")
	}

	binding := term.NewBinding()
	minLen := len(eventFn.Args)
	if len(patternFn.Args) < minLen {
		minLen = len(patternFn.Args)
	}

	for i := 0; i < minLen; i++ {
		if b, err := m.safeUnify(patternFn.Args[i], eventFn.Args[i]); err == nil && b != nil {
			binding = binding.Extend(b)
		}
	}

	return binding, nil
}

// FormatRepairResults formats repair results for display
func FormatRepairResults(results []RepairResult) string {
	if len(results) == 0 {
		return "No repair plans found"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Found %d repair plan(s):\n\n", len(results)))

	for i, result := range results {
		eventFuncName := splitPairFirstName(result.OriginalEvent)
		sb.WriteString(fmt.Sprintf("=== Plan %d: Event: %s (rule: %s) ===\n", i+1, eventFuncName, result.RuleName))
		sb.WriteString(fmt.Sprintf("Original event: %s\n", result.OriginalEvent))
		sb.WriteString(fmt.Sprintf("Legal event:    %s\n", result.LegalEvent))

		if len(result.AcceptedArgs) > 0 {
			sb.WriteString("Accepted arguments (from config):\n")
			for idx, arg := range result.AcceptedArgs {
				sb.WriteString(fmt.Sprintf("  arg[%d]: %s\n", idx, arg))
			}
		}

		if len(result.ResolvedArgs) > 0 {
			sb.WriteString("Resolved arguments (need computation):\n")
			for idx, arg := range result.ResolvedArgs {
				sb.WriteString(fmt.Sprintf("  arg[%d]: %s\n", idx, arg))
			}
		}

		sb.WriteString("\n")
	}

	return sb.String()
}

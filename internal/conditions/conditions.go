package conditions

import (
	"strings"

	"github.com/jeandreh/iam-snitch/internal/domain/model"
)

// ConditionContext contains information available at refresh time that can be used
// to evaluate policy condition statements.
//
// Most condition evaluations depend on runtime request context (principal tags,
// request IP, time, etc.). The refresh process can only evaluate what it knows
// at refresh time (e.g., resource tags, resource ARN).
//
// Implementations can extend this struct in the future.
type ConditionContext struct {
	ResourceARN  string
	ResourceTags map[string]string
	// PrincipalTags are tags attached to the principal (role/user). These are usually
	// only available at request time, so refresh-time evaluation typically cannot
	// resolve them.
	PrincipalTags map[string]string
}

// EvaluatorFunc evaluates a single condition value.
// It returns (matched, handled).
// - matched indicates whether the condition evaluated to true.
// - handled indicates whether the evaluator could resolve the condition.
//   If handled is false, the condition should be treated as "unchecked".
//   If handled is true and matched is false, the statement should not apply.
//   If handled is true and matched is true, the statement may apply (subject to other conditions).
type EvaluatorFunc func(ctx ConditionContext, key string, value interface{}) (matched bool, handled bool)

// KeyMatcher returns true if this evaluator can handle the given condition key.
// Keys are typically things like "aws:ResourceTag/Env".
type KeyMatcher func(key string) bool

type evaluatorEntry struct {
	matches KeyMatcher
	eval    EvaluatorFunc
}

var (
	registry = make(map[string][]evaluatorEntry)
)

// RegisterEvaluator registers an evaluator for the given operator.
// Multiple evaluators can be registered for the same operator (e.g., different keys).
func RegisterEvaluator(operator string, matches KeyMatcher, eval EvaluatorFunc) {
	registry[operator] = append(registry[operator], evaluatorEntry{matches: matches, eval: eval})
}

// EvaluateConditions evaluates a policy statement's condition map.
//
// It returns:
//   - matched: true if the statement is not disqualified by any handled condition.
//   - unchecked: conditions that could not be evaluated (to be surfaced to users).
//
// A condition is treated as "unchecked" if no registered evaluator handled it.
// If any handled condition evaluates to false, the statement is treated as not matched.
func EvaluateConditions(conds map[string]map[string]interface{}, ctx ConditionContext) (matched bool, unchecked []model.Condition) {
	if len(conds) == 0 {
		return true, nil
	}

	matched = true
	for op, keys := range conds {
		for key, value := range keys {
			evaluators := registry[op]
			handled := false
			evaluatedTrue := true
			for _, e := range evaluators {
				if !e.matches(key) {
					continue
				}
				matched, ok := e.eval(ctx, key, value)
				handled = true
				if !ok {
					evaluatedTrue = false
					break
				}
				if !matched {
					evaluatedTrue = false
					break
				}
			}

			if !handled {
				unchecked = append(unchecked, model.Condition{Operator: op, Key: key, Value: value})
				continue
			}

			if !evaluatedTrue {
				// A handled condition evaluated to false: the statement cannot apply.
				return false, nil
			}
		}
	}

	return matched, unchecked
}

// matchPrefix returns a KeyMatcher that matches keys starting with the given prefix.
func matchPrefix(prefix string) KeyMatcher {
	return func(key string) bool {
		return strings.HasPrefix(key, prefix)
	}
}

// matchExact returns a KeyMatcher that matches keys equal to the given target.
func matchExact(target string) KeyMatcher {
	return func(key string) bool {
		return key == target
	}
}

// matchSimpleGlob supports simple wildcard matching where '*' can match any sequence.
// This is used for StringLike evaluation.
func matchSimpleGlob(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == value
	}

	// Prefix
	if len(parts[0]) > 0 && !strings.HasPrefix(value, parts[0]) {
		return false
	}

	// Suffix
	last := parts[len(parts)-1]
	if len(last) > 0 && !strings.HasSuffix(value, last) {
		return false
	}

	// Middle segments
	pos := len(parts[0])
	for _, part := range parts[1 : len(parts)-1] {
		if part == "" {
			continue
		}
		idx := strings.Index(value[pos:], part)
		if idx == -1 {
			return false
		}
		pos += idx + len(part)
	}

	return true
}

func init() {
	// Register default evaluators for resource tag conditions.
	RegisterEvaluator("StringEquals", matchPrefix("aws:ResourceTag/"), evalResourceTagEquals)
	RegisterEvaluator("StringLike", matchPrefix("aws:ResourceTag/"), evalResourceTagLike)
}

func evalResourceTagEquals(ctx ConditionContext, key string, value interface{}) (bool, bool) {
	if !strings.HasPrefix(key, "aws:ResourceTag/") {
		return false, false
	}
	tagKey := strings.TrimPrefix(key, "aws:ResourceTag/")
	if ctx.ResourceTags == nil {
		return false, false
	}

	tagVal, ok := ctx.ResourceTags[tagKey]
	if !ok {
		return false, true
	}

	vals := normalizeConditionValue(value)
	for _, v := range vals {
		if v == tagVal {
			return true, true
		}
	}
	return false, true
}

func evalResourceTagLike(ctx ConditionContext, key string, value interface{}) (bool, bool) {
	if !strings.HasPrefix(key, "aws:ResourceTag/") {
		return false, false
	}
	tagKey := strings.TrimPrefix(key, "aws:ResourceTag/")
	if ctx.ResourceTags == nil {
		return false, false
	}

	tagVal, ok := ctx.ResourceTags[tagKey]
	if !ok {
		return false, true
	}

	vals := normalizeConditionValue(value)
	for _, v := range vals {
		if matchSimpleGlob(v, tagVal) {
			return true, true
		}
	}
	return false, true
}

func normalizeConditionValue(v interface{}) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	default:
		return nil
	}
}

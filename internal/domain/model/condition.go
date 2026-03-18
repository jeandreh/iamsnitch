package model

// Condition represents a parsed IAM policy condition (operator + key + value).
//
// The value can be a string or a slice of string values, matching how AWS represents
// Condition values in JSON.
//
// This type is used to carry "unchecked" conditions in AccessControlRule results when
// the evaluation engine cannot resolve the condition at refresh time (e.g., principal tags).
// Those conditions are then surfaced to the user so they know the rule is conditional.
//
// See internal/conditions for the evaluator registry that attempts to resolve conditions.
type Condition struct {
	Operator string      `json:"operator"`
	Key      string      `json:"key"`
	Value    interface{} `json:"value"`
}

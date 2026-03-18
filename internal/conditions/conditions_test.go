package conditions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConditionContext(t *testing.T) {
	ctx := ConditionContext{
		ResourceARN:  "arn:aws:s3:::mybucket",
		ResourceTags: map[string]string{"Env": "prod", "Team": "dev"},
		PrincipalTags: map[string]string{"Role": "admin"},
	}

	assert.Equal(t, "arn:aws:s3:::mybucket", ctx.ResourceARN)
	assert.Equal(t, map[string]string{"Env": "prod", "Team": "dev"}, ctx.ResourceTags)
	assert.Equal(t, map[string]string{"Role": "admin"}, ctx.PrincipalTags)
}

func TestRegistry(t *testing.T) {
	// Reset registry for test
	registry = make(map[string][]evaluatorEntry)

	// Test registering an evaluator
	RegisterEvaluator("StringEquals", matchPrefix("aws:ResourceTag/"), evalResourceTagEquals)

	entries := registry["StringEquals"]
	require.Len(t, entries, 1)
	assert.NotNil(t, entries[0].matches)
	assert.NotNil(t, entries[0].eval)
}

func TestEvaluateConditions(t *testing.T) {
	// Reset registry
	registry = make(map[string][]evaluatorEntry)

	// Register evaluator
	RegisterEvaluator("StringEquals", matchPrefix("aws:ResourceTag/"), evalResourceTagEquals)

	ctx := ConditionContext{
		ResourceARN:  "arn:aws:s3:::mybucket",
		ResourceTags: map[string]string{"Env": "prod"},
	}

	conditions := map[string]map[string]interface{}{
		"StringEquals": {
			"aws:ResourceTag/Env": "prod",
		},
	}

	matched, unchecked := EvaluateConditions(conditions, ctx)
	assert.True(t, matched)
	assert.Empty(t, unchecked)
}

func TestEvaluateConditionsWithUnchecked(t *testing.T) {
	// Reset registry
	registry = make(map[string][]evaluatorEntry)

	// Register evaluator
	RegisterEvaluator("StringEquals", matchPrefix("aws:ResourceTag/"), evalResourceTagEquals)

	ctx := ConditionContext{
		ResourceARN:  "arn:aws:s3:::mybucket",
		ResourceTags: map[string]string{"Env": "prod"},
	}

	conditions := map[string]map[string]interface{}{
		"StringEquals": {
			"aws:ResourceTag/Env":    "prod", // handled, matches
			"aws:PrincipalTag/Role": "admin", // not handled
		},
	}

	matched, unchecked := EvaluateConditions(conditions, ctx)
	assert.True(t, matched)
	require.Len(t, unchecked, 1)
	assert.Equal(t, "StringEquals", unchecked[0].Operator)
	assert.Equal(t, "aws:PrincipalTag/Role", unchecked[0].Key)
	assert.Equal(t, "admin", unchecked[0].Value)
}

func TestEvaluateConditionsMismatch(t *testing.T) {
	// Reset registry
	registry = make(map[string][]evaluatorEntry)

	// Register evaluator
	RegisterEvaluator("StringEquals", matchPrefix("aws:ResourceTag/"), evalResourceTagEquals)

	ctx := ConditionContext{
		ResourceARN:  "arn:aws:s3:::mybucket",
		ResourceTags: map[string]string{"Env": "prod"},
	}

	conditions := map[string]map[string]interface{}{
		"StringEquals": {
			"aws:ResourceTag/Env": "dev", // handled but doesn't match
		},
	}

	matched, unchecked := EvaluateConditions(conditions, ctx)
	assert.False(t, matched)
	assert.Empty(t, unchecked)
}

func TestEvaluateConditionsNoEvaluators(t *testing.T) {
	// Reset registry (no evaluators registered)
	registry = make(map[string][]evaluatorEntry)

	ctx := ConditionContext{
		ResourceARN:  "arn:aws:s3:::mybucket",
		ResourceTags: map[string]string{"Env": "prod"},
	}

	conditions := map[string]map[string]interface{}{
		"StringEquals": {
			"aws:PrincipalTag/Role": "admin",
		},
	}

	matched, unchecked := EvaluateConditions(conditions, ctx)
	assert.True(t, matched) // Default to true when no evaluators can handle
	require.Len(t, unchecked, 1)
	assert.Equal(t, "StringEquals", unchecked[0].Operator)
	assert.Equal(t, "aws:PrincipalTag/Role", unchecked[0].Key)
	assert.Equal(t, "admin", unchecked[0].Value)
}

func TestEvalResourceTagEquals(t *testing.T) {
	ctx := ConditionContext{
		ResourceTags: map[string]string{"Env": "prod", "Team": "dev"},
	}

	tests := []struct {
		name     string
		key      string
		value    interface{}
		expected bool
		handled  bool
	}{
		{"matching resource tag", "aws:ResourceTag/Env", "prod", true, true},
		{"non-matching resource tag", "aws:ResourceTag/Env", "dev", false, true},
		{"non-existent resource tag", "aws:ResourceTag/Owner", "alice", false, true},
		{"principal tag (not handled)", "aws:PrincipalTag/Role", "admin", false, false},
		{"unknown key (not handled)", "aws:userid", "123", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, handled := evalResourceTagEquals(ctx, tt.key, tt.value)
			assert.Equal(t, tt.expected, matched)
			assert.Equal(t, tt.handled, handled)
		})
	}
}

func TestEvalResourceTagLike(t *testing.T) {
	ctx := ConditionContext{
		ResourceTags: map[string]string{"Env": "production", "Team": "dev-team"},
	}

	tests := []struct {
		name     string
		key      string
		value    interface{}
		expected bool
		handled  bool
	}{
		{"wildcard prefix", "aws:ResourceTag/Env", "prod*", true, true},
		{"wildcard suffix", "aws:ResourceTag/Team", "*team", true, true},
		{"exact match", "aws:ResourceTag/Env", "production", true, true},
		{"no match", "aws:ResourceTag/Env", "dev*", false, true},
		{"principal tag (not handled)", "aws:PrincipalTag/Role", "admin*", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, handled := evalResourceTagLike(ctx, tt.key, tt.value)
			assert.Equal(t, tt.expected, matched)
			assert.Equal(t, tt.handled, handled)
		})
	}
}

func TestNormalizeConditionValue(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected []string
	}{
		{"string", "value", []string{"value"}},
		{"string slice", []string{"a", "b"}, []string{"a", "b"}},
		{"interface slice", []interface{}{"a", "b"}, []string{"a", "b"}},
		{"mixed interface slice", []interface{}{"a", 123}, []string{"a"}},
		{"empty slice", []interface{}{}, []string{}},
		{"nil", nil, nil},
		{"int", 123, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeConditionValue(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
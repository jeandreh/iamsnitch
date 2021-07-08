package aws

import (
	"encoding/json"
)

type Policy struct {
	Version    string      `json:"Version"`
	Statements []Statement `json:"Statement"`
}

type IdentityPolicy struct {
	ARN  string
	Name string
	Policy
}

type AssumePolicy struct {
	RoleID uint
	Policy
}

type ResourcePolicy struct {
	ResourceID uint
	Policy
}

func NewIdentityPolicy(arn string, name string, policyDocument string) (*IdentityPolicy, error) {
	var policy IdentityPolicy

	if err := json.Unmarshal([]byte(policyDocument), &policy); err != nil {
		return nil, err
	}

	policy.ARN = arn
	policy.Name = name

	return &policy, nil
}

func NewAssumePolicy(policyDocument string) (*AssumePolicy, error) {
	var policy AssumePolicy

	if err := json.Unmarshal([]byte(policyDocument), &policy); err != nil {
		return nil, err
	}

	return &policy, nil
}

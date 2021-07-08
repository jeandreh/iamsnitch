package iamsnitch

import (
	"encoding/json"

	"gorm.io/gorm"
)

type Policy struct {
	Version    string      `json:"Version"`
	Statements []Statement `json:"Statement"`
}

type IAMPolicy struct {
	gorm.Model
	ARN    string
	Name   string
	Policy `gorm:"polymorphic:Policy"`
}

type AssumePolicy struct {
	gorm.Model
	RoleID uint
	Policy `gorm:"polymorphic:Policy"`
}

type ResourcePolicy struct {
	gorm.Model
	ResourceID uint
	Policy     `gorm:"polymorphic:Policy"`
}

func NewIAM(arn string, name string, policyDocument string) (*IAMPolicy, error) {
	var policy IAMPolicy

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

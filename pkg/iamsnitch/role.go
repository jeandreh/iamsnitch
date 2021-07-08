package iamsnitch

import "gorm.io/gorm"

type Role struct {
	gorm.Model
	ARN          string
	Name         string
	AssumePolicy *AssumePolicy
	Identities   []Identity  `gorm:"many2many:role_identities;"`
	Policies     []IAMPolicy `gorm:"many2many:role_policies;"`
}

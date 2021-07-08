package iamsnitch

import (
	"gorm.io/gorm"
)

type Statement struct {
	gorm.Model
	PolicyID   uint
	PolicyType string
	Effect     string        `json:"Effect"`
	Principals PrincipalList `json:"Principal"`
	Actions    ActionList    `json:"Action"`
	Resources  ResourceList  `json:"Resource"`
}

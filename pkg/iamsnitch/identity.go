package iamsnitch

import "gorm.io/gorm"

type Identity struct {
	gorm.Model
	ARN  string
	Name string
}

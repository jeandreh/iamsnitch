package iamsnitch

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func NewDB() (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open(".snitch.db"), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	db.AutoMigrate(
		&ActionList{},
		&Action{},
		&ResourceList{},
		&Resource{},
		&PrincipalList{},
		&Principal{},
		&Value{},
		&Identity{},
		&Statement{},
		&IAMPolicy{},
		&AssumePolicy{},
		&ResourcePolicy{},
		&Role{},
	)

	return db, nil
}

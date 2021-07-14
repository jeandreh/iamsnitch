package cache

import (
	"log"

	"github.com/jeandreh/iam-snitch/internal/domain"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type SQLiteCache struct {
	db *gorm.DB
}

var _ domain.CacheIface = (*SQLiteCache)(nil)

func NewCache() (*SQLiteCache, error) {
	db, err := gorm.Open(sqlite.Open(".snitch.db"), &gorm.Config{
		// Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return nil, err
	}

	db.AutoMigrate(
		&AccessControlRule{},
		&Permission{},
		&Grant{},
	)

	return &SQLiteCache{db: db}, nil
}

func (c *SQLiteCache) SaveACL(rules []domain.AccessControlRule) error {
	log.Printf("%v rules saved to cache", len(rules))
	for _, dr := range rules {
		var lr AccessControlRule

		result := c.db.Find(&lr, "rule_id = ?", dr.ID())
		if result.Error != nil {
			return result.Error
		}

		if result.RowsAffected == 1 {
			lr.Principal = dr.Principal.ID
			lr.Resource = dr.Resource.ID
			lr.Permissions = mapPermissions(dr.Permissions)
			c.db.Save(&lr)
		} else {
			nr := NewAccessControlRule(&dr)
			result = c.db.Save(nr)
			if result.Error != nil {
				return result.Error
			}
		}
	}
	return nil
}

func (c *SQLiteCache) Find(filter *domain.Filter) ([]domain.AccessControlRule, error) {
	var filteredRules []AccessControlRule

	// first we search for permissions matching the list filter.Actions
	subQuery := c.db.
		Table("permissions").
		Where("action IN (?)", filter.ActionsAsString()).
		Select("access_control_rule_id")

	// then we use the list to further filter the list of rules
	result := c.db.
		Where("resource IN (?) AND id IN (?)", filter.ResourcesAsString(), subQuery).
		Find(&filteredRules)

	if result.Error != nil {
		return nil, result.Error
	}

	// once we have the matchihg rules, we load the associations
	for i := 0; i < len(filteredRules); i++ {
		err := c.db.Model(&filteredRules[i]).
			Preload("GrantChain").
			Association("Permissions").
			Find(&filteredRules[i].Permissions)

		if err != nil {
			return nil, err
		}
	}

	var acl []domain.AccessControlRule
	for _, r := range filteredRules {
		acl = append(acl, r.Map())
	}

	return acl, nil
}

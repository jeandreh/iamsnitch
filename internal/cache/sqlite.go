package cache

import (
	"fmt"

	"github.com/jeandreh/iam-snitch/internal/domain/model"
	"github.com/jeandreh/iam-snitch/internal/domain/ports"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type SQLiteCache struct {
	db *gorm.DB
}

var _ ports.CacheIface = (*SQLiteCache)(nil)

func New() (*SQLiteCache, error) {
	return new(".snitch.db", &gorm.Config{})
}

func new(connStr string, config *gorm.Config) (*SQLiteCache, error) {
	db, err := gorm.Open(sqlite.Open(connStr), config)
	if err != nil {
		return nil, err
	}

	db.AutoMigrate(
		&AccessControlRule{},
		&Grant{},
	)

	return &SQLiteCache{db: db}, nil
}

func (c *SQLiteCache) SaveACL(rules []model.AccessControlRule) error {
	fmt.Printf("%v rules saved to cache\n", len(rules))
	for _, dr := range rules {
		var lr AccessControlRule

		result := c.db.Find(&lr, "rule_id = ?", dr.ID())
		if result.Error != nil {
			return result.Error
		}

		if result.RowsAffected == 1 {
			lr.Principal = dr.Principal.ID
			lr.Permission = dr.Permission.ID
			lr.Resource = dr.Resource.ID
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

func (c *SQLiteCache) Find(filter *model.Filter) ([]model.AccessControlRule, error) {
	var filteredRules []AccessControlRule

	tx := c.db.
		Preload("GrantChain").
		Where(
			buildWhereExpr("resource", filter.ResourcesAsString(), filter.ExactMatch),
			buildWhereExpr("permission", filter.Actions, filter.ExactMatch),
		).
		Find(&filteredRules)

	if tx.Error != nil {
		return nil, tx.Error
	}

	var acl []model.AccessControlRule
	for _, r := range filteredRules {
		acl = append(acl, r.Map())
	}
	return acl, nil
}

func buildWhereExpr(column string, filters []string, exact bool) clause.Where {
	operation := "GLOB"
	if exact {
		operation = "="
	}

	var exprs []clause.Expression
	for _, v := range filters {
		exprs = append(exprs, clause.Expr{
			SQL:  fmt.Sprintf("%s %s ?", column, operation),
			Vars: []interface{}{v},
		})
	}

	return clause.Where{
		Exprs: []clause.Expression{
			clause.OrConditions{
				Exprs: exprs,
			},
		},
	}
}

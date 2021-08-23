package cache

import (
	"database/sql"
	"fmt"

	"github.com/jeandreh/iam-snitch/internal/domain/model"
	"github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func init() {
	sql.Register("sqlite3_extended",
		&sqlite3.SQLiteDriver{
			ConnectHook: func(conn *sqlite3.SQLiteConn) error {
				return conn.RegisterFunc("match", match, true)
			},
		},
	)
}

type SQLiteCache struct {
	db *gorm.DB
}

func New() (*SQLiteCache, error) {
	return new(".snitch.db", &gorm.Config{})
}

func (c *SQLiteCache) SaveACL(rules []model.AccessControlRule) error {
	for _, r := range rules {
		var lr AccessControlRule

		result := c.db.Find(&lr, "rule_id = ?", r.ID())
		if result.Error != nil {
			logrus.WithFields(logrus.Fields{
				"rule":  r,
				"error": result.Error,
			}).Error("failed to load rule from cache")
			return result.Error
		}

		if result.RowsAffected == 1 {
			lr.Principal = r.Principal.ID
			lr.Permission = r.Permission.ID
			lr.Resource = r.Resource.ID
			c.db.Save(&lr)
		} else {
			result = c.db.Save(NewRule(&r))
			if result.Error != nil {
				logrus.WithFields(logrus.Fields{
					"rule":  lr,
					"error": result.Error,
				}).Error("failed to save rule to cache")
				return result.Error
			}
		}
	}
	fmt.Printf("%v rules saved to cache\n", len(rules))
	return nil
}

func (c *SQLiteCache) Find(filter *model.Filter) ([]model.AccessControlRule, error) {
	var filteredRules []AccessControlRule

	tx := c.db.
		Preload("GrantChain").
		Where(
			clause.Expr{
				SQL:  "match(resource, ?)",
				Vars: []interface{}{filter.Resources[0]},
			},
			buildWhereExpr("permission", filter.Permissions, filter.ExactMatch),
		).
		Find(&filteredRules)

	if tx.Error != nil {
		return nil, tx.Error
	}

	acl := make([]model.AccessControlRule, 0, len(filteredRules))
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

	exprs := make([]clause.Expression, 0, len(filters))
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

func new(connStr string, config *gorm.Config) (*SQLiteCache, error) {
	db, err := gorm.Open(
		sqlite.Dialector{
			DriverName: "sqlite3_extended",
			DSN:        connStr,
		},
		config,
	)

	if err != nil {
		return nil, err
	}

	db.AutoMigrate(
		&AccessControlRule{},
		&Grant{},
	)

	return &SQLiteCache{db: db}, nil
}

func match(s1, s2 string) bool {
	var i1, i2 int

	for i1 < len(s1) && i2 < len(s2) {
		if s1[i1] == '*' {
			i1++
			if s2[i2] == '*' {
				i2++
				continue
			}

			adv, delim := findDelim(s1[i1:])
			if delim == 0 {
				return true
			}
			i1 += adv

			adv = stripMatch(delim, s2[i2:])
			if adv == 0 {
				return false
			}
			i2 += adv

			if i1 >= len(s1) && i2 < len(s2) {
				return false
			}
		} else if s2[i2] == '*' {
			i2++

			adv, delim := findDelim(s2[i2:])
			if delim == 0 {
				return true
			}
			i2 += adv

			adv = stripMatch(delim, s1[i1:])
			if adv == 0 {
				return false
			}
			i1 += adv

			if i2 >= len(s2) && i1 < len(s1) {
				return false
			}
		} else {
			if s1[i1] != s2[i2] {
				return false
			}
			i1++
			i2++
		}
	}
	return true
}

func findDelim(s string) (adv int, delim byte) {
	for i, v := range s {
		if v != '*' {
			delim = byte(v)
			adv = i + 1
			break
		}
	}
	return
}

func stripMatch(delim byte, s string) (adv int) {
	for i, v := range s {
		if v == rune(delim) {
			adv = i + 1
			break
		}
		if v == '*' {
			adv = i + 2
			break
		}
	}
	return
}

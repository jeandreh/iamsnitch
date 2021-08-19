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
	sql.Register("sqlite3_extended",
		&sqlite3.SQLiteDriver{
			ConnectHook: func(conn *sqlite3.SQLiteConn) error {
				return conn.RegisterFunc("match", match, true)
			},
		},
	)

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

// aws:*:ap-*:2893483479:*:test/somedir/obj
// aws:s3:*:2893483479:mybucket:*

func match(s1, s2 string) bool {
	i1, i2 := 0, 0
	for i1 < len(s1) {
		if s1[i1] == '*' {
			if s2[i2] == '*' {
				i1++
				i2++
				continue
			}
			var delim byte
			for j := i1 + 1; j < len(s1); j++ {
				if s1[j] != '*' {
					delim = s1[j]
					i1 = j
					break
				}
			}
			if delim == 0 {
				return true
			}
			found := false
			for j := i2; j < len(s2); j++ {
				if s2[j] == delim {
					i2 = j
					found = true
					break
				}
				if s2[j] == '*' {
					i2 = j + 1
					found = true
					break
				}
			}
			if !found {
				return false
			}
		} else if s2[i2] == '*' {
			if s1[i1] == '*' {
				i1++
				i2++
				continue
			}
			var delim byte
			for j := i2 + 1; j < len(s2); j++ {
				if s2[j] != '*' {
					delim = s2[j]
					i2 = j
					break
				}
			}
			if delim == 0 {
				return true
			}
			found := false
			for j := i1 + 1; j < len(s1); j++ {
				if s1[j] == delim {
					i1 = j
					found = true
					break
				}
				if s1[j] == '*' {
					i1 = j + 1
					found = true
					break
				}
			}
			if !found {
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

// func match(re, s string) (bool, error) {
// 	re = strings.Replace(re, "*", ".*", -1)
// 	re = strings.Replace(re, "?", ".?", -1)
// 	return regexp.MatchString(re, s)
// }

func findDelim(s string) (delim byte) {
	for _, v := range s {
		if v != '*' {
			delim = byte(v)
			break
		}
	}
	return
}

func matchingString(s string) (string, bool) {

	var delim byte
	for j := i1 + 1; j < len(s1); j++ {
		if s1[j] != '*' {
			delim = s1[j]
			i1 = j
			break
		}
	}
	if delim == 0 {
		return true
	}
	found := false
	for j := i2; j < len(s2); j++ {
		if s2[j] == delim {
			i2 = j
			found = true
			break
		}
		if s2[j] == '*' {
			i2 = j + 1
			found = true
			break
		}
	}
	if !found {
		return false
	}
}

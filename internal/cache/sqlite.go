package cache

import (
	"database/sql"
	"fmt"
	"strings"

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
			buildWhereExpr("resource", filter.Resources, filter.ExactMatch),
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
	operation := "match(%s, ?)"
	if exact {
		operation = "%s = ?"
	}

	exprs := make([]clause.Expression, 0, len(filters))
	for _, v := range filters {
		exprs = append(exprs, clause.Expr{
			SQL:  fmt.Sprintf(operation, column),
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
	// Special case: if s1 is an ARN and s2 contains wildcards, use AWS ARN matching
	if strings.HasPrefix(s1, "arn:") && strings.Contains(s2, "*") {
		return matchUnidirectional(s1, s2)
	}

	// If either string contains wildcards, use complex bidirectional matching
	if strings.Contains(s1, "*") || strings.Contains(s2, "*") {
		return matchComplex(s1, s2)
	}

	// Otherwise, assume s1 is stored value, s2 is user pattern
	return matchUnidirectional(s1, s2)
}

func matchUnidirectional(storedValue, userPattern string) bool {
	if userPattern == "*" {
		return true
	}

	if storedValue == userPattern {
		return true
	}

	// For ARN-like stored values, use segment-aware matching
	if strings.HasPrefix(storedValue, "arn:") {
		return matchARNPattern(storedValue, userPattern)
	}

	// For other values (permissions, etc.), use simple glob matching
	return matchSimpleGlob(userPattern, storedValue)
}

func matchARNPattern(arn, pattern string) bool {
	// Check if pattern is just "*"
	if pattern == "*" {
		return true
	}

	// If pattern doesn't contain wildcards, exact match
	if !strings.Contains(pattern, "*") {
		return arn == pattern
	}

	// Apply AWS ARN wildcard rules: * doesn't cross segment boundaries
	arnSegments := splitARNByDelimiters(arn)
	patternSegments := splitARNByDelimiters(pattern)

	// Must have same number of segments
	if len(arnSegments) != len(patternSegments) {
		return false
	}

	// Compare segment by segment
	for i := 0; i < len(arnSegments); i++ {
		if !matchSegment(patternSegments[i], arnSegments[i]) {
			return false
		}
	}

	return true
}

func matchSimpleGlob(pattern, str string) bool {
	// Simple glob matching for permissions like "s3:Get*"
	if !strings.Contains(pattern, "*") {
		return pattern == str
	}

	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return false
	}

	// Check prefix
	if len(parts[0]) > 0 && !strings.HasPrefix(str, parts[0]) {
		return false
	}

	// Check suffix
	lastPart := parts[len(parts)-1]
	if len(lastPart) > 0 && !strings.HasSuffix(str, lastPart) {
		return false
	}

	// Check middle parts are present in order
	checkStart := len(parts[0])
	for i := 1; i < len(parts)-1; i++ {
		part := parts[i]
		if len(part) == 0 {
			continue
		}
		pos := strings.Index(str[checkStart:], part)
		if pos == -1 {
			return false
		}
		checkStart += pos + len(part)
	}

	return true
}

func splitARNByDelimiters(s string) []string {
	var segments []string
	var current strings.Builder

	for _, r := range s {
		if r == ':' || r == '/' {
			if current.Len() > 0 {
				segments = append(segments, current.String())
				current.Reset()
			}
			segments = append(segments, string(r))
		} else {
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		segments = append(segments, current.String())
	}

	return segments
}

func matchSegment(pattern, str string) bool {
	if pattern == "*" {
		return true
	}

	if pattern == str {
		return true
	}

	// Simple glob matching within the segment
	if !strings.Contains(pattern, "*") {
		return false
	}

	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return false
	}

	// Check prefix
	if len(parts[0]) > 0 && !strings.HasPrefix(str, parts[0]) {
		return false
	}

	// Check suffix
	lastPart := parts[len(parts)-1]
	if len(lastPart) > 0 && !strings.HasSuffix(str, lastPart) {
		return false
	}

	// Check middle parts are present in order
	checkStart := len(parts[0])
	for i := 1; i < len(parts)-1; i++ {
		part := parts[i]
		if len(part) == 0 {
			continue
		}
		pos := strings.Index(str[checkStart:], part)
		if pos == -1 {
			return false
		}
		checkStart += pos + len(part)
	}

	return true
}

func matchComplex(s1, s2 string) bool {
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

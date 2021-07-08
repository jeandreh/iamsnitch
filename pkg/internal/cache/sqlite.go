package cache

import (
	"fmt"

	"github.com/jeandreh/iam-snitch/pkg/internal/domain"
)

type SQLiteCache struct {
}

var _ domain.CacheIface = (*SQLiteCache)(nil)

func (c *SQLiteCache) SaveACL(rules []domain.AccessControlRule) error {
	return fmt.Errorf("TODO not implemented")
}

func (c *SQLiteCache) Find(filter domain.Filter) ([]domain.AccessControlRule, error) {
	return nil, fmt.Errorf("TODO not implemented")
}

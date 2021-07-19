package ports

import "github.com/jeandreh/iam-snitch/internal/domain/model"

//go:generate mockgen -destination=../../mocks/mock_cache.go -package=mocks -mock_names CacheIface=CacheMock . CacheIface
type CacheIface interface {
	SaveACL(rules []model.AccessControlRule) error
	Find(filter *model.Filter) ([]model.AccessControlRule, error)
}

package iamsnitch

import (
	"github.com/jeandreh/iam-snitch/internal/domain/model"
	"github.com/jeandreh/iam-snitch/internal/domain/ports"
)

type AccessControlService struct {
	provider ports.IAMProviderIface
	cache    ports.CacheIface
}

func NewAccessControlService(provider ports.IAMProviderIface, cache ports.CacheIface) *AccessControlService {
	return &AccessControlService{
		provider: provider,
		cache:    cache,
	}
}

func (a *AccessControlService) RefreshACL() (err error) {
	var nextPage ports.PageIface
	var rules []model.AccessControlRule

	for ok := true; ok; ok = nextPage.HasNext() {
		rules, nextPage, err = a.provider.FetchACL(nextPage)
		if err != nil {
			return err
		}

		if err = a.cache.SaveACL(rules); err != nil {
			return err
		}
	}

	return nil
}

func (a *AccessControlService) WhoCan(permissions []string, resources []string, exact bool) ([]model.AccessControlRule, error) {
	return a.cache.Find(&model.Filter{
		Permissions: permissions,
		Resources:   resources,
		ExactMatch:  exact,
	})
}

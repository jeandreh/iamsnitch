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

func (a *AccessControlService) RefreshACL() error {
	acl, err := a.provider.FetchACL()
	if err != nil {
		return err
	}
	return a.cache.SaveACL(acl)
}

func (a *AccessControlService) WhoCan(actions []string, resources []model.Resource, exact bool) ([]model.AccessControlRule, error) {
	return a.cache.Find(&model.Filter{
		Actions:    actions,
		Resources:  resources,
		ExactMatch: exact,
	})
}

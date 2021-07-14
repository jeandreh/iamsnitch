package iamsnitch

import "github.com/jeandreh/iam-snitch/internal/domain"

type AccessControlService struct {
	provider domain.IAMProviderIface
	cache    domain.CacheIface
}

func NewAccessControlService(provider domain.IAMProviderIface, cache domain.CacheIface) *AccessControlService {
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

func (a *AccessControlService) WhoCan(action domain.Action, resource domain.Resource) ([]domain.AccessControlRule, error) {
	return a.cache.Find(&domain.Filter{
		Actions:   []domain.Action{action},
		Resources: []domain.Resource{resource},
	})
}

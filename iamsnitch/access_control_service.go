package iamsnitch

import (
	"github.com/jeandreh/iam-snitch/internal/aws"
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

func (a *AccessControlService) RefreshACL(resourceServices []string) (err error) {
	var nextPage ports.PageIface
	var identityPolicies []model.IdentityPolicy

	// Fetch all identity policies
	for ok := true; ok; ok = nextPage.HasNext() {
		policies, page, err := a.provider.FetchIdentityPolicies(nextPage)
		if err != nil {
			return err
		}
		identityPolicies = append(identityPolicies, policies...)
		nextPage = page
	}

	// Collect principals for boundary fetching
	principals := make([]string, len(identityPolicies))
	for i, policy := range identityPolicies {
		principals[i] = policy.Principal
	}

	// Fetch boundaries
	boundaries, err := a.provider.FetchPermissionBoundaries(principals)
	if err != nil {
		return err
	}

	// Fetch SCPs
	scps, err := a.provider.FetchSCPs()
	if err != nil {
		return err
	}

	// Fetch resource policies if services specified
	var resourcePolicies map[string]model.ResourcePolicy
	if len(resourceServices) > 0 {
		resourcePolicies, err = a.provider.FetchResourcePolicies(resourceServices)
		if err != nil {
			return err
		}
	}

	// Build ACL using the new evaluation order
	builder := aws.NewACLBuilderWithPolicies(identityPolicies, boundaries, scps, resourcePolicies)
	rules := builder.Build()

	// Save to cache
	if err = a.cache.SaveACL(rules); err != nil {
		return err
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

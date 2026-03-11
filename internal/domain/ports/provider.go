package ports

import "github.com/jeandreh/iam-snitch/internal/domain/model"

//go:generate mockgen -destination=../../mocks/mock_provider.go -package=mocks -mock_names IAMProviderIface=IAMProviderMock . IAMProviderIface
type IAMProviderIface interface {
	FetchACL(page PageIface) ([]model.AccessControlRule, PageIface, error)
	FetchPermissionBoundaries(principals []string) (map[string]*model.BoundaryPolicy, error)
	FetchSCPs() ([]model.SCPPolicy, error)
	FetchResourcePolicies(services []string) (map[string]model.ResourcePolicy, error)
}

//go:generate mockgen -destination=../../mocks/mock_page.go -package=mocks -mock_names PageIface=PageMock . PageIface
type PageIface interface {
	Next() *string
	HasNext() bool
}

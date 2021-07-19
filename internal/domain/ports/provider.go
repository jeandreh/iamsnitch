package ports

import "github.com/jeandreh/iam-snitch/internal/domain/model"

//go:generate mockgen -destination=../../mocks/mock_provider.go -package=mocks -mock_names IAMProviderIface=IAMProviderMock . IAMProviderIface
type IAMProviderIface interface {
	FetchACL() ([]model.AccessControlRule, error)
}

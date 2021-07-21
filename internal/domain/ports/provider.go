package ports

import "github.com/jeandreh/iam-snitch/internal/domain/model"

//go:generate mockgen -destination=../../mocks/mock_provider.go -package=mocks -mock_names IAMProviderIface=IAMProviderMock . IAMProviderIface
type IAMProviderIface interface {
	FetchACL(page PageIface) ([]model.AccessControlRule, PageIface, error)
}

//go:generate mockgen -destination=../../mocks/mock_page.go -package=mocks -mock_names PageIface=PageMock . PageIface
type PageIface interface {
	Next() *string
	HasNext() bool
}

package domain

//go:generate mockgen -destination=../mocks/mock_provider.go -package=mocks -mock_names IAMProviderIface=IAMProviderMock . IAMProviderIface
type IAMProviderIface interface {
	FetchACL() ([]AccessControlRule, error)
}

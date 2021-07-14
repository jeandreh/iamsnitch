package domain

type ProviderIface interface {
	FetchACL() ([]AccessControlRule, error)
}

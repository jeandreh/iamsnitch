package model

type ProviderIface interface {
	FetchACL() ([]AccessControlRule, error)
}

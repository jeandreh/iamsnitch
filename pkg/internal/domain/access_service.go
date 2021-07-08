package domain

type AccessServiceIface interface {
	RefreshACL() error
	WhoCan(action Permission, resource Resource) ([]AccessControlRule, error)
}

package domain

type CacheIface interface {
	SaveACL(rules []AccessControlRule) error
	Find(filter Filter) ([]AccessControlRule, error)
}

type Filter struct {
	Permissions []Permission
	Principal   Principal
	Resources   []Resource
}

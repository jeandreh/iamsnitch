package domain

//go:generate mockgen -destination=../mocks/mock_cache.go -package=mocks -mock_names CacheIface=CacheMock . CacheIface
type CacheIface interface {
	SaveACL(rules []AccessControlRule) error
	Find(filter *Filter) ([]AccessControlRule, error)
}

type Filter struct {
	Actions   []Action
	Principal Principal
	Resources []Resource
}

func (f *Filter) ActionsAsString() []string {
	var strList []string
	for _, a := range f.Actions {
		strList = append(strList, a.ID)
	}
	return strList
}

func (f *Filter) ResourcesAsString() []string {
	var strList []string
	for _, r := range f.Resources {
		strList = append(strList, r.ID)
	}
	return strList
}

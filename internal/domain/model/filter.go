package model

type Filter struct {
	Actions   []string
	Principal Principal
	Resources []Resource
	ExactMatch     bool
}

func (f *Filter) ResourcesAsString() []string {
	var strList []string
	for _, r := range f.Resources {
		strList = append(strList, r.ID)
	}
	return strList
}

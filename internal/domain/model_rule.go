package domain

import (
	"crypto/sha1"
	"fmt"
)

type AccessControlRule struct {
	Principal   Principal
	Permissions []Permission
	Resource    Resource
}

func (a *AccessControlRule) ID() string {
	id := fmt.Sprintf("%v:%v:%v", a.Principal, a.Resource, a.Permissions[0].GrantChain[0])
	return fmt.Sprintf("%x", sha1.Sum([]byte(id)))
}

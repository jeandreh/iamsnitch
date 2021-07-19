package model

import (
	"crypto/sha1"
	"fmt"
)

type AccessControlRule struct {
	Principal  Principal
	Permission Permission
	Resource   Resource
	GrantChain []GrantIface
}

func (a *AccessControlRule) ID() string {
	id := fmt.Sprintf("%v:%v:%v", a.Principal, a.Resource, a.GrantChain[0])
	return fmt.Sprintf("%x", sha1.Sum([]byte(id)))
}

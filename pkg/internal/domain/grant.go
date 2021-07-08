package domain

import "fmt"

type GrantIface interface {
	String() string
}

type RoleGrant struct {
	Grant
}

type PolicyGrant struct {
	Grant
}

type Grant struct {
	Type string
	ID   string
}

func NewRoleGrant(id string) RoleGrant {
	return RoleGrant{
		Grant{
			Type: "Role",
			ID:   id,
		},
	}
}

func NewPolicyGrant(id string) PolicyGrant {
	return PolicyGrant{
		Grant{
			Type: "Policy",
			ID:   id,
		},
	}
}

func (rg Grant) String() string {
	return fmt.Sprintf("%v:%v", rg.Type, rg.ID)
}

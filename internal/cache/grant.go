package cache

import (
	"strings"

	"github.com/jeandreh/iam-snitch/internal/domain"
	"gorm.io/gorm"
)

type Grant struct {
	gorm.Model
	PermissionID uint
	Value        string
}

func NewGrant(dg domain.GrantIface) Grant {
	return Grant{
		Value: dg.String(),
	}
}

func (g *Grant) Map() domain.GrantIface {
	if strings.Index(g.Value, "Role:") == 0 {
		return domain.NewRoleGrant(strings.Replace(g.Value, "Role:", "", 1))
	}
	return domain.NewPolicyGrant(strings.Replace(g.Value, "Policy:", "", 1))
}

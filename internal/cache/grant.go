package cache

import (
	"strings"

	"github.com/jeandreh/iam-snitch/internal/domain/model"
	"gorm.io/gorm"
)

type Grant struct {
	gorm.Model
	AccessControlRuleID uint
	Value               string
}

func NewGrantChain(dg []model.GrantIface) []Grant {
	var gc []Grant
	for _, g := range dg {
		gc = append(gc, Grant{Value: g.String()})
	}
	return gc
}

func (g *Grant) Map() model.GrantIface {
	if strings.Index(g.Value, "Role:") == 0 {
		return model.NewRoleGrant(strings.Replace(g.Value, "Role:", "", 1))
	}
	return model.NewPolicyGrant(strings.Replace(g.Value, "Policy:", "", 1))
}

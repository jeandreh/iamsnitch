package cache

import (
	"github.com/jeandreh/iam-snitch/internal/domain/model"
	"gorm.io/gorm"
)

type AccessControlRule struct {
	gorm.Model
	RuleID     string
	Principal  string
	Permission string
	Resource   string
	GrantChain []Grant
}

func NewAccessControlRule(da *model.AccessControlRule) *AccessControlRule {
	return &AccessControlRule{
		RuleID:     da.ID(),
		Principal:  da.Principal.ID,
		Permission: da.Permission.ID,
		Resource:   da.Resource.ID,
		GrantChain: NewGrantChain(da.GrantChain),
	}
}

func (a *AccessControlRule) Map() model.AccessControlRule {
	return model.AccessControlRule{
		Principal: model.Principal{ID: a.Principal},
		Permission: model.Permission{
			ID: a.Permission,
		},
		Resource:   model.Resource{ID: a.Resource},
		GrantChain: a.mapGrantChain(),
	}
}

func (a *AccessControlRule) mapGrantChain() []model.GrantIface {
	var mg []model.GrantIface
	for _, g := range a.GrantChain {
		mg = append(mg, g.Map())
	}
	return mg
}

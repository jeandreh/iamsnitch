package cache

import (
	"github.com/jeandreh/iam-snitch/internal/domain"
	"gorm.io/gorm"
)

type AccessControlRule struct {
	gorm.Model
	RuleID      string
	Principal   string
	Permissions []Permission
	Resource    string
}

func NewAccessControlRule(da *domain.AccessControlRule) *AccessControlRule {
	return &AccessControlRule{
		RuleID:      da.ID(),
		Principal:   da.Principal.ID,
		Permissions: mapPermissions(da.Permissions),
		Resource:    da.Resource.ID,
	}
}

func (a *AccessControlRule) Map() domain.AccessControlRule {
	dacl := domain.AccessControlRule{
		Principal: domain.Principal{ID: a.Principal},
		Resource:  domain.Resource{ID: a.Resource},
	}
	for _, p := range a.Permissions {
		dacl.Permissions = append(dacl.Permissions, p.Map())
	}
	return dacl
}

func mapPermissions(dpl []domain.Permission) []Permission {
	pl := make([]Permission, 0, 10)
	for _, p := range dpl {
		pl = append(pl, NewPermission(&p))
	}
	return pl
}

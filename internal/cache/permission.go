package cache

import (
	"github.com/jeandreh/iam-snitch/internal/domain"
	"gorm.io/gorm"
)

type Permission struct {
	gorm.Model
	AccessControlRuleID uint
	Action              string
	GrantChain          []Grant
}

func NewPermission(dp *domain.Permission) Permission {
	p := Permission{
		Action: dp.Action.ID,
	}
	for _, g := range dp.GrantChain {
		p.GrantChain = append(p.GrantChain, NewGrant(g))
	}
	return p
}

func (p *Permission) Map() domain.Permission {
	dp := domain.Permission{
		Action: domain.Action{ID: p.Action},
	}
	for _, g := range p.GrantChain {
		dp.GrantChain = append(dp.GrantChain, g.Map())
	}
	return dp
}

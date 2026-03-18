package cache

import (
	"encoding/json"

	"github.com/jeandreh/iam-snitch/internal/domain/model"
	"gorm.io/gorm"
)

type AccessControlRule struct {
	gorm.Model
	RuleID              string
	Principal           string
	Permission          string
	Resource            string
	GrantChain          []Grant
	UncheckedConditions string // JSON-encoded []model.Condition
}

func NewRule(da *model.AccessControlRule) *AccessControlRule {
	uncheckedJSON, _ := json.Marshal(da.UncheckedConditions)
	return &AccessControlRule{
		RuleID:              da.ID(),
		Principal:           da.Principal.ID,
		Permission:          da.Permission.ID,
		Resource:            da.Resource.ID,
		GrantChain:          NewGrantChain(da.GrantChain),
		UncheckedConditions: string(uncheckedJSON),
	}
}

func (a *AccessControlRule) Map() model.AccessControlRule {
	var unchecked []model.Condition
	if a.UncheckedConditions != "" {
		_ = json.Unmarshal([]byte(a.UncheckedConditions), &unchecked)
	}

	return model.AccessControlRule{
		Principal: model.Principal{ID: a.Principal},
		Permission: model.Permission{
			ID: a.Permission,
		},
		Resource:            model.Resource{ID: a.Resource},
		GrantChain:          a.mapGrantChain(),
		UncheckedConditions: unchecked,
	}
}

func (a *AccessControlRule) mapGrantChain() []model.GrantIface {
	mg := make([]model.GrantIface, 0, len(a.GrantChain))
	for _, g := range a.GrantChain {
		mg = append(mg, g.Map())
	}
	return mg
}

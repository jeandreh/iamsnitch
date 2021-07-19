package aws

import (
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/jeandreh/iam-snitch/internal/domain/model"
)

type ACLBuilder struct {
	role       types.Role
	principals []Principal
	policies   []IdentityPolicy
	acl        []model.AccessControlRule
}

func NewACLBuilder(role types.Role, principals []Principal, policies []IdentityPolicy) *ACLBuilder {
	return &ACLBuilder{
		role,
		principals,
		policies,
		make([]model.AccessControlRule, 0, 100),
	}
}

func (b *ACLBuilder) Build() []model.AccessControlRule {
	for _, po := range b.policies {
		for _, pr := range b.principals {
			b.processStatements(&pr, &po)
		}
	}
	return b.acl
}

func (b *ACLBuilder) processStatements(pr *Principal, po *IdentityPolicy) {
	for _, s := range po.Statements {
		b.processStatement(pr, po, &s)
	}
}

func (b *ACLBuilder) processStatement(pr *Principal, po *IdentityPolicy, s *Statement) {
	for _, r := range s.Resources {
		b.processRules(pr, po, r, s.Actions)
	}
}

func (b *ACLBuilder) processRules(pr *Principal, po *IdentityPolicy, r string, al []string) {
	for _, a := range al {
		rule := model.AccessControlRule{
			Principal: model.Principal{ID: pr.String()},
			Permission: model.Permission{
				ID: a,
			},
			Resource: model.Resource{ID: r},
			GrantChain: []model.GrantIface{
				model.NewRoleGrant(*b.role.Arn),
				model.NewPolicyGrant(po.ARN),
			},
		}
		b.acl = append(b.acl, rule)
	}
}

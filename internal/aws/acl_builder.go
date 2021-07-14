package aws

import (
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/jeandreh/iam-snitch/internal/domain"
)

type ACLBuilder struct {
	role       types.Role
	principals []Principal
	policies   []IdentityPolicy
	acl        []domain.AccessControlRule
}

func NewACLBuilder(role types.Role, principals []Principal, policies []IdentityPolicy) *ACLBuilder {
	return &ACLBuilder{
		role,
		principals,
		policies,
		make([]domain.AccessControlRule, 0, 100),
	}
}

func (b *ACLBuilder) Build() []domain.AccessControlRule {
	for _, po := range b.policies {
		for _, pr := range b.principals {
			b.processStatements(&po, &pr)
		}
	}
	return b.acl
}

func (b *ACLBuilder) processStatements(po *IdentityPolicy, pr *Principal) {
	for _, s := range po.Statements {
		for _, r := range s.Resources {
			rule := domain.AccessControlRule{
				Principal:   domain.Principal{ID: pr.String()},
				Permissions: make([]domain.Permission, 0, 10),
				Resource:    domain.Resource{ID: r},
			}
			for _, a := range s.Actions {
				perm := domain.Permission{
					Action: domain.Action{ID: a},
					GrantChain: []domain.GrantIface{
						domain.NewRoleGrant(*b.role.Arn),
						domain.NewPolicyGrant(po.ARN),
					},
				}
				rule.Permissions = append(rule.Permissions, perm)
			}
			b.acl = append(b.acl, rule)
		}
	}
}

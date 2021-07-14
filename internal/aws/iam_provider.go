package aws

import (
	"context"
	"log"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/jeandreh/iam-snitch/internal/domain"
)

type IAMProvider struct {
	ctx context.Context
	cli IAMClientIface
}

var _ domain.IAMProviderIface = (*IAMProvider)(nil)

func NewIAMProvider(cfg *aws.Config) (as *IAMProvider, err error) {
	ctx := context.TODO()

	if cfg == nil {
		// Load the Shared AWS Configuration (~/.aws/config)
		newCfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return as, err
		}
		cfg = &newCfg
	}

	as = &IAMProvider{
		ctx: ctx,
		cli: iam.NewFromConfig(*cfg),
	}
	return as, err
}

func (a *IAMProvider) FetchACL() ([]domain.AccessControlRule, error) {
	roles, err := a.fetchRoles()
	if err != nil {
		return nil, err
	}

	var acl []domain.AccessControlRule
	for _, role := range roles {
		principals, err := a.getPrincipals(&role)
		if err != nil {
			return nil, err
		}

		policies, err := a.fetchAttachedPolicies(&role)
		if err != nil {
			return nil, err
		}

		newRules := NewACLBuilder(role, principals, policies).Build()

		log.Printf("%v rules found for role %v", len(newRules), *role.RoleName)

		acl = append(acl, newRules...)
	}
	return acl, nil
}

func (a *IAMProvider) fetchRoles() ([]types.Role, error) {
	output, err := a.cli.ListRoles(a.ctx, &iam.ListRolesInput{})
	if err != nil {
		return nil, err
	}

	return output.Roles, nil
}

func (a *IAMProvider) getPrincipals(role *types.Role) ([]Principal, error) {
	policyDoc, err := url.QueryUnescape(*role.AssumeRolePolicyDocument)
	if err != nil {
		return nil, err
	}

	assumePolicy, err := NewAssumePolicy(policyDoc)
	if err != nil {
		return nil, err
	}

	return assumePolicy.Statements[0].Principals.Items, nil
}

func (a *IAMProvider) fetchAttachedPolicies(role *types.Role) ([]IdentityPolicy, error) {
	lp, err := a.cli.ListAttachedRolePolicies(a.ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: role.RoleName,
	})
	if err != nil {
		return nil, err
	}

	var policies []IdentityPolicy
	for _, attachedRolePolicy := range lp.AttachedPolicies {
		np, err := a.fetchIdentityPolicy(&attachedRolePolicy)
		if err != nil {
			return nil, err
		}
		policies = append(policies, *np)
	}
	return policies, nil
}

func (a *IAMProvider) fetchIdentityPolicy(ap *types.AttachedPolicy) (*IdentityPolicy, error) {
	gp, err := a.cli.GetPolicy(a.ctx, &iam.GetPolicyInput{
		PolicyArn: ap.PolicyArn,
	})
	if err != nil {
		return nil, err
	}

	pv, err := a.cli.GetPolicyVersion(a.ctx, &iam.GetPolicyVersionInput{
		PolicyArn: gp.Policy.Arn,
		VersionId: gp.Policy.DefaultVersionId,
	})
	if err != nil {
		return nil, err
	}

	pd, err := url.QueryUnescape(*pv.PolicyVersion.Document)
	if err != nil {
		return nil, err
	}

	np, err := NewIdentityPolicy(*gp.Policy.Arn, *gp.Policy.PolicyName, pd)
	if err != nil {
		return nil, err
	}
	return np, nil
}

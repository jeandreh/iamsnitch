package aws

import (
	"context"
	"fmt"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/jeandreh/iam-snitch/pkg/internal/domain"
)

type AccessService struct {
	ctx   context.Context
	cli   *iam.Client
	cache domain.CacheIface
}

var _ domain.AccessServiceIface = (*AccessService)(nil)

func New(cfg *aws.Config, cache domain.CacheIface) (as *AccessService, err error) {
	ctx := context.TODO()

	if cfg == nil {
		// Load the Shared AWS Configuration (~/.aws/config)
		newCfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return as, err
		}
		cfg = &newCfg
	}

	as = &AccessService{
		ctx:   ctx,
		cli:   iam.NewFromConfig(*cfg),
		cache: cache,
	}
	return as, err
}

func (a *AccessService) WhoCan(action domain.Permission, resource domain.Resource) ([]domain.AccessControlRule, error) {
	return nil, fmt.Errorf("TODO not implemented")
}

func (a *AccessService) RefreshACL() error {
	roles, err := a.fetchRoles()
	if err != nil {
		return err
	}

	for _, role := range roles {
		principals, err := a.getPrincipals(&role)
		if err != nil {
			return err
		}

		policies, err := a.fetchAttachedPolicies(role)
		if err != nil {
			return err
		}
		a.cache.SaveACL(NewACLBuilder(role, principals, policies).Build())
	}
	return nil
}

func (a *AccessService) fetchRoles() ([]types.Role, error) {
	output, err := a.cli.ListRoles(a.ctx, &iam.ListRolesInput{})
	if err != nil {
		return nil, err
	}

	return output.Roles, nil
}

func (a *AccessService) getPrincipals(role *types.Role) ([]Principal, error) {
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

func (a *AccessService) fetchAttachedPolicies(role types.Role) ([]IdentityPolicy, error) {
	lp, err := a.cli.ListAttachedRolePolicies(a.ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: role.RoleName,
	})
	if err != nil {
		return nil, err
	}

	policies := make([]IdentityPolicy, 0, 100)

	for _, attachedRolePolicy := range lp.AttachedPolicies {
		gp, err := a.cli.GetPolicy(a.ctx, &iam.GetPolicyInput{
			PolicyArn: attachedRolePolicy.PolicyArn,
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

		policies = append(policies, *np)
	}

	return policies, nil
}

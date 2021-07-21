package aws

import (
	"context"
	"fmt"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/jeandreh/iam-snitch/internal/domain/model"
	"github.com/jeandreh/iam-snitch/internal/domain/ports"
	"github.com/sirupsen/logrus"
)

type IAMProvider struct {
	ctx context.Context
	cli IAMClientIface
}

var _ ports.IAMProviderIface = (*IAMProvider)(nil)

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

func (a *IAMProvider) FetchACL(page ports.PageIface) ([]model.AccessControlRule, ports.PageIface, error) {
	roles, nextPage, err := a.fetchRoles(page)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"page":  page,
			"error": err,
		}).Error("failed to fetch roles from aws")
		return nil, nil, err
	}

	var acl []model.AccessControlRule
	for _, role := range roles {
		principals, err := a.getPrincipals(&role)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"role":      *role.Arn,
				"principal": *role.AssumeRolePolicyDocument,
				"error":     err,
			}).Error("failed to fetch principal from trust policy")
			continue
		}

		policies, err := a.fetchAttachedPolicies(&role)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"role":  *role.Arn,
				"error": err,
			}).Error("failed to fetch policies attached to role")
			continue
		}

		newRules := NewACLBuilder(role, principals, policies).Build()

		fmt.Printf("%v rules found for role %v\n", len(newRules), *role.RoleName)

		acl = append(acl, newRules...)
	}

	return acl, nextPage, nil
}

func (a *IAMProvider) fetchRoles(pageToken ports.PageIface) ([]types.Role, ports.PageIface, error) {
	lri := iam.ListRolesInput{}

	if pageToken != nil {
		lri.Marker = pageToken.Next()
	}

	output, err := a.cli.ListRoles(a.ctx, &lri)
	if err != nil {
		return nil, nil, err
	}

	return output.Roles, NewPageToken(output.Marker), nil
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

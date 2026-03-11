package aws

import (
	"context"
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

func (a *IAMProvider) FetchIdentityPolicies(page ports.PageIface) ([]model.IdentityPolicy, ports.PageIface, error) {
	roles, nextPage, err := a.fetchRoles(page)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"page":  page,
			"error": err,
		}).Error("failed to fetch roles from aws")
		return nil, nil, err
	}

	var identityPolicies []model.IdentityPolicy
	for _, role := range roles {
		statements, err := a.fetchRolePolicyStatements(&role)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"role":  *(role.Arn),
				"error": err,
			}).Error("failed to fetch policy statements for role")
			continue
		}

		identityPolicy := model.IdentityPolicy{
			Principal:  *role.Arn,
			Statements: statements,
		}

		identityPolicies = append(identityPolicies, identityPolicy)
	}

	return identityPolicies, nextPage, nil
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

func (a *IAMProvider) fetchRolePolicyStatements(role *types.Role) ([]Statement, error) {
	var allStatements []Statement

	// Fetch attached policies
	attachedPolicies, err := a.fetchAttachedPolicyStatements(role)
	if err != nil {
		return nil, err
	}
	allStatements = append(allStatements, attachedPolicies...)

	// Fetch inline policies
	inlinePolicies, err := a.fetchInlinePolicyStatements(role)
	if err != nil {
		return nil, err
	}
	allStatements = append(allStatements, inlinePolicies...)

	return allStatements, nil
}

func (a *IAMProvider) fetchAttachedPolicyStatements(role *types.Role) ([]Statement, error) {
	lp, err := a.cli.ListAttachedRolePolicies(a.ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: role.RoleName,
	})
	if err != nil {
		return nil, err
	}

	var statements []Statement
	for _, attachedRolePolicy := range lp.AttachedPolicies {
		policyStatements, err := a.fetchPolicyStatements(attachedRolePolicy.PolicyArn)
		if err != nil {
			return nil, err
		}
		statements = append(statements, policyStatements...)
	}
	return statements, nil
}

func (a *IAMProvider) fetchInlinePolicyStatements(role *types.Role) ([]Statement, error) {
	lip, err := a.cli.ListRolePolicies(a.ctx, &iam.ListRolePoliciesInput{
		RoleName: role.RoleName,
	})
	if err != nil {
		return nil, err
	}

	var statements []Statement
	for _, policyName := range lip.PolicyNames {
		policyDoc, err := a.cli.GetRolePolicy(a.ctx, &iam.GetRolePolicyInput{
			RoleName:   role.RoleName,
			PolicyName: &policyName,
		})
		if err != nil {
			return nil, err
		}

		pd, err := url.QueryUnescape(*policyDoc.PolicyDocument)
		if err != nil {
			return nil, err
		}

		policy, err := NewIdentityPolicy("", policyName, pd)
		if err != nil {
			return nil, err
		}
		statements = append(statements, policy.Statements...)
	}
	return statements, nil
}

func (a *IAMProvider) fetchPolicyStatements(policyArn *string) ([]Statement, error) {
	gp, err := a.cli.GetPolicy(a.ctx, &iam.GetPolicyInput{
		PolicyArn: policyArn,
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

	policy, err := NewIdentityPolicy(*gp.Policy.Arn, *gp.Policy.PolicyName, pd)
	if err != nil {
		return nil, err
	}
	return policy.Statements, nil
}

// FetchPermissionBoundaries fetches permission boundary policies for given principals.
// Phase 2 placeholder: Returns empty map until AWS API integration is implemented.
func (a *IAMProvider) FetchPermissionBoundaries(principals []string) (map[string]*model.BoundaryPolicy, error) {
	// TODO: Phase 2 - Implement AWS API calls to fetch permission boundaries
	// using iam.GetUserPermissionsBoundary() and iam.GetRolePermissionsBoundary()
	return make(map[string]*model.BoundaryPolicy), nil
}

// FetchSCPs fetches all Service Control Policies for the account.
// Phase 2 placeholder: Returns empty slice until AWS API integration is implemented.
func (a *IAMProvider) FetchSCPs() ([]model.SCPPolicy, error) {
	// TODO: Phase 2 - Implement AWS API calls to fetch SCPs
	// using organizations.ListPolicies() with PolicyType="SERVICE_CONTROL_POLICY"
	return make([]model.SCPPolicy, 0), nil
}

// FetchResourcePolicies fetches resource-based policies for specified services.
// Phase 2 placeholder: Returns empty map until AWS API integration is implemented.
func (a *IAMProvider) FetchResourcePolicies(services []string) (map[string]model.ResourcePolicy, error) {
	// TODO: Phase 2 - Implement AWS API calls to fetch resource policies
	// by service type (S3, SQS, SNS, KMS, Secrets Manager, Lambda)
	return make(map[string]model.ResourcePolicy), nil
}

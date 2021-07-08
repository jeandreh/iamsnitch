package main

import (
	"context"
	"log"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"gorm.io/gorm"

	"github.com/jeandreh/iam-snitch/pkg/iamsnitch"
)

func main() {
	db, err := iamsnitch.NewDB()
	if err != nil {
		log.Fatal(err)
	}

	if err = buildCache(db); err != nil {
		log.Fatal(err)
	}

	var statements []iamsnitch.Statement
	db.Joins("JOIN action_lists ON statements.id = action_lists.statement_id").
		Joins("JOIN actions ON action_lists.id = actions.action_list_id").
		Find(&statements, "statements.policy_type = ? and actions.value = ?", "iam_policies", "ec2:CreateTags")

}

func buildCache(db *gorm.DB) error {
	ctx := context.TODO()

	// Load the Shared AWS Configuration (~/.aws/config)
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatal(err)
	}

	client := iam.NewFromConfig(cfg)

	rolesOutput, err := client.ListRoles(ctx, &iam.ListRolesInput{})
	if err != nil {
		return err
	}

	for i, role := range rolesOutput.Roles {
		log.Printf("[%v/%v] %v", i+1, len(rolesOutput.Roles), *role.Arn)

		newRole := &iamsnitch.Role{
			ARN:  *role.Arn,
			Name: *role.RoleName,
		}

		assumePolicyDocument, err := url.QueryUnescape(*role.AssumeRolePolicyDocument)
		if err != nil {
			return err
		}

		assumePolicy, err := iamsnitch.NewAssumePolicy(assumePolicyDocument)
		if err != nil {
			return err
		}

		newRole.AssumePolicy = assumePolicy

		attachedRolePoliciesOutput, err := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
			RoleName: role.RoleName,
		})
		if err != nil {
			return err
		}

		for j, attachedRolePolicy := range attachedRolePoliciesOutput.AttachedPolicies {
			log.Printf("\t[%v/%v] %v", j+1, len(attachedRolePoliciesOutput.AttachedPolicies), *attachedRolePolicy.PolicyName)

			policyOutput, err := client.GetPolicy(ctx, &iam.GetPolicyInput{
				PolicyArn: attachedRolePolicy.PolicyArn,
			})
			if err != nil {
				return err
			}

			currentPolicyVersion, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
				PolicyArn: policyOutput.Policy.Arn,
				VersionId: policyOutput.Policy.DefaultVersionId,
			})
			if err != nil {
				return err
			}

			policyDocument, err := url.QueryUnescape(*currentPolicyVersion.PolicyVersion.Document)
			if err != nil {
				return err
			}

			newPolicy, err := iamsnitch.NewIAM(
				*policyOutput.Policy.Arn,
				*policyOutput.Policy.PolicyName,
				policyDocument,
			)
			if err != nil {
				return err
			}

			newRole.Policies = append(newRole.Policies, *newPolicy)
		}
		db.Create(newRole)
	}
	return nil
}

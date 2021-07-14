package aws

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/golang/mock/gomock"
	"github.com/jeandreh/iam-snitch/internal/domain"
	"github.com/jeandreh/iam-snitch/internal/mocks"
	"github.com/stretchr/testify/require"
)

func TestFetchACL(t *testing.T) {
	type args struct {
		listRolesOutput        *iam.ListRolesOutput
		rolePoliciesOutput     *iam.ListAttachedRolePoliciesOutput
		getPolicyOutput        *iam.GetPolicyOutput
		getPolicyVersionOutput *iam.GetPolicyVersionOutput
	}
	tests := []struct {
		name    string
		args    args
		want    []domain.AccessControlRule
		wantErr error
	}{
		{
			"success",
			args{
				listRolesOutput: &iam.ListRolesOutput{
					Roles: []types.Role{
						{
							RoleId:   aws.String("roleid"),
							Arn:      aws.String("arn:role"),
							RoleName: aws.String("rolename"),
							AssumeRolePolicyDocument: aws.String(`{
								"Version": "2012-10-17",
								"Statement": [
									{
										"Effect": "Allow",
										"Principal": {
											"Service": "s3.amazonaws.com"
										},
										"Action": "sts:AssumeRole"
									}
								]
							}`),
						},
					},
				},
				rolePoliciesOutput: &iam.ListAttachedRolePoliciesOutput{
					AttachedPolicies: []types.AttachedPolicy{
						{
							PolicyArn:  aws.String("arn:policy"),
							PolicyName: aws.String("policyname"),
						},
					},
				},
				getPolicyOutput: &iam.GetPolicyOutput{
					Policy: &types.Policy{
						Arn:              aws.String("arn:policy"),
						PolicyName:       aws.String("policy"),
						DefaultVersionId: aws.String("version"),
					},
				},
				getPolicyVersionOutput: &iam.GetPolicyVersionOutput{
					PolicyVersion: &types.PolicyVersion{
						Document: aws.String(`{
							"Version": "2012-10-17",
							"Statement": [
								{
									"Effect": "Allow",
									"Action": "someaction",
									"Resource": "someresource"
								}
							]
						}`),
					},
				},
			},
			[]domain.AccessControlRule{
				{
					Principal: domain.Principal{ID: "Service[s3.amazonaws.com]"},
					Resource:  domain.Resource{ID: "someresource"},
					Permissions: []domain.Permission{
						{
							Action: domain.Action{ID: "someaction"},
							GrantChain: []domain.GrantIface{
								domain.RoleGrant{
									Grant: domain.Grant{
										Type: "Role",
										ID:   "arn:role",
									},
								},
								domain.PolicyGrant{
									Grant: domain.Grant{
										Type: "Policy",
										ID:   "arn:policy",
									},
								},
							},
						},
					},
				},
			},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			ctx := context.TODO()
			iamMock := mocks.NewIAMClientMock(ctrl)

			a := &IAMProvider{
				ctx: ctx,
				cli: iamMock,
			}

			iamMock.
				EXPECT().
				ListRoles(gomock.Eq(ctx), gomock.Eq(&iam.ListRolesInput{})).
				Return(tt.args.listRolesOutput, nil).
				Times(1)

			iamMock.
				EXPECT().
				ListAttachedRolePolicies(
					gomock.Eq(ctx),
					gomock.Eq(&iam.ListAttachedRolePoliciesInput{
						RoleName: tt.args.listRolesOutput.Roles[0].RoleName,
					}),
				).
				Return(tt.args.rolePoliciesOutput, nil).
				Times(1)

			iamMock.
				EXPECT().
				GetPolicy(
					gomock.Eq(ctx),
					gomock.Eq(&iam.GetPolicyInput{
						PolicyArn: tt.args.rolePoliciesOutput.AttachedPolicies[0].PolicyArn,
					}),
				).
				Return(tt.args.getPolicyOutput, nil).
				Times(1)

			iamMock.
				EXPECT().
				GetPolicyVersion(
					gomock.Eq(ctx),
					gomock.Eq(&iam.GetPolicyVersionInput{
						PolicyArn: tt.args.getPolicyOutput.Policy.Arn,
						VersionId: tt.args.getPolicyOutput.Policy.DefaultVersionId,
					}),
				).
				Return(tt.args.getPolicyVersionOutput, nil).
				Times(1)

			acl, err := a.FetchACL()

			require.Equal(t, tt.wantErr, err)
			require.Equal(t, tt.want, acl)
		})
	}
}

package aws

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/jeandreh/iam-snitch/internal/domain/model"
	"github.com/stretchr/testify/require"
)

func TestBuildACL(t *testing.T) {
	type fields struct {
		role       types.Role
		principals []Principal
		policies   []IdentityPolicy
	}
	tests := []struct {
		name   string
		fields fields
		want   []model.AccessControlRule
	}{
		{
			"single action",
			fields{
				types.Role{
					Arn:      aws.String("arn:aws:iam::111122223333:role/SomeRole"),
					RoleName: aws.String("SomeRole"),
				},
				[]Principal{
					{
						Type: AWS,
						ID:   "arn:aws:iam::111122223333:role/TestRole",
					},
				},
				[]IdentityPolicy{
					{
						ARN:  "arn:aws:iam::111122223333:policy/TestPolicy",
						Name: "TestPolicy",
						Policy: Policy{
							Version: "2012-10-17",
							Statements: []Statement{
								{
									Effect:  "Allow",
									Actions: []string{"ec2:CreateInstance"},
									Resources: []string{
										"arn:aws:ec2:*:*:instance/someinstanceid",
										"arn:aws:ec2:*:*:instance/someotherinstance",
									},
								},
							},
						},
					},
				},
			},
			[]model.AccessControlRule{
				{
					Principal: model.Principal{
						ID: "AWS[arn:aws:iam::111122223333:role/TestRole]",
					},
					Permission: model.Permission{
						ID: "ec2:CreateInstance",
					},
					Resource: model.Resource{
						ID: "arn:aws:ec2:*:*:instance/someinstanceid",
					},
					GrantChain: []model.GrantIface{
						model.RoleGrant{
							Grant: model.Grant{
								Type: "Role",
								ID:   "arn:aws:iam::111122223333:role/SomeRole",
							},
						},
						model.PolicyGrant{
							Grant: model.Grant{
								Type: "Policy",
								ID:   "arn:aws:iam::111122223333:policy/TestPolicy",
							},
						},
					},
				},
				{
					Principal: model.Principal{
						ID: "AWS[arn:aws:iam::111122223333:role/TestRole]",
					},
					Permission: model.Permission{
						ID: "ec2:CreateInstance",
					},
					Resource: model.Resource{
						ID: "arn:aws:ec2:*:*:instance/someotherinstance",
					},
					GrantChain: []model.GrantIface{
						model.RoleGrant{
							Grant: model.Grant{
								Type: "Role",
								ID:   "arn:aws:iam::111122223333:role/SomeRole",
							},
						},
						model.PolicyGrant{
							Grant: model.Grant{
								Type: "Policy",
								ID:   "arn:aws:iam::111122223333:policy/TestPolicy",
							},
						},
					},
				},
			},
		},
		{
			"two actions",
			fields{
				types.Role{
					Arn:      aws.String("arn:aws:iam::111122223333:role/SomeRole"),
					RoleName: aws.String("SomeRole"),
				},
				[]Principal{
					{
						Type: AWS,
						ID:   "arn:aws:iam::111122223333:role/TestRole",
					},
				},
				[]IdentityPolicy{
					{
						ARN:  "arn:aws:iam::111122223333:policy/TestPolicy",
						Name: "TestPolicy",
						Policy: Policy{
							Version: "2012-10-17",
							Statements: []Statement{
								{
									Effect: "Allow",
									Actions: []string{
										"ec2:CreateInstance",
										"ec2:DescribeInstance",
									},
									Resources: []string{
										"arn:aws:ec2:*:*:instance/someinstanceid",
									},
								},
							},
						},
					},
				},
			},
			[]model.AccessControlRule{
				{
					Principal: model.Principal{
						ID: "AWS[arn:aws:iam::111122223333:role/TestRole]",
					},
					Permission: model.Permission{
						ID: "ec2:CreateInstance",
					},
					Resource: model.Resource{
						ID: "arn:aws:ec2:*:*:instance/someinstanceid",
					},
					GrantChain: []model.GrantIface{
						model.RoleGrant{
							Grant: model.Grant{
								Type: "Role",
								ID:   "arn:aws:iam::111122223333:role/SomeRole",
							},
						},
						model.PolicyGrant{
							Grant: model.Grant{
								Type: "Policy",
								ID:   "arn:aws:iam::111122223333:policy/TestPolicy",
							},
						},
					},
				},
				{
					Principal: model.Principal{
						ID: "AWS[arn:aws:iam::111122223333:role/TestRole]",
					},
					Permission: model.Permission{
						ID: "ec2:DescribeInstance",
					},
					Resource: model.Resource{
						ID: "arn:aws:ec2:*:*:instance/someinstanceid",
					},
					GrantChain: []model.GrantIface{
						model.RoleGrant{
							Grant: model.Grant{
								Type: "Role",
								ID:   "arn:aws:iam::111122223333:role/SomeRole",
							},
						},
						model.PolicyGrant{
							Grant: model.Grant{
								Type: "Policy",
								ID:   "arn:aws:iam::111122223333:policy/TestPolicy",
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewACLBuilder(
				tt.fields.role,
				tt.fields.principals,
				tt.fields.policies,
			).Build()
			require.Equal(t, result, tt.want)
		})
	}
}

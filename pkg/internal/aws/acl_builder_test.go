package aws

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/jeandreh/iam-snitch/pkg/internal/domain"
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
		want   []domain.AccessControlRule
	}{
		{
			"single policy",
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
			[]domain.AccessControlRule{
				{
					Principal: domain.Principal{
						ID: "AWS[arn:aws:iam::111122223333:role/TestRole]",
					},
					Permissions: []domain.Permission{
						{
							Action: "ec2:CreateInstance",
							GrantChain: []domain.GrantIface{
								domain.RoleGrant{
									Grant: domain.Grant{
										Type: "Role",
										ID:   "arn:aws:iam::111122223333:role/SomeRole",
									},
								},
								domain.PolicyGrant{
									Grant: domain.Grant{
										Type: "Policy",
										ID:   "arn:aws:iam::111122223333:policy/TestPolicy",
									},
								},
							},
						},
					},
					Resource: domain.Resource{
						ID: "arn:aws:ec2:*:*:instance/someinstanceid",
					},
				},
				{
					Principal: domain.Principal{
						ID: "AWS[arn:aws:iam::111122223333:role/TestRole]",
					},
					Permissions: []domain.Permission{
						{
							Action: "ec2:CreateInstance",
							GrantChain: []domain.GrantIface{
								domain.RoleGrant{
									Grant: domain.Grant{
										Type: "Role",
										ID:   "arn:aws:iam::111122223333:role/SomeRole",
									},
								},
								domain.PolicyGrant{
									Grant: domain.Grant{
										Type: "Policy",
										ID:   "arn:aws:iam::111122223333:policy/TestPolicy",
									},
								},
							},
						},
					},
					Resource: domain.Resource{
						ID: "arn:aws:ec2:*:*:instance/someotherinstance",
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

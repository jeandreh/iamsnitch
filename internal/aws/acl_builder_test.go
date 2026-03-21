package aws

import (
	"testing"

	"github.com/jeandreh/iam-snitch/internal/domain/model"
	"github.com/stretchr/testify/require"
)

func TestBuildACL(t *testing.T) {
	type fields struct {
		identityPolicies []model.IdentityPolicy
		boundaries       map[string]*model.BoundaryPolicy
		scps             []model.SCPPolicy
		resourcePolicies map[string]model.ResourcePolicy
	}
	tests := []struct {
		name   string
		fields fields
		want   []model.AccessControlRule
	}{
		{
			"single action",
			fields{
				identityPolicies: []model.IdentityPolicy{
					{
						Principal: "arn:aws:iam::111122223333:policy/TestPolicy",
						Statements: []Statement{
							{
								Effect:   "Allow",
								Actions:  []string{"ec2:CreateInstance"},
								Resources: []string{"arn:aws:ec2:*:*:instance/someinstanceid", "arn:aws:ec2:*:*:instance/someotherinstance"},
							},
						},
					},
				},
				boundaries:       make(map[string]*model.BoundaryPolicy),
				scps:             make([]model.SCPPolicy, 0),
				resourcePolicies: make(map[string]model.ResourcePolicy),
			},
			[]model.AccessControlRule{
				{
					Principal: model.Principal{
						ID: "arn:aws:iam::111122223333:policy/TestPolicy",
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
								ID:   "arn:aws:iam::111122223333:policy/TestPolicy",
							},
						},
					},
					UncheckedConditions: nil,
				},
				{
					Principal: model.Principal{
						ID: "arn:aws:iam::111122223333:policy/TestPolicy",
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
								ID:   "arn:aws:iam::111122223333:policy/TestPolicy",
							},
						},
					},
					UncheckedConditions: nil,
				},
			},
		},
		{
			"two actions",
			fields{
				identityPolicies: []model.IdentityPolicy{
					{
						Principal: "arn:aws:iam::111122223333:policy/TestPolicy",
						Statements: []Statement{
							{
								Effect:   "Allow",
								Actions:  []string{"ec2:CreateInstance", "ec2:DescribeInstance"},
								Resources: []string{"arn:aws:ec2:*:*:instance/someinstanceid"},
							},
						},
					},
				},
				boundaries:       make(map[string]*model.BoundaryPolicy),
				scps:             make([]model.SCPPolicy, 0),
				resourcePolicies: make(map[string]model.ResourcePolicy),
			},
			[]model.AccessControlRule{
				{
					Principal: model.Principal{
						ID: "arn:aws:iam::111122223333:policy/TestPolicy",
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
								ID:   "arn:aws:iam::111122223333:policy/TestPolicy",
							},
						},
					},
					UncheckedConditions: nil,
				},
				{
					Principal: model.Principal{
						ID: "arn:aws:iam::111122223333:policy/TestPolicy",
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
								ID:   "arn:aws:iam::111122223333:policy/TestPolicy",
							},
						},
					},
					UncheckedConditions: nil,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewACLBuilderWithPolicies(tt.fields.identityPolicies, tt.fields.boundaries, tt.fields.scps, tt.fields.resourcePolicies).Build()
			require.Equal(t, tt.want, result)
		})
	}
}

package cache

import (
	"testing"

	"github.com/jeandreh/iam-snitch/internal/domain/model"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestSQLiteCacheSaveACL(t *testing.T) {
	type args struct {
		rules []model.AccessControlRule
	}
	tests := []struct {
		name    string
		args    args
		want    []model.AccessControlRule
		wantErr error
	}{
		{
			"new rule",
			args{
				[]model.AccessControlRule{
					newRule("ec2:CreateInstance", "arn:aws:ec2:*:*:instance/someinstanceid"),
				},
			},
			[]model.AccessControlRule{
				newRule("ec2:CreateInstance", "arn:aws:ec2:*:*:instance/someinstanceid"),
			},
			nil,
		},
		{
			"rule update",
			args{
				[]model.AccessControlRule{
					newRule("ec2:CreateInstance", "arn:aws:ec2:*:*:instance/someinstanceid"),
					newRule("ec2:CreateInstance", "arn:aws:ec2:*:*:instance/someinstanceid"),
				},
			},
			[]model.AccessControlRule{
				newRule("ec2:CreateInstance", "arn:aws:ec2:*:*:instance/someinstanceid"),
			},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache, err := new("file::memory:?cache=shared", &gorm.Config{})
			require.Nil(t, err)

			require.Equal(t, cache.SaveACL(tt.args.rules), tt.wantErr)

			savedRules, err := cache.Find(&model.Filter{
				Permissions:    []string{"*"},
				Resources:  []string{"*"},
				ExactMatch: false,
			})

			require.Nil(t, err)
			require.ElementsMatch(t, tt.want, savedRules)
		})
	}
}

func TestSQLiteCacheFind(t *testing.T) {
	type args struct {
		rules  []model.AccessControlRule
		filter model.Filter
	}
	tests := []struct {
		name    string
		args    args
		want    []model.AccessControlRule
		wantErr error
	}{
		{
			"exact match",
			args{
				[]model.AccessControlRule{
					newRule("*", "*"),
					newRule("ec2:CreateInstance", "arn:aws:ec2:*:*:instance/someinstanceid"),
				},
				model.Filter{
					Permissions:    []string{"ec2:CreateInstance"},
					Resources:  []string{"arn:aws:ec2:*:*:instance/someinstanceid"},
					ExactMatch: true,
				},
			},
			[]model.AccessControlRule{
				newRule("ec2:CreateInstance", "arn:aws:ec2:*:*:instance/someinstanceid"),
			},
			nil,
		},
		{
			"exact match */*",
			args{
				[]model.AccessControlRule{
					newRule("*", "*"),
					newRule("ec2:CreateInstance", "arn:aws:ec2:*:*:instance/someinstanceid"),
				},
				model.Filter{
					Permissions:    []string{"*"},
					Resources:  []string{"*"},
					ExactMatch: true,
				},
			},
			[]model.AccessControlRule{
				newRule("*", "*"),
			},
			nil,
		},
		{
			"wildcard match */*",
			args{
				[]model.AccessControlRule{
					newRule("*", "*"),
					newRule("ec2:CreateInstance", "arn:aws:ec2:*:*:instance/someinstanceid"),
				},
				model.Filter{
					Permissions:    []string{"*"},
					Resources:  []string{"*"},
					ExactMatch: false,
				},
			},
			[]model.AccessControlRule{
				newRule("*", "*"),
				newRule("ec2:CreateInstance", "arn:aws:ec2:*:*:instance/someinstanceid"),
			},
			nil,
		},
		{
			"wildcard match action*/*",
			args{
				[]model.AccessControlRule{
					newRule("*", "*"),
					newRule("ec2:CreateInstance", "arn:aws:ec2:*:*:instance/someinstanceid"),
				},
				model.Filter{
					Permissions:    []string{"ec2:Create*"},
					Resources:  []string{"*"},
					ExactMatch: false,
				},
			},
			[]model.AccessControlRule{
				newRule("ec2:CreateInstance", "arn:aws:ec2:*:*:instance/someinstanceid"),
			},
			nil,
		},
		{
			"exact match action*/*",
			args{
				[]model.AccessControlRule{
					newRule("*", "*"),
					newRule("ec2:CreateInstance", "arn:aws:ec2:*:*:instance/someinstanceid"),
				},
				model.Filter{
					Permissions:    []string{"ec2:Create*"},
					Resources:  []string{"*"},
					ExactMatch: true,
				},
			},
			nil,
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache, err := new("file::memory:?cache=shared", &gorm.Config{})
			require.Nil(t, err)

			require.Equal(t, cache.SaveACL(tt.args.rules), tt.wantErr)

			savedRules, err := cache.Find(&tt.args.filter)

			require.Nil(t, err)
			require.ElementsMatch(t, tt.want, savedRules)
		})
	}
}

func newRule(permisison string, resource string) model.AccessControlRule {
	return model.AccessControlRule{
		Principal: model.Principal{
			ID: "AWS[arn:aws:iam::111122223333:role/TestRole]",
		},
		Permission: model.Permission{
			ID: permisison,
		},
		Resource: model.Resource{
			ID: resource,
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
	}
}

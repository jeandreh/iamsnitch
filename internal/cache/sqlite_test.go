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
				Permissions: []string{"*"},
				Resources:   []string{"*"},
				ExactMatch:  false,
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
					Permissions: []string{"ec2:CreateInstance"},
					Resources:   []string{"arn:aws:ec2:*:*:instance/someinstanceid"},
					ExactMatch:  true,
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
					Permissions: []string{"*"},
					Resources:   []string{"*"},
					ExactMatch:  true,
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
					Permissions: []string{"*"},
					Resources:   []string{"*"},
					ExactMatch:  false,
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
					Permissions: []string{"ec2:Create*"},
					Resources:   []string{"*"},
					ExactMatch:  false,
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
					Permissions: []string{"ec2:Create*"},
					Resources:   []string{"*"},
					ExactMatch:  true,
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

func TestMatch(t *testing.T) {
	type args struct {
		re string
		s  string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			"star1",
			args{
				"aws:*:ap-*:2893483479:*:test/somedir/obj",
				"aws:s3:*:2893483479:mybucket:*",
			},
			true,
		},
		{
			"star2",
			args{
				"aws:*:ap-*",
				"aws:s3:*:2893483479:mybucket:*",
			},
			true,
		},
		{
			"star3",
			args{
				"aws:*:ap-*:2893483479:test:*",
				"aws:s3:*:2893483479:mybucket:*",
			},
			false,
		},
		{
			"star4",
			args{
				"*",
				"arn:aws:logs:*:*:log-group:*",
			},
			true,
		},
		{
			"star5",
			args{
				"arn:*",
				"arn:aws:logs:*:*:log-group:*",
			},
			true,
		},
		// {
		// 	"star",
		// 	args{
		// 		"*",
		// 		"arn:aws:apigateway:test::/apis/test/deployments",
		// 	},
		// 	true,
		// 	false,
		// },
		// {
		// 	"star in the middle",
		// 	args{
		// 		"arn:aws:apigateway:*::/apis/*/deployments",
		// 		"arn:aws:apigateway:test::/apis/test/deployments",
		// 	},
		// 	true,
		// 	false,
		// },
		// {
		// 	"question mark in the middle",
		// 	args{
		// 		"arn:aws:apigateway:t?st::/apis/?est/deployments",
		// 		"arn:aws:apigateway:test::/apis/test/deployments",
		// 	},
		// 	true,
		// 	false,
		// },
		// {
		// 	"mismatch",
		// 	args{
		// 		"arn:aws:apigateway:t?t::/apis/?est/deployments",
		// 		"arn:aws:apigateway:test::/apis/test/deployments",
		// 	},
		// 	false,
		// 	false,
		// },
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := match(tt.args.re, tt.args.s)
			if got != tt.want {
				t.Errorf("match() = %v, want %v", got, tt.want)
			}
		})
	}
}

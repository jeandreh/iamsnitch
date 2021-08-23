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
		s1 string
		s2 string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			"wildcard in string 1 only",
			args{
				"aws:s3:ap-southeast-2:2893483479:mybucket:test/somedir/obj",
				"aws:s3:*:2893483479:mybucket:*",
			},
			true,
		},
		{
			"wildcard in string 2 only",
			args{
				"aws:s3:*:2893483479:mybucket:*",
				"aws:s3:ap-southeast-2:2893483479:mybucket:test/somedir/obj",
			},
			true,
		},
		{
			"wildcards in different components of both strings",
			args{
				"aws:*:ap-*:2893483479:*:test/somedir/obj",
				"aws:s3:*:2893483479:mybucket:*",
			},
			true,
		},
		{
			"multiple wildcards in sequence shouldn't affect match",
			args{
				"aws:*:ap-*:2893483479:*******:test/*****/obj",
				"aws:s3:*:2893483479:mybucket:*",
			},
			true,
		},
		{
			"string 1 with less components than string 2",
			args{
				"aws:*:ap-*",
				"aws:s3:*:2893483479:mybucket:*",
			},
			true,
		},
		{
			"string 2 with less components than string 1",
			args{
				"aws:s3:*:2893483479:mybucket:*",
				"aws:*:ap-*",
			},
			true,
		},
		{
			"strings don't match",
			args{
				"aws:*:ap-*:2893483479:test:*",
				"aws:s3:*:2893483479:mybucket:*",
			},
			false,
		},
		{
			"string 1 can be anything",
			args{
				"*",
				"arn:aws:logs:*:*:log-group:*",
			},
			true,
		},
		{
			"string 2 can be anything",
			args{
				"arn:aws:logs:*:*:log-group:*",
				"*",
			},
			true,
		},
		{
			"string 1 ends in a letter present in the middle of string 2",
			args{
				"*s",
				"arn:aws:logs:*:*:log-group:*",
			},
			false,
		},
		{
			"string 1 has a letter in string 2 surrounded by *",
			args{
				"*s*",
				"arn:aws:logs:*:*:log-group:*",
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := match(tt.args.s1, tt.args.s2)
			if got != tt.want {
				t.Errorf("match() = %v, want %v", got, tt.want)
			}
		})
	}
}

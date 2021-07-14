package aws

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeserialisePolicyFromJSON(t *testing.T) {
	tests := []struct {
		name   string
		policy string
		result *Policy
		err    error
	}{
		{
			"assume policy",
			`{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": {
							"Service": "support.amazonaws.com"
						},
						"Action": "sts:AssumeRole"
					}
				]
			}`,
			&Policy{
				Version: "2012-10-17",
				Statements: []Statement{
					{
						Effect:     "Allow",
						Actions:    []string{"sts:AssumeRole"},
						Principals: PrincipalList{[]Principal{{Service, "support.amazonaws.com"}}},
					},
				},
			},
			nil,
		},
		{
			"identity policy",
			`{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": "ec2:CreateInstance",
						"Resource": "arn:aws:ec2:*:*:instance/someinstanceid"
					}
				]
			}`,
			&Policy{
				Version: "2012-10-17",
				Statements: []Statement{
					{
						Effect:    "Allow",
						Actions:   []string{"ec2:CreateInstance"},
						Resources: []string{"arn:aws:ec2:*:*:instance/someinstanceid"},
					},
				},
			},
			nil,
		},
		{
			"resource policy",
			`{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": "ec2:CreateInstance",
						"Principal": [
							{
								"AWS": "arn:aws:iam::111122223333:role/TestRole"
							}
						],
						"Resource": "*"
					}
				]
			}`,
			&Policy{
				Version: "2012-10-17",
				Statements: []Statement{
					{
						Effect:     "Allow",
						Principals: PrincipalList{[]Principal{{AWS, "arn:aws:iam::111122223333:role/TestRole"}}},
						Actions:    []string{"ec2:CreateInstance"},
						Resources:  []string{"*"},
					},
				},
			},
			nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var policy Policy
			err := json.Unmarshal([]byte(test.policy), &policy)

			if test.err == nil {
				require.Nil(t, err)
				require.Equal(t, *test.result, policy)
			} else {
				require.Equal(t, err, test.err)
			}

		})
	}
}

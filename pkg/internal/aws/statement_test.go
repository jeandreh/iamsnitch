package aws

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeserialiseStatementFromJSON(t *testing.T) {
	tests := []struct {
		name      string
		statement string
		result    *Statement
		err       error
	}{
		{
			"single action and resource",
			`{
				"Effect":"Allow",
				"Action":"ec2:DescribeInstance",
				"Resource":"arn:aws:ec2:*:*:instance/someinstanceid" 
			}`,
			&Statement{
				Effect:    "Allow",
				Actions:   []string{"ec2:DescribeInstance"},
				Resources: []string{"arn:aws:ec2:*:*:instance/someinstanceid"},
			},
			nil,
		},
		{
			"multiple actions and resources",
			`{
				"Effect":"Allow",
				"Action":["ec2:DescribeInstance", "ec2:CreateInstance"],
				"Resource":["arn:aws:ec2:*:*:instance/someinstanceid", "arn:aws:ec2:*:*:instance/someotherinstance"]
			}`,
			&Statement{
				Effect:    "Allow",
				Actions:   []string{"ec2:DescribeInstance", "ec2:CreateInstance"},
				Resources: []string{"arn:aws:ec2:*:*:instance/someinstanceid", "arn:aws:ec2:*:*:instance/someotherinstance"},
			},
			nil,
		},
		{
			"single principal",
			`{
				"Effect":"Allow",
				"Principal": {
					"Service":"ecs.amazonaws.com"
				},
				"Action":["ec2:DescribeInstance", "ec2:CreateInstance"],
				"Resource":["arn:aws:ec2:*:*:instance/someinstanceid", "arn:aws:ec2:*:*:instance/someotherinstance"]
			}`,
			&Statement{
				Effect:     "Allow",
				Principals: PrincipalList{Items: []Principal{{Service, "ecs.amazonaws.com"}}},
				Actions:    []string{"ec2:DescribeInstance", "ec2:CreateInstance"},
				Resources:  []string{"arn:aws:ec2:*:*:instance/someinstanceid", "arn:aws:ec2:*:*:instance/someotherinstance"},
			},
			nil,
		},
		{
			"multiple principals",
			`{
				"Effect":"Allow",
				"Principal": [
					{
						"Service":"ecs.amazonaws.com"
					},
					{
						"AWS":"arn:aws:iam::111122223333:user/test"
					}
				],
				"Action":["ec2:DescribeInstance", "ec2:CreateInstance"],
				"Resource":["arn:aws:ec2:*:*:instance/someinstanceid", "arn:aws:ec2:*:*:instance/someotherinstance"]
			}`,
			&Statement{
				Effect:     "Allow",
				Principals: PrincipalList{Items: []Principal{{Service, "ecs.amazonaws.com"}, {AWS, "arn:aws:iam::111122223333:user/test"}}},
				Actions:    []string{"ec2:DescribeInstance", "ec2:CreateInstance"},
				Resources:  []string{"arn:aws:ec2:*:*:instance/someinstanceid", "arn:aws:ec2:*:*:instance/someotherinstance"},
			},
			nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var statement Statement
			err := json.Unmarshal([]byte(test.statement), &statement)

			if test.err == nil {
				require.Nil(t, err)
				require.Equal(t, *test.result, statement)
			} else {
				require.Equal(t, err, test.err)
			}

		})
	}

}

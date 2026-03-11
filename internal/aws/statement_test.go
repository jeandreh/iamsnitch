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
		{
			"statement with single string condition",
			`{
				"Effect":"Allow",
				"Action":"s3:GetObject",
				"Resource":"arn:aws:s3:::mybucket/*",
				"Condition": {
					"StringLike": {
						"aws:username": "johndoe"
					}
				}
			}`,
			&Statement{
				Effect:    "Allow",
				Actions:   []string{"s3:GetObject"},
				Resources: []string{"arn:aws:s3:::mybucket/*"},
				Conditions: map[string]map[string]interface{}{
					"StringLike": {
						"aws:username": "johndoe",
					},
				},
			},
			nil,
		},
		{
			"statement with array condition values",
			`{
				"Effect":"Allow",
				"Action":"s3:GetObject",
				"Resource":"arn:aws:s3:::mybucket/*",
				"Condition": {
					"IpAddress": {
						"aws:SourceIp": ["192.0.2.0/24", "203.0.113.0/24"]
					}
				}
			}`,
			&Statement{
				Effect:    "Allow",
				Actions:   []string{"s3:GetObject"},
				Resources: []string{"arn:aws:s3:::mybucket/*"},
				Conditions: map[string]map[string]interface{}{
					"IpAddress": {
						"aws:SourceIp": []interface{}{"192.0.2.0/24", "203.0.113.0/24"},
					},
				},
			},
			nil,
		},
		{
			"statement with multiple condition operators",
			`{
				"Effect":"Allow",
				"Action":"s3:GetObject",
				"Resource":"arn:aws:s3:::mybucket/*",
				"Condition": {
					"StringLike": {
						"aws:username": "johndoe"
					},
					"IpAddress": {
						"aws:SourceIp": "192.0.2.0/24"
					}
				}
			}`,
			&Statement{
				Effect:    "Allow",
				Actions:   []string{"s3:GetObject"},
				Resources: []string{"arn:aws:s3:::mybucket/*"},
				Conditions: map[string]map[string]interface{}{
					"StringLike": {
						"aws:username": "johndoe",
					},
					"IpAddress": {
						"aws:SourceIp": "192.0.2.0/24",
					},
				},
			},
			nil,
		},
		{
			"statement with multiple condition keys under same operator",
			`{
				"Effect":"Allow",
				"Action":"s3:GetObject",
				"Resource":"arn:aws:s3:::mybucket/*",
				"Condition": {
					"StringEquals": {
						"aws:username": "johndoe",
						"aws:userid": "AIDACKCEVSQ6C2EXAMPLE"
					}
				}
			}`,
			&Statement{
				Effect:    "Allow",
				Actions:   []string{"s3:GetObject"},
				Resources: []string{"arn:aws:s3:::mybucket/*"},
				Conditions: map[string]map[string]interface{}{
					"StringEquals": {
						"aws:username": "johndoe",
						"aws:userid":   "AIDACKCEVSQ6C2EXAMPLE",
					},
				},
			},
			nil,
		},
		{
			"statement without conditions",
			`{
				"Effect":"Allow",
				"Action":"s3:GetObject",
				"Resource":"arn:aws:s3:::mybucket/*"
			}`,
			&Statement{
				Effect:     "Allow",
				Actions:    []string{"s3:GetObject"},
				Resources:  []string{"arn:aws:s3:::mybucket/*"},
				Conditions: nil,
			},
			nil,
		},
		{
			"statement with principal and conditions",
			`{
				"Effect":"Allow",
				"Principal": {
					"Service":"ecs.amazonaws.com"
				},
				"Action":"sts:AssumeRole",
				"Resource":"arn:aws:iam::111122223333:role/myrole",
				"Condition": {
					"StringEquals": {
						"sts:ExternalId": "unique-external-id"
					}
				}
			}`,
			&Statement{
				Effect:     "Allow",
				Principals: PrincipalList{Items: []Principal{{Service, "ecs.amazonaws.com"}}},
				Actions:    []string{"sts:AssumeRole"},
				Resources:  []string{"arn:aws:iam::111122223333:role/myrole"},
				Conditions: map[string]map[string]interface{}{
					"StringEquals": {
						"sts:ExternalId": "unique-external-id",
					},
				},
			},
			nil,
		},
		{
			"statement with complex nested conditions",
			`{
				"Effect":"Allow",
				"Action":["s3:GetObject", "s3:PutObject"],
				"Resource":"arn:aws:s3:::mybucket/*",
				"Condition": {
					"DateGreaterThan": {
						"aws:CurrentTime": "2020-01-01T00:00:00Z"
					},
					"DateLessThan": {
						"aws:CurrentTime": "2025-12-31T23:59:59Z"
					},
					"StringLike": {
						"s3:x-amz-server-side-encryption": "AES256"
					}
				}
			}`,
			&Statement{
				Effect:    "Allow",
				Actions:   []string{"s3:GetObject", "s3:PutObject"},
				Resources: []string{"arn:aws:s3:::mybucket/*"},
				Conditions: map[string]map[string]interface{}{
					"DateGreaterThan": {
						"aws:CurrentTime": "2020-01-01T00:00:00Z",
					},
					"DateLessThan": {
						"aws:CurrentTime": "2025-12-31T23:59:59Z",
					},
					"StringLike": {
						"s3:x-amz-server-side-encryption": "AES256",
					},
				},
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

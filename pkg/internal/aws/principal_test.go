package aws

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeserialisePrincipalFromJSON(t *testing.T) {
	tests := []struct {
		name      string
		principal string
		result    *PrincipalList
		err       error
	}{
		{
			"single service principal",
			`{
				"Service":"ecs.amazonaws.com"
			}`,
			&PrincipalList{
				Items: []Principal{
					{
						Type: Service,
						ID:   "ecs.amazonaws.com",
					},
				},
			},
			nil,
		},
		{
			"two service principals",
			`{
				"Service": [
					"ecs.amazonaws.com",
					"s3.amazonaws.com"
				]
			}`,
			&PrincipalList{
				Items: []Principal{
					{
						Type: Service,
						ID:   "ecs.amazonaws.com",
					},
					{
						Type: Service,
						ID:   "s3.amazonaws.com",
					},
				},
			},
			nil,
		},
		{
			"service and user principals",
			`{
				"Service": "ecs.amazonaws.com",
				"AWS": "arn:aws:iam::111122223333:user/test"
			}`,
			&PrincipalList{
				Items: []Principal{
					{
						Type: Service,
						ID:   "ecs.amazonaws.com",
					},
					{
						Type: AWS,
						ID:   "arn:aws:iam::111122223333:user/test",
					},
				},
			},
			nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var principals PrincipalList
			err := json.Unmarshal([]byte(test.principal), &principals)

			if test.err == nil {
				require.Nil(t, err)
				require.Equal(t, *test.result, principals)
			} else {
				require.Equal(t, err, test.err)
			}

		})
	}
}

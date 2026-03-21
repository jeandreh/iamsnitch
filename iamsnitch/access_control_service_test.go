package iamsnitch

import (
	"fmt"
	"testing"

	"go.uber.org/mock/gomock"
	"github.com/jeandreh/iam-snitch/internal/domain/model"
	"github.com/jeandreh/iam-snitch/internal/mocks"
	"github.com/stretchr/testify/require"
)

func TestRefreshACL(t *testing.T) {
	tests := []struct {
		name         string
		want         []model.AccessControlRule
		wantErrFetch error
		wantErrSave  error
		wantErr      error
	}{
		{
			"success",
			[]model.AccessControlRule{},
			nil,
			nil,
			nil,
		},
		{
			"error fetch",
			nil,
			fmt.Errorf("fetch error"),
			nil,
			fmt.Errorf("fetch error"),
		},
		{
			"error save",
			[]model.AccessControlRule{},
			nil,
			fmt.Errorf("save error"),
			fmt.Errorf("save error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			iamMock := mocks.NewIAMProviderMock(ctrl)
			cacheMock := mocks.NewCacheMock(ctrl)

			a := &AccessControlService{
				provider: iamMock,
				cache:    cacheMock,
			}

			pageMock := mocks.NewPageMock(ctrl)

			iamMock.
				EXPECT().
				FetchIdentityPolicies(nil).
				Return([]model.IdentityPolicy{}, pageMock, tt.wantErrFetch).
				Times(1)

			if tt.wantErrFetch == nil {
				pageMock.
					EXPECT().
					HasNext().
					Return(false).
					Times(1)

				iamMock.
					EXPECT().
					FetchPermissionBoundaries(gomock.Any()).
					Return(map[string]*model.BoundaryPolicy{}, nil).
					Times(1)

				iamMock.
					EXPECT().
					FetchSCPs().
					Return([]model.SCPPolicy{}, nil).
					Times(1)

				cacheMock.
					EXPECT().
					SaveACL(gomock.Any()).
					Return(tt.wantErrSave).
					Times(1)
			}

			require.Equal(t, tt.wantErr, a.RefreshACL([]string{}))
		})
	}
}

func TestWhoCan(t *testing.T) {
	type args struct {
		actions   []string
		resources []string
		exact     bool
	}
	tests := []struct {
		name    string
		args    args
		want    []model.AccessControlRule
		wantErr error
	}{
		{
			"globbed search",
			args{
				actions:   []string{"someaction"},
				resources: []string{"resource"},
				exact:     false,
			},
			[]model.AccessControlRule{
				{
					Principal: model.Principal{ID: "someprincipal"},
				},
			},
			nil,
		},
		{
			"exact search",
			args{
				actions:   []string{"someaction"},
				resources: []string{"resource"},
				exact:     true,
			},
			[]model.AccessControlRule{
				{
					Principal: model.Principal{ID: "someprincipal"},
				},
			},
			nil,
		},
		{
			"find error",
			args{
				actions:   []string{"someaction"},
				resources: []string{"resource"},
				exact:     false,
			},
			nil,
			fmt.Errorf("find error"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			iamMock := mocks.NewIAMProviderMock(ctrl)
			cacheMock := mocks.NewCacheMock(ctrl)

			a := &AccessControlService{
				provider: iamMock,
				cache:    cacheMock,
			}

			iamMock.
				EXPECT().
				FetchIdentityPolicies(gomock.Any()).
				Times(0)

			cacheMock.
				EXPECT().
				Find(gomock.Eq(&model.Filter{
					Permissions: tt.args.actions,
					Resources:   tt.args.resources,
					ExactMatch:  tt.args.exact,
				})).
				Return(tt.want, tt.wantErr).
				Times(1)

			acl, err := a.WhoCan(tt.args.actions, tt.args.resources, tt.args.exact)

			require.Equal(t, tt.wantErr, err)
			require.Equal(t, tt.want, acl)
		})
	}
}

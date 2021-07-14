package iamsnitch

import (
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/jeandreh/iam-snitch/internal/domain"
	"github.com/jeandreh/iam-snitch/internal/mocks"
	"github.com/stretchr/testify/require"
)

func TestRefreshACL(t *testing.T) {
	tests := []struct {
		name         string
		want         []domain.AccessControlRule
		wantErrFetch error
		wantErrSave  error
		wantErr      error
	}{
		{
			"success",
			[]domain.AccessControlRule{},
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
			[]domain.AccessControlRule{},
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

			iamMock.
				EXPECT().
				FetchACL().
				Return(tt.want, tt.wantErrFetch).
				Times(1)

			if tt.wantErrFetch == nil {
				cacheMock.
					EXPECT().
					SaveACL(gomock.Eq(tt.want)).
					Return(tt.wantErrSave).
					Times(1)
			} else {
				cacheMock.
					EXPECT().
					SaveACL(gomock.Any()).
					Times(0)
			}

			require.Equal(t, tt.wantErr, a.RefreshACL())
		})
	}
}

func TestWhoCan(t *testing.T) {
	type args struct {
		action   domain.Action
		resource domain.Resource
	}
	tests := []struct {
		name    string
		args    args
		want    []domain.AccessControlRule
		wantErr error
	}{
		{
			"success",
			args{
				action: domain.Action{
					ID: "someaction",
				},
				resource: domain.Resource{
					ID: "resource",
				},
			},
			[]domain.AccessControlRule{
				{
					Principal: domain.Principal{ID: "someprincipal"},
				},
			},
			nil,
		},
		{
			"find error",
			args{
				action: domain.Action{
					ID: "someaction",
				},
				resource: domain.Resource{
					ID: "resource",
				},
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
				FetchACL().
				Times(0)

			cacheMock.
				EXPECT().
				Find(gomock.Eq(&domain.Filter{
					Actions:   []domain.Action{tt.args.action},
					Resources: []domain.Resource{tt.args.resource},
				})).
				Return(tt.want, tt.wantErr).
				Times(1)

			acl, err := a.WhoCan(tt.args.action, tt.args.resource)

			require.Equal(t, tt.wantErr, err)
			require.Equal(t, tt.want, acl)
		})
	}
}

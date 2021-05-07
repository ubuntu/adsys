package adsysservice_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/adsysservice"
	"github.com/ubuntu/adsys/internal/authorizer"
)

type mockAuthorizer struct {
	doneCalled int
	doneError  error
}

func (mockAuthorizer) IsAllowedFromContext(context.Context, authorizer.Action) error {
	return nil
}

func (m *mockAuthorizer) Done() error {
	m.doneCalled++
	return m.doneError
}

func TestNew(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		authorizerDoneFail     error
		AdNewFail              bool
		existingAdsysDirs      bool
		readUnexistingSssdConf bool

		wantNewErr     bool
		wantDoneCalled int
	}{
		"New and Done succeeds as expected, first run": {wantDoneCalled: 1},
		"Done fails only prints a warning":             {authorizerDoneFail: errors.New("Fail to create authorizer"), wantDoneCalled: 1},
		"Adsys directory can already exists":           {existingAdsysDirs: true, wantDoneCalled: 1},

		// Error cases
		"Ad New fails prevents adsysservice creation":      {AdNewFail: true, existingAdsysDirs: true, wantNewErr: true},
		"No url and domain while sssdconf does not exists": {readUnexistingSssdConf: true, wantNewErr: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			temp := t.TempDir()
			adsysCacheDir := filepath.Join(temp, "cache")
			adsysRunDir := filepath.Join(temp, "run")
			dconfDir := filepath.Join(temp, "dconf")
			sssCacheDir := filepath.Join(temp, "sss")
			if tc.existingAdsysDirs {
				require.NoError(t, os.MkdirAll(adsysCacheDir, 0700), "Setup: could not create adsys cache directory")
				require.NoError(t, os.MkdirAll(adsysRunDir, 0700), "Setup: could not create adsys run directory")
			}

			auth := mockAuthorizer{doneError: tc.authorizerDoneFail}

			if tc.AdNewFail {
				err := os.Chmod(adsysCacheDir, 0000)
				require.NoError(t, err, "Setup: Could not prevent writing to cache directory")
				defer func() {
					err := os.Chmod(adsysCacheDir, 0700)
					require.NoError(t, err, "Teardown: Could not restore writing to cache directory")
				}()
			}

			var s *adsysservice.Service
			var err error
			if !tc.readUnexistingSssdConf {
				s, err = adsysservice.New(context.Background(), "my-ldap-url", "example.com",
					adsysservice.WithCacheDir(adsysCacheDir),
					adsysservice.WithRunDir(adsysRunDir),
					adsysservice.WithDconfDir(dconfDir),
					adsysservice.WithSSSCacheDir(sssCacheDir),
					adsysservice.WithMockAuthorizer(&auth),
				)
			} else {
				s, err = adsysservice.New(context.Background(), "", "",
					adsysservice.WithSSSdConf(filepath.Join(temp, "does-not-exists", "sssd.conf")))
			}

			if tc.wantNewErr {
				require.Error(t, err, "New should return an error but didn’t")
				return
			}
			require.NoError(t, err, "New should not return an error")

			s.Quit(context.Background())
			require.Equal(t, tc.wantDoneCalled, auth.doneCalled, "Done was called the expected number of times")

			_, err = os.Stat(adsysCacheDir)
			require.NoError(t, err, "adsys cache directory exists as expected")
			_, err = os.Stat(adsysRunDir)
			require.NoError(t, err, "adsys run directory exists as expected")
		})
	}
}

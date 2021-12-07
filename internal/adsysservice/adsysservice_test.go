package adsysservice_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/adsysservice"
	"github.com/ubuntu/adsys/internal/authorizer"
)

type mockAuthorizer struct {
}

func (mockAuthorizer) IsAllowedFromContext(context.Context, authorizer.Action) error {
	return nil
}

func TestNew(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		url                    string
		domain                 string
		authorizerDoneFail     error
		AdNewFail              bool
		existingAdsysDirs      bool
		readUnexistingSssdConf bool

		wantNewErr bool
	}{
		"New and Done succeeds as expected, first run": {url: "my-ldap-url", domain: "example.com"},
		"Adsys directory can already exists":           {url: "my-ldap-url", domain: "example.com", existingAdsysDirs: true},

		// Error cases
		"Ad New fails prevents adsysservice creation":      {url: "my-ldap-url", domain: "example.com", AdNewFail: true, existingAdsysDirs: true, wantNewErr: true},
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
			sudoersDir := filepath.Join(temp, "sudoers.d")
			policyKitDir := filepath.Join(temp, "polkit-1")
			sssCacheDir := filepath.Join(temp, "sss")
			if tc.existingAdsysDirs {
				require.NoError(t, os.MkdirAll(adsysCacheDir, 0700), "Setup: could not create adsys cache directory")
				require.NoError(t, os.MkdirAll(adsysRunDir, 0700), "Setup: could not create adsys run directory")
			}

			auth := mockAuthorizer{}

			if tc.AdNewFail {
				err := os.Chmod(adsysCacheDir, 0000)
				require.NoError(t, err, "Setup: Could not prevent writing to cache directory")
				defer func() {
					err := os.Chmod(adsysCacheDir, 0600)
					require.NoError(t, err, "Teardown: Could not restore writing to cache directory")
				}()
			}

			options := []adsysservice.Option{
				adsysservice.WithCacheDir(adsysCacheDir),
				adsysservice.WithRunDir(adsysRunDir),
				adsysservice.WithDconfDir(dconfDir),
				adsysservice.WithSudoersDir(sudoersDir),
				adsysservice.WithPolicyKitDir(policyKitDir),
				adsysservice.WithSSSCacheDir(sssCacheDir),
				adsysservice.WithMockAuthorizer(&auth),
				adsysservice.WithDefaultDomainSuffix("mydomain.biz"),
			}
			if tc.readUnexistingSssdConf {
				options = append(options, adsysservice.WithSSSdConf(filepath.Join(temp, "does-not-exists", "sssd.conf")))
			}

			s, err := adsysservice.New(context.Background(), tc.url, tc.domain, options...)
			if tc.wantNewErr {
				require.Error(t, err, "New should return an error but didn’t")
				return
			}
			require.NoError(t, err, "New should not return an error")

			s.Quit(context.Background())

			_, err = os.Stat(adsysCacheDir)
			require.NoError(t, err, "adsys cache directory exists as expected")
			_, err = os.Stat(adsysRunDir)
			require.NoError(t, err, "adsys run directory exists as expected")
		})
	}
}

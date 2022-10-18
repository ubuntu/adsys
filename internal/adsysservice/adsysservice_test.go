package adsysservice_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/ad/backends/sss"
	"github.com/ubuntu/adsys/internal/adsysservice"
	"github.com/ubuntu/adsys/internal/authorizer"
	"github.com/ubuntu/adsys/internal/testutils"
)

type mockAuthorizer struct {
}

func (mockAuthorizer) IsAllowedFromContext(context.Context, authorizer.Action) error {
	return nil
}

func TestNew(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		sssdConf string

		roDir             string
		existingAdsysDirs bool

		wantNewErr bool
	}{
		"New and Quit succeeds as expected, first run": {},
		"Adsys directory can already exists":           {existingAdsysDirs: true},

		// Error cases
		"Error on failure to create run directory":       {roDir: "parentrun", wantNewErr: true},
		"Error on failure to create cache directory":     {roDir: "parentcache", wantNewErr: true},
		"Error on nonexistent sssd.conf":                 {sssdConf: "does_not_exist", wantNewErr: true},
		"Error on ad.New prevents adsysservice creation": {roDir: "parentcache/cache", wantNewErr: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if tc.sssdConf == "" {
				tc.sssdConf = "testdata/sssd.conf"
			}

			temp := t.TempDir()
			adsysCacheDir := filepath.Join(temp, "parentcache", "cache")
			adsysRunDir := filepath.Join(temp, "parentrun", "run")
			dconfDir := filepath.Join(temp, "dconf")
			sudoersDir := filepath.Join(temp, "sudoers.d")
			policyKitDir := filepath.Join(temp, "polkit-1")
			apparmorDir := filepath.Join(temp, "apparmor.d", "adsys")
			apparmorFsDir := filepath.Join(temp, "apparmorfs")
			if tc.existingAdsysDirs {
				require.NoError(t, os.MkdirAll(adsysCacheDir, 0700), "Setup: could not create adsys cache directory")
				require.NoError(t, os.MkdirAll(adsysRunDir, 0700), "Setup: could not create adsys run directory")
			}

			sssdConfig := sss.Config{
				Conf:     tc.sssdConf,
				CacheDir: t.TempDir(),
			}

			if tc.roDir != "" {
				dest := filepath.Join(temp, tc.roDir)
				require.NoError(t, os.MkdirAll(dest, 0700), "Setup: can't create directory to make it Read Only")
				testutils.MakeReadOnly(t, dest)
			}

			options := []adsysservice.Option{
				adsysservice.WithCacheDir(adsysCacheDir),
				adsysservice.WithRunDir(adsysRunDir),
				adsysservice.WithDconfDir(dconfDir),
				adsysservice.WithSudoersDir(sudoersDir),
				adsysservice.WithPolicyKitDir(policyKitDir),
				adsysservice.WithApparmorDir(apparmorDir),
				adsysservice.WithApparmorFsDir(apparmorFsDir),
				adsysservice.WithSSSConfig(sssdConfig),
			}

			s, err := adsysservice.New(context.Background(), options...)
			if tc.wantNewErr {
				require.Error(t, err, "New should return an error but did not")
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

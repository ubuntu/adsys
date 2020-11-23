package ad_test

import (
	"context"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/policies/ad"
)

func TestNew(t *testing.T) {
	t.Parallel() // we setenv for kinit

	tests := map[string]struct {
		cacheDirRO bool
		runDirRO   bool
		kinitFail  bool

		wantErr bool
	}{
		"create one AD object will create all necessary cache dirs": {},
		"failed to create KRB5 cache directory":                     {runDirRO: true, wantErr: true},
		"failed to create GPO cache directory":                      {cacheDirRO: true, wantErr: true},
		"failed to execute kinit":                                   {kinitFail: true, wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			//t.Parallel() // we setenv for kinit
			runDir, cacheDir := t.TempDir(), t.TempDir()

			if tc.runDirRO {
				require.NoError(t, os.Chmod(runDir, 0400), "Setup: can’t set run directory to Read only")

			}
			if tc.cacheDirRO {
				require.NoError(t, os.Chmod(cacheDir, 0400), "Setup: can’t set cache directory to Read only")
			}
			if tc.kinitFail {
				err := os.Setenv("KINITFAILED", "1")
				require.NoError(t, err, "Setup: can’t set env variable for KINIT to fail")
				defer func() {
					if err := os.Unsetenv("KINITFAILED"); err != nil {
						log.Printf("Couln't restore initial value for KINIT_FAILED: %v", err)
					}
				}()
			}

			adc, err := ad.New(context.Background(), "ldap://UNUSED:1636/", "localdomain", ad.WithRunDir(runDir), ad.WithCacheDir(cacheDir))
			if tc.wantErr {
				require.NotNil(t, err, "AD creation should have failed")
			} else {
				require.NoError(t, err, "AD creation should be successfull failed")
			}

			if !tc.wantErr {
				// Ensure cache directories exists
				assert.DirExists(t, adc.Krb5CacheDir(), "Kerberos ticket cache directory doesn't exist")
				assert.DirExists(t, adc.GpoCacheDir(), "GPO cache directory doesn't exist")
			}
		})
	}
}

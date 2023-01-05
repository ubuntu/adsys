package ad_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/ad"
	"github.com/ubuntu/adsys/internal/ad/backends"
	"github.com/ubuntu/adsys/internal/ad/backends/mock"
	"github.com/ubuntu/adsys/internal/policies"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestNew(t *testing.T) {
	t.Parallel()

	bus := testutils.NewDbusConn(t)
	hostname, err := os.Hostname()
	require.NoError(t, err, "Setup: failed to get hostname for tests.")

	tests := map[string]struct {
		sysvolCacheDirExists  bool
		cacheDirRO            bool
		runDirRO              bool
		backendServerURLError error

		wantErr bool
	}{
		"create KRB5 and Sysvol cache directory":                {},
		"no active server in backend does not fail ad creation": {backendServerURLError: backends.ErrNoActiveServer},

		"failed to create KRB5 cache directory":     {runDirRO: true, wantErr: true},
		"failed to create Sysvol cache directory":   {cacheDirRO: true, wantErr: true},
		"failed to create Policies cache directory": {sysvolCacheDirExists: true, cacheDirRO: true, wantErr: true},
		"error on backend ServerURL random failure": {backendServerURLError: errors.New("Some failure on ServerURL"), wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runDir, cacheDir := t.TempDir(), t.TempDir()

			if tc.sysvolCacheDirExists {
				require.NoError(t, os.MkdirAll(filepath.Join(cacheDir, "sysvol", "Policies"), 0750),
					"Setup: create pre-existing policies cache directory")
			}
			if tc.runDirRO {
				testutils.MakeReadOnly(t, runDir)
			}
			if tc.cacheDirRO {
				testutils.MakeReadOnly(t, cacheDir)
			}

			adc, err := ad.New(context.Background(), bus, mock.Backend{ErrServerURL: tc.backendServerURLError}, hostname,
				ad.WithRunDir(runDir),
				ad.WithCacheDir(cacheDir))
			if tc.wantErr {
				require.NotNil(t, err, "AD creation should have failed")
				return
			}

			require.NoError(t, err, "AD creation should be successful failed")

			// Ensure cache directories exists
			assert.DirExists(t, adc.Krb5CacheDir(), "Kerberos ticket cache directory doesn't exist")
			assert.DirExists(t, adc.SysvolCacheDir(), "GPO cache directory doesn't exist")
			assert.DirExists(t, adc.PoliciesCacheDir(), "policies cache directory doesn't exist")
		})
	}
}

func TestGetPolicies(t *testing.T) {
	t.Parallel() // libsmbclient overrides SIGCHILD, but we have one global lock

	hostname, err := os.Hostname()
	require.NoError(t, err, "Setup: failed to get hostname")

	bus := testutils.NewDbusConn(t)

	/*
				GPOs layout:

						User
						standard	A:standardA B:standardB C:standardC
						user-only	A:userOnlyA B:userOnlyB
						one-value	C:oneValueC
					disabled-value C

						Machine
						standard		A:standardA D:standardD E:standardE
						machine-only	A:machOnlyA D:machOnlyD
						one-value		E:oneValueE
						disabled-value C
		 		*

		 			/*
					TODO:
					- Verify if Registry.pol always exists or not. If it doesn't when no value
					  is modified for the host, it'll defeat the strategy to set default values.
	*/

	tests := map[string]struct {
		objectName         string
		objectClass        ad.ObjectClass
		userKrb5CCBaseName string

		backend     mock.Backend
		versionID   string
		gpoListArgs []string

		turnKrb5CCCacheRO bool
		existing          map[string]string

		want             policies.Policies
		wantAssetsEquals string
		wantErr          bool
	}{
		"Standard policy, user object": {
			gpoListArgs: []string{"gpoonly.com", "bob:standard"},
			want:        policies.Policies{GPOs: []policies.GPO{standardUserGPO("standard")}},
		},
		"Standard policy, computer object": {
			objectName:  hostname,
			objectClass: ad.ComputerObject,
			gpoListArgs: []string{"gpoonly.com", hostname + ":standard"},
			want:        policies.Policies{GPOs: []policies.GPO{standardComputerGPO("standard")}},
		},
		"User only policy, user object": {
			gpoListArgs: []string{"gpoonly.com", "bob:user-only"},
			want: policies.Policies{GPOs: []policies.GPO{
				{ID: "user-only", Name: "user-only-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "A", Value: "userOnlyA"},
						{Key: "B", Value: "userOnlyB"},
					}}}},
			},
		},
		"User only policy, computer object, policy is empty": {
			objectName:  hostname,
			objectClass: ad.ComputerObject,
			gpoListArgs: []string{"gpoonly.com", hostname + ":user-only"},
			want:        policies.Policies{GPOs: []policies.GPO{{ID: "user-only", Name: "user-only-name", Rules: make(map[string][]entry.Entry)}}},
		},
		"Computer only policy, user object, policy is empty": {
			gpoListArgs: []string{"gpoonly.com", "bob:machine-only"},
			want:        policies.Policies{GPOs: []policies.GPO{{ID: "machine-only", Name: "machine-only-name", Rules: make(map[string][]entry.Entry)}}},
		},

		// Assets cases
		"Standard policy with assets, downloads assets": {
			objectName:  hostname,
			objectClass: ad.ComputerObject,
			backend: mock.Backend{
				Dom:    "assetsandgpo.com",
				Online: true,
			},
			gpoListArgs:      []string{"assetsandgpo.com", hostname + ":standard"},
			want:             policies.Policies{GPOs: []policies.GPO{standardComputerGPO("standard")}},
			wantAssetsEquals: "testdata/AD/SYSVOL/assetsandgpo.com/Ubuntu",
		},
		"Standard policy with assets, existing assets are reattached if not refreshed": {
			objectName: "bob@ASSETSANDGPO.COM",
			backend: mock.Backend{
				Dom:    "assetsandgpo.com",
				Online: true,
			},
			gpoListArgs:      []string{"assetsandgpo.com", "bob:standard"},
			existing:         map[string]string{"assets": "testdata/AD/SYSVOL/assetsandgpo.com/Ubuntu", "assets.db": "testdata/sysvolcache/assets.db"},
			want:             policies.Policies{GPOs: []policies.GPO{standardUserGPO("standard")}},
			wantAssetsEquals: "testdata/AD/SYSVOL/assetsandgpo.com/Ubuntu",
		},
		"Local assets and its db are removed if not present anymore on AD sysvol": {
			objectName: "bob@ASSETSANDGPO.COM",
			backend: mock.Backend{
				Dom:    "assetsandgpo.com",
				Online: true,
			},
			gpoListArgs:      []string{"gpoonly.com", "bob:standard"}, // this forces to download from a GPO without assets
			existing:         map[string]string{"assets": "testdata/AD/SYSVOL/assetsandgpo.com/Ubuntu", "assets.db": "testdata/sysvolcache/assets.db"},
			want:             policies.Policies{GPOs: []policies.GPO{standardUserGPO("standard")}},
			wantAssetsEquals: "",
		},
		"Assets can’t be downloaded without GPO": {
			objectName:  hostname,
			objectClass: ad.ComputerObject,
			backend: mock.Backend{
				Dom:    "assetsandgpo.com",
				Online: true,
			},
			gpoListArgs:      []string{"assetsonly.com", ""},
			want:             policies.Policies{},
			wantAssetsEquals: "",
		},
		"Assets directory being a file cleanup local existing assets and its db": {
			objectName:  hostname,
			objectClass: ad.ComputerObject,
			backend: mock.Backend{
				Dom:    "assetsdirisfile.com",
				Online: true,
			},
			gpoListArgs:      []string{"assetsdirisfile.com", hostname + ":standard"},
			existing:         map[string]string{"assets": "testdata/AD/SYSVOL/assetsandgpo.com/Ubuntu", "assets.db": "testdata/sysvolcache/assets.db"},
			want:             policies.Policies{GPOs: []policies.GPO{standardComputerGPO("standard")}},
			wantAssetsEquals: "",
		},

		// Multi releases cases
		"Enabled override": {
			versionID:   "21.04",
			gpoListArgs: []string{"gpoonly.com", "bob:multiple-releases-one-enabled"},
			want: policies.Policies{GPOs: []policies.GPO{{ID: "multiple-releases-one-enabled", Name: "multiple-releases-one-enabled-name", Rules: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "21.04Value"},
				}}}},
			},
		},
		"Disabled override": {
			versionID:   "21.04",
			gpoListArgs: []string{"gpoonly.com", "bob:multiple-releases-one-disabled"},
			want: policies.Policies{GPOs: []policies.GPO{{ID: "multiple-releases-one-disabled", Name: "multiple-releases-one-disabled-name", Rules: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "AllValue"},
				}}}},
			},
		},
		"Enabled override for matching release, other releases override ignored": {
			versionID:   "21.04",
			gpoListArgs: []string{"gpoonly.com", "bob:multiple-releases"},
			want: policies.Policies{GPOs: []policies.GPO{{ID: "multiple-releases", Name: "multiple-releases-name", Rules: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "21.04Value"},
				}}}},
			},
		},
		"Disable override for matching release, other releases override ignored": {
			versionID:   "20.04",
			gpoListArgs: []string{"gpoonly.com", "bob:multiple-releases"},
			want: policies.Policies{GPOs: []policies.GPO{{ID: "multiple-releases", Name: "multiple-releases-name", Rules: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "AllValue"},
				}}}},
			},
		},
		"No override for this release, takes default value": {
			versionID:   "not in pol file",
			gpoListArgs: []string{"gpoonly.com", "bob:multiple-releases"},
			want: policies.Policies{GPOs: []policies.GPO{{ID: "multiple-releases", Name: "multiple-releases-name", Rules: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "AllValue"},
				}}}},
			},
		},

		// No override option for this release

		// Multi domain cases
		"Multiple domains, same GPO": {
			gpoListArgs: []string{"gpoonly.com", "bob:multiple-domains"},
			want: policies.Policies{GPOs: []policies.GPO{
				{ID: "multiple-domains", Name: "multiple-domains-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "A", Value: "standardA"},
						{Key: "C", Value: "standardC"},
					},
					"other": {
						{Key: "B", Value: "standardB"},
					}}}},
			},
		},
		"Same key in different domains are kept separated": {
			gpoListArgs: []string{"gpoonly.com", "bob:other-domain::bob:one-value"},
			want: policies.Policies{GPOs: []policies.GPO{
				{ID: "other-domain", Name: "other-domain-name", Rules: map[string][]entry.Entry{
					"other": {
						{Key: "C", Value: "otherC"},
					}}},
				{ID: "one-value", Name: "one-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "C", Value: "oneValueC"},
					}}}},
			},
		},

		"Two policies, with overrides": {
			gpoListArgs: []string{"gpoonly.com", "bob:one-value::bob:standard"},
			want: policies.Policies{GPOs: []policies.GPO{
				{ID: "one-value", Name: "one-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "C", Value: "oneValueC"},
					}}},
				{ID: "standard", Name: "standard-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "A", Value: "standardA"},
						{Key: "B", Value: "standardB"},
						// this value will be overridden with the higher one
						{Key: "C", Value: "standardC"},
					}}}},
			},
		},
		"Two policies, with reversed overrides": {
			gpoListArgs: []string{"gpoonly.com", "bob:standard::bob:one-value"},
			want: policies.Policies{GPOs: []policies.GPO{
				standardUserGPO("standard"),
				{ID: "one-value", Name: "one-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						// this value will be overridden with the higher one
						{Key: "C", Value: "oneValueC"},
					}}}},
			},
		},
		"Two policies, no overrides": {
			gpoListArgs: []string{"gpoonly.com", "bob:one-value::bob:user-only"},
			want: policies.Policies{GPOs: []policies.GPO{
				{ID: "one-value", Name: "one-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "C", Value: "oneValueC"},
					}}},
				{ID: "user-only", Name: "user-only-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "A", Value: "userOnlyA"},
						{Key: "B", Value: "userOnlyB"},
					}}}},
			},
		},
		"Two policies, no overrides, reversed": {
			gpoListArgs: []string{"gpoonly.com", "bob:user-only::bob:one-value"},
			want: policies.Policies{GPOs: []policies.GPO{
				{ID: "user-only", Name: "user-only-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "A", Value: "userOnlyA"},
						{Key: "B", Value: "userOnlyB"},
					}}},
				{ID: "one-value", Name: "one-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "C", Value: "oneValueC"},
					}}}},
			},
		},
		"Two policies, no overrides, one is not the same object type, machine ones are empty when parsing user": {
			gpoListArgs: []string{"gpoonly.com", "bob:machine-only::bob:standard"},
			want: policies.Policies{GPOs: []policies.GPO{{ID: "machine-only", Name: "machine-only-name", Rules: make(map[string][]entry.Entry)},
				standardUserGPO("standard")}},
		},

		"Disabled value overrides non disabled one": {
			gpoListArgs: []string{"gpoonly.com", "bob:disabled-value::bob:standard"},
			want: policies.Policies{GPOs: []policies.GPO{
				{ID: "disabled-value", Name: "disabled-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "C", Value: "", Disabled: true},
					}}},
				standardUserGPO("standard"),
			}},
		},
		"Disabled value is overridden": {
			gpoListArgs: []string{"gpoonly.com", "bob:standard::bob:disabled-value"},
			want: policies.Policies{GPOs: []policies.GPO{
				standardUserGPO("standard"),
				{ID: "disabled-value", Name: "disabled-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "C", Value: "", Disabled: true},
					}}},
			}},
		},

		"More policies, with multiple overrides": {
			gpoListArgs: []string{"gpoonly.com", "bob:user-only::bob:one-value::bob:standard"},
			want: policies.Policies{GPOs: []policies.GPO{
				{ID: "user-only", Name: "user-only-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "A", Value: "userOnlyA"},
						{Key: "B", Value: "userOnlyB"},
					}}},
				{ID: "one-value", Name: "one-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "C", Value: "oneValueC"},
					}}},
				standardUserGPO("standard"),
			}},
		},
		"Filter non Ubuntu keys": {
			gpoListArgs: []string{"gpoonly.com", "bob:filtered"},
			want: policies.Policies{GPOs: []policies.GPO{
				{ID: "filtered", Name: "filtered-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "A", Value: "standardA"},
						{Key: "C", Value: "standardC"},
					}}},
			}},
		},
		"Ignore errors on non Ubuntu keys": {
			gpoListArgs: []string{"gpoonly.com", "bob:unsupported-with-errors"},
			want: policies.Policies{GPOs: []policies.GPO{
				{ID: "unsupported-with-errors", Name: "unsupported-with-errors-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "A", Value: "standardA"},
						{Key: "C", Value: "standardC"},
					}}},
			}},
		},

		// Policy class directory spelling cases
		"Policy user directory is uppercase": {
			gpoListArgs: []string{"gpoonly.com", "bob:uppercase-class"},
			want:        policies.Policies{GPOs: []policies.GPO{standardUserGPO("uppercase-class")}},
		},
		"Policy machine directory is uppercase": {
			objectName:  hostname,
			objectClass: ad.ComputerObject,
			gpoListArgs: []string{"gpoonly.com", hostname + ":uppercase-class"},
			want:        policies.Policies{GPOs: []policies.GPO{standardComputerGPO("uppercase-class")}},
		},

		"Policy user directory is not capitalized or uppercase, no rules are parsed": {
			gpoListArgs: []string{"gpoonly.com", "bob:lowercase-class"},
			want: policies.Policies{GPOs: []policies.GPO{
				{ID: "lowercase-class", Name: "lowercase-class-name", Rules: map[string][]entry.Entry{}}},
			},
		},
		"Policy machine directory is not capitalized or uppercase, no rules are parsed": {
			objectName:  hostname,
			objectClass: ad.ComputerObject,
			gpoListArgs: []string{"gpoonly.com", hostname + ":lowercase-class"},
			want: policies.Policies{GPOs: []policies.GPO{
				{ID: "lowercase-class", Name: "lowercase-class-name", Rules: map[string][]entry.Entry{}}},
			},
		},

		// Error cases
		"Machine doesn’t match": {
			objectName:  "NotHostname",
			objectClass: ad.ComputerObject,
			gpoListArgs: []string{"gpoonly.com", "NotHostname:standard"},
			wantErr:     true,
		},
		"Without previous call, needs userKrb5CCBaseName": {
			gpoListArgs:        []string{"gpoonly.com", "bob:standard"},
			userKrb5CCBaseName: "-",
			wantErr:            true,
		},
		"Unexisting CC original file for user": {
			gpoListArgs:        []string{"gpoonly.com", "bob:standard"},
			userKrb5CCBaseName: "dont-exist",
			wantErr:            true,
		},
		"Unexisting CC original file for machine": {
			objectName:  hostname,
			objectClass: ad.ComputerObject,
			backend: mock.Backend{
				Dom:                "gpoonly.com",
				HostKrb5CCNamePath: "dont-exist",
				Online:             true,
			},
			gpoListArgs: []string{"gpoonly.com", hostname + ":standard"},
			wantErr:     true,
		},
		"Error on backend ServerURL call failed": {
			backend: mock.Backend{
				Dom:    "gpoonly.com",
				Online: true,
				// This error is skipped by New(), but not by GetPolicies
				ErrServerURL: backends.ErrNoActiveServer,
			},
			gpoListArgs: []string{"gpoonly.com", "bob:standard"},
			wantErr:     true,
		},
		"Error on backend IsOnline call failed": {
			backend: mock.Backend{
				Dom:         "gpoonly.com",
				Online:      true,
				ErrIsOnline: true,
			},
			gpoListArgs: []string{"gpoonly.com", "bob:standard"},
			wantErr:     true,
		},
		"Error on backend HostKrb5CCName call failed": {
			objectName:  hostname,
			objectClass: ad.ComputerObject,
			backend: mock.Backend{
				Dom:           "gpoonly.com",
				Online:        true,
				ErrKrb5CCName: true,
			},
			gpoListArgs: []string{"gpoonly.com", hostname + ":standard"},
			wantErr:     true,
		},
		"Error on user without @ in name": {
			objectName:  "bob",
			gpoListArgs: []string{"gpoonly.com", "bob:standard"},
			want:        policies.Policies{GPOs: []policies.GPO{standardUserGPO("standard")}},
			wantErr:     true,
		},
		"Corrupted policy file": {
			gpoListArgs: []string{"gpoonly.com", "bob:corrupted-policy"},
			wantErr:     true,
		},
		"Policy can’t be downloaded": {
			gpoListArgs: []string{"gpoonly.com", "bob:no-gpt-ini"},
			wantErr:     true,
		},
		"Symlinks can’t be created": {
			gpoListArgs:       []string{"gpoonly.com", "bob:standard"},
			turnKrb5CCCacheRO: true,
			wantErr:           true,
		},
		"Unsupported type for unfiltered entry": {
			gpoListArgs: []string{"gpoonly.com", "bob:bad-entry-type"},
			wantErr:     true,
		},
		"Empty value for unfiltered entry": {
			gpoListArgs: []string{"gpoonly.com", "bob:empty-value"},
			wantErr:     true,
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel() // libsmbclient overrides SIGCHILD, but we have one global lock

			if tc.objectName == "" {
				tc.objectName = "bob@GPOONLY.COM"
			}
			if tc.objectClass == "" {
				tc.objectClass = ad.UserObject
			}

			if tc.backend == (mock.Backend{}) {
				tc.backend = mock.Backend{
					Dom:    "gpoonly.com",
					Online: true,
				}
			}
			if tc.backend.ServURL == "" {
				tc.backend.ServURL = "ldap://myserver." + tc.backend.Dom
			}
			// we file in host_ccache to not have to reset it in every single test
			if tc.backend.HostKrb5CCNamePath == "" {
				tc.backend.HostKrb5CCNamePath = filepath.Join(t.TempDir(), "host_ccache")
			}
			if tc.backend.HostKrb5CCNamePath != "dont-exist" {
				testutils.CreatePath(t, tc.backend.HostKrb5CCNamePath)
			}

			var krb5CCName string
			if tc.objectClass == ad.UserObject {
				switch tc.userKrb5CCBaseName {
				case "":
					tc.userKrb5CCBaseName = "kbr5cc_adsys_tests_bob"
				case "-":
					tc.userKrb5CCBaseName = ""
				}
				krb5CCName = tc.userKrb5CCBaseName
				// only create original cc file when requested
				if tc.userKrb5CCBaseName != "" && !strings.HasSuffix(tc.userKrb5CCBaseName, "dont-exist") {
					krb5CCName = setKrb5CC(t, tc.userKrb5CCBaseName)
				}
			}

			cachedir, rundir := t.TempDir(), t.TempDir()
			adc, err := ad.New(context.Background(), bus, tc.backend, hostname,
				ad.WithCacheDir(cachedir), ad.WithRunDir(rundir), ad.WithoutKerberos(),
				ad.WithGPOListCmd(mockGPOListCmd(t, tc.gpoListArgs...)),
				ad.WithVersionID(tc.versionID))
			require.NoError(t, err, "Setup: cannot create ad object")

			if tc.turnKrb5CCCacheRO {
				testutils.MakeReadOnly(t, adc.Krb5CacheDir())
			}

			// prepare by copying downloadables if any
			for n, src := range tc.existing {
				testutils.Copy(t, src, filepath.Join(adc.SysvolCacheDir(), n))
			}

			entries, err := adc.GetPolicies(context.Background(), tc.objectName, tc.objectClass, krb5CCName)
			if tc.wantErr {
				require.Error(t, err, "GetPolicies should have errored out")
				return
			}
			require.NoError(t, err, "GetPolicies should return no error")

			// Compare GPOs
			require.Equal(t, tc.want.GPOs, entries.GPOs, "GetPolicies returns expected GPO entries in correct order")

			// Compare assets
			uncompressedAssets := t.TempDir()
			require.NoError(t, os.RemoveAll(uncompressedAssets), "Teardown: can’t remove uncompressed assets directory for saving assets")
			err = entries.SaveAssetsTo(context.Background(), ".", uncompressedAssets, -1, -1)
			if tc.wantAssetsEquals == "" {
				require.Error(t, err, "Teardown: policies should have no assets to uncompress")
				require.NoFileExists(t, filepath.Join(adc.SysvolCacheDir(), "assets.db"), "assets db cache should not exists")
			} else {
				require.NoError(t, err, "Teardown: SaveAssetsTo should deserialize successfully.")
				testutils.CompareTreesWithFiltering(t, uncompressedAssets, tc.wantAssetsEquals, false)
			}
		})
	}
}

func TestGetPoliciesOffline(t *testing.T) {
	t.Parallel()

	hostname, err := os.Hostname()
	require.NoError(t, err, "Setup: failed to get hostname")

	bus := testutils.NewDbusConn(t)

	tests := map[string]struct {
		domainToCache string
		backend       mock.Backend
		gpoListArgs   []string

		wantAssets bool
		wantErr    bool
	}{
		"Offline, get from cache, gpo only": {
			domainToCache: "gpoonly.com",
			backend: mock.Backend{
				Dom:    "gpoonly.com",
				Online: false,
			},
			gpoListArgs: nil,
		},
		"Offline, get from cache, with assets": {
			domainToCache: "assetsandgpo.com",
			backend: mock.Backend{
				Dom:    "assetsandgpo.com",
				Online: false,
			},
			gpoListArgs: nil,
			wantAssets:  true,
		},
		"Offline, ensure we fetch from cache and not fetch GPO list": {
			domainToCache: "gpoonly.com",
			backend: mock.Backend{
				Dom:    "gpoonly.com",
				Online: false,
			},
			gpoListArgs: []string{"-Exit2-"}, // this should not be used
		},
		"Offline, with assets": {
			domainToCache: "assetsandgpo.com",
			backend: mock.Backend{
				Dom:    "assetsandgpo.com",
				Online: false,
			},
			gpoListArgs: []string{"-Exit2-"}, // this should not be used
			wantAssets:  true,
		},

		"Error on SSSD reports online, but we are actually offline when fetching gpo list, even with a cache": {
			domainToCache: "assetsandgpo.com",
			backend: mock.Backend{
				Dom:    "assetsandgpo.com",
				Online: true,
			},
			gpoListArgs: []string{"-Exit2-"},
			wantErr:     true,
		},
		"Error offline with no cache": {
			domainToCache: "",
			backend: mock.Backend{
				Dom:    "gpoonly.com",
				Online: false,
			},
			wantErr: true,
		},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tc.backend.ServURL = "ldap://myserver." + tc.backend.Dom
			tc.backend.HostKrb5CCNamePath = filepath.Join(t.TempDir(), "host_ccache")
			testutils.CreatePath(t, tc.backend.HostKrb5CCNamePath)

			cachedir, rundir := t.TempDir(), t.TempDir()
			adc, err := ad.New(context.Background(), bus, tc.backend, hostname,
				ad.WithCacheDir(cachedir), ad.WithRunDir(rundir), ad.WithoutKerberos(),
				ad.WithGPOListCmd(mockGPOListCmd(t, tc.gpoListArgs...)))
			require.NoError(t, err, "Setup: cannot create ad object")

			objectName := fmt.Sprintf("useroffline@%s", strings.ToUpper(tc.backend.Dom))
			objectClass := ad.UserObject
			krb5CCName := setKrb5CC(t, objectName)

			var initialPolicies policies.Policies

			if tc.domainToCache != "" {
				objectNameForCache := fmt.Sprintf("useroffline@%s", strings.ToUpper(tc.domainToCache))
				krb5CCNameForCache := setKrb5CC(t, objectNameForCache)

				cachedir, rundir := t.TempDir(), t.TempDir()
				adcForCache, err := ad.New(context.Background(), bus,
					mock.Backend{
						Dom:                tc.domainToCache,
						Online:             true,
						HostKrb5CCNamePath: tc.backend.HostKrb5CCNamePath,
					}, hostname,
					ad.WithCacheDir(cachedir), ad.WithRunDir(rundir), ad.WithoutKerberos(),
					ad.WithGPOListCmd(mockGPOListCmd(t, tc.domainToCache, fmt.Sprintf("useroffline:standard::%s:standard", hostname))))
				require.NoError(t, err, "Setup: cannot create ad object")

				initialPolicies, err = adcForCache.GetPolicies(context.Background(), objectNameForCache, objectClass, krb5CCNameForCache)
				require.NoError(t, err, "Setup: caching with getPolicies failed")

				// Save it and copy to finale destination
				err = initialPolicies.Save(filepath.Join(adc.PoliciesCacheDir(), objectName))
				require.NoError(t, err, "Setup: cannot create policy cache file for finale user")
			}

			entries, err := adc.GetPolicies(context.Background(), objectName, objectClass, krb5CCName)
			if tc.wantErr {
				require.NotNil(t, err, "GetPolicies should have errored out")
				return
			}
			require.NoError(t, err, "GetPolicies should return no error")

			// Ensure we only have one policy
			require.NotEqual(t, 0, len(entries.GPOs), "GetPolicies should return at least one GPO list when not failing")

			assertEqualPolicies(t, initialPolicies, entries, tc.wantAssets)
		})
	}
}

func TestGetPoliciesWorkflows(t *testing.T) {
	t.Parallel() // libsmbclient overrides SIGCHILD, but we have one global lock

	bus := testutils.NewDbusConn(t)

	hostname, err := os.Hostname()
	require.NoError(t, err, "Setup: failed to get hostname")

	gpoListArgs := []string{"assetsandgpo.com", fmt.Sprintf("bob:standard::sponge:standard::%s:standard", hostname)}

	tests := map[string]struct {
		objectName1         string
		objectName2         string
		userKrb5CCBaseName1 string
		userKrb5CCBaseName2 string
		restart             bool

		wantErr bool
	}{
		"Second call is a refresh (without Krb5CCName specified)": {
			objectName1:         "bob@ASSETSANDGPO.COM",
			objectName2:         "bob@ASSETSANDGPO.COM",
			userKrb5CCBaseName1: "bob",
			userKrb5CCBaseName2: "EMPTY",
		},
		"Second call after service restarted": {
			restart:             true,
			objectName1:         "bob@ASSETSANDGPO.COM",
			objectName2:         "bob@ASSETSANDGPO.COM",
			userKrb5CCBaseName1: "bob",
			userKrb5CCBaseName2: "", // We did’t RENEW the ticket
		},
		"Second call with different user": {
			objectName1:         "bob@ASSETSANDGPO.COM",
			objectName2:         "sponge@ASSETSANDGPO.COM",
			userKrb5CCBaseName1: "bob",
			userKrb5CCBaseName2: "sponge",
		},
		"Second call after a relogin": {
			objectName1:         "bob@ASSETSANDGPO.COM",
			objectName2:         "bob@ASSETSANDGPO.COM",
			userKrb5CCBaseName1: "bob",
			userKrb5CCBaseName2: "bobNew",
		},

		// Machine for assets cases
		"Second machine call is a refresh (without Krb5CCName specified)": {
			objectName1:         hostname,
			objectName2:         hostname,
			userKrb5CCBaseName1: hostname,
			userKrb5CCBaseName2: "EMPTY",
		},
		"Second machine call after service restarted": {
			restart:             true,
			objectName1:         hostname,
			objectName2:         hostname,
			userKrb5CCBaseName1: hostname,
			userKrb5CCBaseName2: "", // We did’t RENEW the ticket
		},
		"Second machine call after a restart": {
			objectName1:         hostname,
			objectName2:         hostname,
			userKrb5CCBaseName1: hostname,
			userKrb5CCBaseName2: "otherNew",
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel() // libsmbclient overrides SIGCHILD, but we have one global lock

			objectClass := ad.UserObject
			krb5CCName := setKrb5CC(t, tc.userKrb5CCBaseName1)

			if tc.objectName1 == hostname {
				objectClass = ad.ComputerObject
			}

			cachedir, rundir := t.TempDir(), t.TempDir()

			backend := mock.Backend{
				Dom:                "assetsandgpo.com",
				ServURL:            "ldap://UNUSED:1636/",
				HostKrb5CCNamePath: filepath.Join(t.TempDir(), "host_ccache"),
				Online:             true,
			}
			testutils.CreatePath(t, backend.HostKrb5CCNamePath)

			adc, err := ad.New(context.Background(), bus, backend, hostname,
				ad.WithCacheDir(cachedir), ad.WithRunDir(rundir), ad.WithoutKerberos(),
				ad.WithGPOListCmd(mockGPOListCmd(t, gpoListArgs...)))
			require.NoError(t, err, "Setup: cannot create ad object")

			// First call
			entries, err := adc.GetPolicies(context.Background(), tc.objectName1, objectClass, krb5CCName)
			require.NoError(t, err, "GetPolicies should return no error")

			wantPolicyDir := filepath.Join("testdata", "sysvolcache", strings.ToLower(tc.objectName1))
			if tc.objectName1 == hostname {
				wantPolicyDir = filepath.Join("testdata", "sysvolcache", "machine")
			}
			want, err := policies.NewFromCache(context.Background(), wantPolicyDir)
			require.NoError(t, err, "Setup: can't load wanted policies")
			assertEqualPolicies(t, want, entries, tc.objectName1 == hostname)

			// Recreate the ticket if needed or reset it to empty for refresh
			if tc.userKrb5CCBaseName2 != "" {
				if tc.userKrb5CCBaseName2 == "EMPTY" {
					krb5CCName = ""
				} else {
					krb5CCName = setKrb5CC(t, tc.userKrb5CCBaseName2)
				}
			}

			// Restart: recreate ad object
			if tc.restart {
				adc, err = ad.New(context.Background(), bus, backend, hostname,
					ad.WithCacheDir(cachedir), ad.WithRunDir(rundir), ad.WithoutKerberos(),
					ad.WithGPOListCmd(mockGPOListCmd(t, gpoListArgs...)))
				require.NoError(t, err, "Cannot create second ad object")
			}

			// Second call
			entries, err = adc.GetPolicies(context.Background(), tc.objectName2, objectClass, krb5CCName)
			require.NoError(t, err, "GetPolicies should return no error")

			wantPolicyDir = filepath.Join("testdata", "sysvolcache", strings.ToLower(tc.objectName2))
			if tc.objectName2 == hostname {
				wantPolicyDir = filepath.Join("testdata", "sysvolcache", "machine")
			}
			want, err = policies.NewFromCache(context.Background(), wantPolicyDir)
			require.NoError(t, err, "Setup: can't load wanted policies")
			assertEqualPolicies(t, want, entries, tc.objectName2 == hostname)
		})
	}
}

func TestGetPoliciesConcurrently(t *testing.T) {
	t.Parallel() // libsmbclient overrides SIGCHILD, but we have one global lock

	bus := testutils.NewDbusConn(t)

	hostname, err := os.Hostname()
	require.NoError(t, err, "Setup: failed to get hostname")

	tests := map[string]struct {
		objectName1  string
		objectName2  string
		objectClass1 ad.ObjectClass
		objectClass2 ad.ObjectClass
		gpo1         string
		gpo2         string

		wantErr bool
	}{
		"Same user, same GPO": {
			objectName1:  "bob@ASSETSANDGPO.COM",
			objectName2:  "bob@ASSETSANDGPO.COM",
			objectClass1: ad.UserObject,
			objectClass2: ad.UserObject,
			gpo1:         "standard",
			gpo2:         "standard",
		},
		// We can’t run this test currently as the mock will always return the same value for bob (both gpos):
		// both calls are identical.
		/*"Same user, different GPOs": {
		objectName1: "bob@ASSETSANDGPO.COM",
		objectName2: "bob@ASSETSANDGPO.COM",
		objectClass1: ad.UserObject,
		objectClass2: ad.UserObject,
		gpo1:        "standard",
		gpo2:        "one-value",
		},*/
		"Different users, same GPO": {
			objectName1:  "bob@ASSETSANDGPO.COM",
			objectName2:  "sponge@ASSETSANDGPO.COM",
			objectClass1: ad.UserObject,
			objectClass2: ad.UserObject,
			gpo1:         "standard",
			gpo2:         "standard",
		},
		"Different users, different GPO": {
			objectName1:  "bob@ASSETSANDGPO.COM",
			objectName2:  "carol@ASSETSANDGPO.COM",
			objectClass1: ad.UserObject,
			objectClass2: ad.UserObject,
			gpo1:         "standard",
			gpo2:         "one-value",
		},

		// Machines and assets cases
		"One machine, one user": {
			objectName1:  "bob@ASSETSANDGPO.COM",
			objectName2:  hostname,
			objectClass1: ad.UserObject,
			objectClass2: ad.ComputerObject,
			gpo1:         "standard",
			gpo2:         "standard",
		},
		"Machine requested twice at the same time": {
			objectName1:  hostname,
			objectName2:  hostname,
			objectClass1: ad.ComputerObject,
			objectClass2: ad.ComputerObject,
			gpo1:         "standard",
			gpo2:         "standard",
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel() // libsmbclient overrides SIGCHILD, but we have one global lock

			krb5CCName1 := setKrb5CC(t, tc.objectName1)
			krb5CCName2 := setKrb5CC(t, tc.objectName2)

			cachedir, rundir := t.TempDir(), t.TempDir()

			backend := mock.Backend{
				Dom:                "assetsandgpo.com",
				ServURL:            "ldap://UNUSED:1636/",
				HostKrb5CCNamePath: filepath.Join(t.TempDir(), "host_ccache"),
				Online:             true,
			}
			testutils.CreatePath(t, backend.HostKrb5CCNamePath)

			mockObjectName1 := tc.objectName1
			if i := strings.LastIndex(mockObjectName1, "@"); i > 0 {
				mockObjectName1 = mockObjectName1[:i]
			}
			mockObjectName2 := tc.objectName2
			if i := strings.LastIndex(mockObjectName2, "@"); i > 0 {
				mockObjectName2 = mockObjectName2[:i]
			}

			gpoListMeta := fmt.Sprintf("%s:%s::%s:%s", mockObjectName1, tc.gpo1, mockObjectName2, tc.gpo2)
			if mockObjectName1 == mockObjectName2 {
				gpoListMeta = fmt.Sprintf("%s:%s", mockObjectName1, tc.gpo1)
			}
			adc, err := ad.New(context.Background(), bus, backend, hostname,
				ad.WithCacheDir(cachedir), ad.WithRunDir(rundir), ad.WithoutKerberos(),
				ad.WithGPOListCmd(mockGPOListCmd(t, "assetsandgpo.com", gpoListMeta)))
			require.NoError(t, err, "Setup: cannot create ad object")

			wg := sync.WaitGroup{}
			wg.Add(2)
			go func() {
				defer wg.Done()
				got1, err := adc.GetPolicies(context.Background(), tc.objectName1, tc.objectClass1, krb5CCName1)
				require.NoError(t, err, "GetPolicies should return no error")

				wantPolicyDir := filepath.Join("testdata", "sysvolcache", strings.ToLower(tc.objectName1))
				if tc.objectName1 == hostname {
					wantPolicyDir = filepath.Join("testdata", "sysvolcache", "machine")
				}
				want, err := policies.NewFromCache(context.Background(), wantPolicyDir)
				require.NoError(t, err, "Setup: can't load wanted policies")
				assertEqualPolicies(t, want, got1, tc.objectName1 == hostname)
			}()
			go func() {
				defer wg.Done()
				got2, err := adc.GetPolicies(context.Background(), tc.objectName2, tc.objectClass2, krb5CCName2)
				require.NoError(t, err, "GetPolicies should return no error")

				wantPolicyDir := filepath.Join("testdata", "sysvolcache", strings.ToLower(tc.objectName2))
				if tc.objectName2 == hostname {
					wantPolicyDir = filepath.Join("testdata", "sysvolcache", "machine")
				}
				want, err := policies.NewFromCache(context.Background(), wantPolicyDir)
				require.NoError(t, err, "Setup: can't load wanted policies")
				assertEqualPolicies(t, want, got2, tc.objectName2 == hostname)
			}()
			wg.Wait()
		})
	}
}

func TestListUsersFromCache(t *testing.T) {
	t.Parallel()

	bus := testutils.NewDbusConn(t)
	hostname, err := os.Hostname()
	require.NoError(t, err, "Setup: failed to get hostname for tests.")

	tests := map[string]struct {
		ccCachesToCreate []string
		noCCacheDir      bool

		want    []string
		wantErr bool
	}{
		"One user": {
			ccCachesToCreate: []string{"bob@GPOONLY.COM"},
			want:             []string{"bob@GPOONLY.COM"},
		},
		"Two users": {
			ccCachesToCreate: []string{"bob@GPOONLY.COM", "sponge@OTHERDOMAIN.BIZ"},
			want:             []string{"bob@GPOONLY.COM", "sponge@OTHERDOMAIN.BIZ"},
		},
		"None": {
			ccCachesToCreate: []string{},
			want:             nil,
		},
		"Machines are ignored": {
			ccCachesToCreate: []string{"bob@GPOONLY.COM", "sponge@OTHERDOMAIN.BIZ", "myMachine"},
			want:             []string{"bob@GPOONLY.COM", "sponge@OTHERDOMAIN.BIZ"},
		},
		"Machine Only": {
			ccCachesToCreate: []string{"myMachine"},
			want:             nil,
		},

		// Error cases
		"Error on Krb5 directory not existing": {
			noCCacheDir: true,
			wantErr:     true,
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cachedir, rundir := t.TempDir(), t.TempDir()

			// populate rundir with users and machines
			krb5CacheDir := filepath.Join(rundir, "krb5cc")
			if len(tc.ccCachesToCreate) > 0 {
				require.NoError(t, os.MkdirAll(krb5CacheDir, 0700), "Setup: can’t create krb5cc cache dir")
				for _, f := range tc.ccCachesToCreate {
					require.NoError(t, os.Symlink("nonexistent", filepath.Join(krb5CacheDir, f)),
						"Setup: symlink creation of krb5cc failed")
				}
			}

			adc, err := ad.New(context.Background(), bus, mock.Backend{Dom: "gpoonly.com", ServURL: "ldap://myserver.gpoonly.com"}, hostname,
				ad.WithCacheDir(cachedir), ad.WithRunDir(rundir))
			require.NoError(t, err, "Setup: New should return no error")

			if tc.noCCacheDir {
				require.NoError(t, os.RemoveAll(krb5CacheDir), "Setup: can’t remove krb5 cache directory")
			}

			got, err := adc.ListActiveUsers(context.Background())
			if tc.wantErr {
				require.Error(t, err, "ListUsersFromCache should return an error and didn't")
				return
			}
			require.NoError(t, err, "ListUsersFromCache should return no error")

			sort.Strings(tc.want)
			sort.Strings(got)
			assert.Equal(t, tc.want, got, "ListUsersFromCache should return the list of expected users")
		})
	}
}

func TestGetInfo(t *testing.T) {
	t.Parallel()

	bus := testutils.NewDbusConn(t)
	hostname, err := os.Hostname()
	require.NoError(t, err, "Setup: failed to get hostname for tests.")

	tests := map[string]struct {
		online       bool
		errIsOnline  bool
		ErrServerURL error
	}{
		"Info reported from backend, online":  {online: true},
		"Info reported from backend, offline": {online: false},

		"Report unknown state if IsOnline calls fail": {errIsOnline: true},
		// This error is skipped by New(), but not by GetInfo
		"Report unknown state if ServerURL calls fail": {ErrServerURL: backends.ErrNoActiveServer},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			adc, err := ad.New(context.Background(), bus,
				mock.Backend{
					Dom: "example.com", ServURL: "ldap://myserver.example.com",
					Online:      tc.online,
					ErrIsOnline: tc.errIsOnline, ErrServerURL: tc.ErrServerURL},
				hostname,
				ad.WithCacheDir(t.TempDir()), ad.WithRunDir(t.TempDir()))
			require.NoError(t, err, "Setup: New should return no error")

			msg := adc.GetInfo(context.Background())
			testutils.LoadWithUpdateFromGolden(t, msg)
		})
	}
}

func TestNormalizeTargetName(t *testing.T) {
	t.Parallel()

	hostname, err := os.Hostname()
	require.NoError(t, err, "Setup: failed to get hostname")

	bus := testutils.NewDbusConn(t)

	tests := map[string]struct {
		target              string
		objectClass         ad.ObjectClass
		defaultDomainSuffix string

		want    string
		wantErr bool
	}{
		"One valid user":                          {target: "user@gpoonly.com", want: "user@gpoonly.com"},
		"One valid user with mixed case":          {target: "User@GPOONLY.COM", want: "user@gpoonly.com"},
		`One valid user with domain\user`:         {target: `gpoonly.com\user`, want: "user@gpoonly.com"},
		"One user without explicit domain suffix": {target: "user", defaultDomainSuffix: "gpoonly.com", want: "user@gpoonly.com"},

		// User match computer names
		"User name matching computer, setting as user": {target: hostname, objectClass: ad.UserObject, defaultDomainSuffix: "gpoonly.com",
			want: hostname + "@gpoonly.com"},
		"User name fqdn matching computer":  {target: hostname + "@gpoonly.com", want: hostname + "@gpoonly.com"},
		"Computer name without objectClass": {target: hostname, want: hostname},

		// Computer cases
		"Computer is left as such":              {target: "computername", objectClass: ad.ComputerObject, want: "computername"},
		"Computer in uppercase is left as such": {target: "COMPUTERNAME", objectClass: ad.ComputerObject, want: "computername"},
		"Computer with @ is left as such":       {target: "computername@gpoonly.com", objectClass: ad.ComputerObject, want: "computername@gpoonly"},

		// Error cases
		`Error on multiple \ in name`:                        {target: `gpoonly.com\user\something`, wantErr: true},
		`Error on no default domain suffix and no fqdn user`: {target: `user`, wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			adc, err := ad.New(context.Background(), bus,
				mock.Backend{Dom: tc.defaultDomainSuffix, ServURL: "ldap://myserver.gpoonly.com"}, // Dom is the default domain suffix in the mock
				hostname,
				ad.WithCacheDir(t.TempDir()), ad.WithRunDir(t.TempDir()))
			require.NoError(t, err, "Setup: New should return no error")

			got, err := adc.NormalizeTargetName(context.Background(), tc.target, tc.objectClass)
			if tc.wantErr {
				require.Error(t, err, "NormalizeTargetName should return an error and didn't")
				return
			}
			require.NoError(t, err, "NormalizeTargetName should return no error")

			assert.Equal(t, tc.want, got, "NormalizeTargetName should return the expected user")
		})
	}
}

func TestMockGPOList(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	defer os.Exit(0)

	krb5File := os.Getenv("KRB5CCNAME")
	if _, err := os.Lstat(krb5File); errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "Expecting symlink %s to exists", krb5File)
		os.Exit(1)
	}
	if _, err := os.Stat(krb5File); errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "Expecting file pointed by %s to exists", krb5File)
		os.Exit(1)
	}

	args := os.Args
	for len(args) > 0 {
		if args[0] != "--" {
			args = args[1:]
			continue
		}
		args = args[1:]
		break
	}

	// simulating offline mode with Exit 2
	if args[0] == "-Exit2-" {
		fmt.Fprint(os.Stderr, "Error during gpo list requested with exit 2")
		os.Exit(2)
	}

	// Get Domain
	domain := args[0]

	// as in gpolist, we split on the @ if any
	objectName := args[len(args)-1]
	objectName = strings.Split(objectName, "@")[0]

	var gpos []string

	// Arg 0 is the list of GPOs to return, in the form: "user1:GPO1::user2:GPO2::user1:GPO3"
	for _, gpoItem := range strings.Split(args[1], "::") {
		e := strings.SplitN(gpoItem, ":", 2)
		if e[0] != objectName {
			continue
		}
		gpos = append(gpos, e[1])
	}

	for _, gpo := range gpos {
		fmt.Fprintf(os.Stdout, "%s-name\tsmb://localhost:%d/SYSVOL/%s/Policies/%s\n", gpo, ad.SmbPort, domain, gpo)
	}
}

func mockGPOListCmd(t *testing.T, args ...string) []string {
	t.Helper()

	cmdArgs := []string{"env", "GO_WANT_HELPER_PROCESS=1", os.Args[0], "-test.run=TestMockGPOList", "--"}
	cmdArgs = append(cmdArgs, args...)
	return cmdArgs
}

// setKrb5CC create a temporary file for a KRB5 ticket.
// It will be automatically purged when the test ends.
func setKrb5CC(t *testing.T, ccRootName string) string {
	t.Helper()

	f, err := os.CreateTemp("", fmt.Sprintf("kbr5cc_adsys_tests_%s_*", ccRootName))
	require.NoError(t, err, "Setup: failed to create temporary krb5 cache file")
	defer f.Close()
	krb5CCName := f.Name()
	_, err = f.Write([]byte("KRB5 Ticket file content"))
	require.NoError(t, err, "Setup: failed to write to temporary krb5 cache file")
	t.Cleanup(func() { os.Remove(krb5CCName) })
	return krb5CCName
}

// assertEqualPolicies compares expected and actual policies by deserializing them.
func assertEqualPolicies(t *testing.T, expected policies.Policies, got policies.Policies, checkAssets bool) {
	t.Helper()

	require.Equal(t, expected.GPOs, got.GPOs, "Policies should have the same GPOs")

	if !checkAssets {
		return
	}

	expectedAssetsDir, gotAssetsDir := t.TempDir(), t.TempDir()
	// the directories should not exists to deserialize the assets
	require.NoError(t, os.RemoveAll(expectedAssetsDir), "Teardown: can’t remove expected assets directory created for comparison")
	require.NoError(t, os.RemoveAll(gotAssetsDir), "Teardown: can’t remove new assets directory created for comparison")

	require.NoError(t, expected.SaveAssetsTo(context.Background(), ".", expectedAssetsDir, -1, -1), "Teardown: Saving expected policies failed.")
	require.NoError(t, got.SaveAssetsTo(context.Background(), ".", gotAssetsDir, -1, -1), "Teardown: Saving got policies failed.")

	testutils.CompareTreesWithFiltering(t, gotAssetsDir, expectedAssetsDir, false)
}

func standardUserGPO(id string) policies.GPO {
	return policies.GPO{ID: id, Name: id + "-name", Rules: map[string][]entry.Entry{
		"dconf": {
			{Key: "A", Value: "standardA"},
			{Key: "B", Value: "standardB"},
			{Key: "C", Value: "standardC"},
		}}}
}

func standardComputerGPO(id string) policies.GPO {
	return policies.GPO{ID: id, Name: id + "-name", Rules: map[string][]entry.Entry{
		"dconf": {
			{Key: "A", Value: "standardA"},
			{Key: "D", Value: "standardD"},
			{Key: "E", Value: "standardE"},
		}}}
}

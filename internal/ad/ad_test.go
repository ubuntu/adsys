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
	"github.com/ubuntu/adsys/internal/policies"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestNew(t *testing.T) {
	t.Parallel()

	bus := testutils.NewDbusConn(t)

	tests := map[string]struct {
		cacheDirRO      bool
		runDirRO        bool
		staticServerURL string
		wantServerURL   string

		wantErr bool
	}{
		"create one AD object will create all necessary cache dirs": {staticServerURL: "ldap://my-static-server.example.com:1636/", wantServerURL: "ldap://my-static-server.example.com:1636/"},
		"static server is always prefixed with ldap":                {staticServerURL: "my-static-server.example.com:1636/", wantServerURL: "ldap://my-static-server.example.com:1636/"},
		"not provided static server URL is blank":                   {staticServerURL: "", wantServerURL: ""},

		"failed to create KRB5 cache directory": {runDirRO: true, wantErr: true},
		"failed to create GPO cache directory":  {cacheDirRO: true, wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runDir, cacheDir := t.TempDir(), t.TempDir()

			if tc.runDirRO {
				require.NoError(t, os.Chmod(runDir, 0400), "Setup: can’t set run directory to Read only")
			}
			if tc.cacheDirRO {
				require.NoError(t, os.Chmod(cacheDir, 0400), "Setup: can’t set cache directory to Read only")
			}

			adc, err := ad.New(context.Background(), tc.staticServerURL, "localdomain", bus,
				ad.WithRunDir(runDir),
				ad.WithCacheDir(cacheDir),
				ad.WithSSSCacheDir("testdata/sss/db"))
			if tc.wantErr {
				require.NotNil(t, err, "AD creation should have failed")
				return
			}

			require.NoError(t, err, "AD creation should be successful failed")

			// Ensure cache directories exists
			assert.DirExists(t, adc.Krb5CacheDir(), "Kerberos ticket cache directory doesn't exist")
			assert.DirExists(t, adc.GpoCacheDir(), "GPO cache directory doesn't exist")

			adServerURL, offline := adc.GetStatus()
			assert.Equal(t, tc.wantServerURL, adServerURL, "AD server URl matches static configuration")
			assert.False(t, offline, "Considered online until first update")
		})
	}
}

func TestGetPolicies(t *testing.T) {
	t.Parallel() // libsmbclient overrides SIGCHILD, but we have one global lock

	hostname, err := os.Hostname()
	require.NoError(t, err, "Setup: failed to get hostname")

	bus := testutils.NewDbusConn(t)

	standardGPO := policies.GPO{ID: "standard", Name: "standard-name", Rules: map[string][]entry.Entry{
		"dconf": {
			{Key: "A", Value: "standardA"},
			{Key: "B", Value: "standardB"},
			{Key: "C", Value: "standardC"},
		}}}

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
		gpoListArgs        string
		objectName         string
		objectClass        ad.ObjectClass
		userKrb5CCBaseName string
		versionID          string
		staticServerURL    string
		domain             string

		dontCreateOriginalKrb5CCName bool
		turnKrb5CCRO                 bool

		want          policies.Policies
		wantServerURL string
		wantErr       bool
	}{
		"Standard policy, user object": {
			gpoListArgs:        "standard",
			objectName:         "bob@EXAMPLE.COM",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			want:               policies.Policies{GPOs: []policies.GPO{standardGPO}},
			wantServerURL:      "ldap://myserver.example.com",
		},
		"Standard policy, computer object": {
			gpoListArgs:        "standard",
			objectName:         hostname,
			objectClass:        ad.ComputerObject,
			userKrb5CCBaseName: "", // ignored for machine
			want: policies.Policies{GPOs: []policies.GPO{
				{ID: "standard", Name: "standard-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "A", Value: "standardA"},
						{Key: "D", Value: "standardD"},
						{Key: "E", Value: "standardE"},
					}}}},
			},
			wantServerURL: "ldap://myserver.example.com",
		},
		"User only policy, user object": {
			gpoListArgs:        "user-only",
			objectName:         "bob@EXAMPLE.COM",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			want: policies.Policies{GPOs: []policies.GPO{
				{ID: "user-only", Name: "user-only-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "A", Value: "userOnlyA"},
						{Key: "B", Value: "userOnlyB"},
					}}}},
			},
			wantServerURL: "ldap://myserver.example.com",
		},
		"User only policy, computer object, policy is empty": {
			gpoListArgs:        "user-only",
			objectName:         hostname,
			objectClass:        ad.ComputerObject,
			userKrb5CCBaseName: "",
			want:               policies.Policies{GPOs: []policies.GPO{{ID: "user-only", Name: "user-only-name", Rules: make(map[string][]entry.Entry)}}},
			wantServerURL:      "ldap://myserver.example.com",
		},
		"Computer only policy, user object, policy is empty": {
			gpoListArgs:        "machine-only",
			objectName:         "bob@EXAMPLE.COM",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			want:               policies.Policies{GPOs: []policies.GPO{{ID: "machine-only", Name: "machine-only-name", Rules: make(map[string][]entry.Entry)}}},
			wantServerURL:      "ldap://myserver.example.com",
		},
		"Computer ignored CCBaseName": {
			gpoListArgs:        "standard",
			objectName:         hostname,
			objectClass:        ad.ComputerObject,
			userKrb5CCBaseName: "somethingtotallyarbitrary", // ignored for machine
			want: policies.Policies{GPOs: []policies.GPO{
				{ID: "standard", Name: "standard-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "A", Value: "standardA"},
						{Key: "D", Value: "standardD"},
						{Key: "E", Value: "standardE"},
					}}}},
			},
			wantServerURL: "ldap://myserver.example.com",
		},

		// Multi releases cases
		"Enabled override": {
			versionID:          "21.04",
			gpoListArgs:        "multiple-releases-one-enabled",
			objectName:         "bob@EXAMPLE.COM",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			want: policies.Policies{GPOs: []policies.GPO{{ID: "multiple-releases-one-enabled", Name: "multiple-releases-one-enabled-name", Rules: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "21.04Value"},
				}}}},
			},
			wantServerURL: "ldap://myserver.example.com",
		},
		"Disabled override": {
			versionID:          "21.04",
			gpoListArgs:        "multiple-releases-one-disabled",
			objectName:         "bob@EXAMPLE.COM",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			want: policies.Policies{GPOs: []policies.GPO{{ID: "multiple-releases-one-disabled", Name: "multiple-releases-one-disabled-name", Rules: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "AllValue"},
				}}}},
			},
			wantServerURL: "ldap://myserver.example.com",
		},
		"Enabled override for matching release, other releases override ignored": {
			versionID:          "21.04",
			gpoListArgs:        "multiple-releases",
			objectName:         "bob@EXAMPLE.COM",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			want: policies.Policies{GPOs: []policies.GPO{{ID: "multiple-releases", Name: "multiple-releases-name", Rules: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "21.04Value"},
				}}}},
			},
			wantServerURL: "ldap://myserver.example.com",
		},
		"Disable override for matching release, other releases override ignored": {
			versionID:          "20.04",
			gpoListArgs:        "multiple-releases",
			objectName:         "bob@EXAMPLE.COM",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			want: policies.Policies{GPOs: []policies.GPO{{ID: "multiple-releases", Name: "multiple-releases-name", Rules: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "AllValue"},
				}}}},
			},
			wantServerURL: "ldap://myserver.example.com",
		},
		"No override for this release, takes default value": {
			versionID:          "not in pol file",
			gpoListArgs:        "multiple-releases",
			objectName:         "bob@EXAMPLE.COM",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			want: policies.Policies{GPOs: []policies.GPO{{ID: "multiple-releases", Name: "multiple-releases-name", Rules: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "AllValue"},
				}}}},
			},
			wantServerURL: "ldap://myserver.example.com",
		},

		// No override option for this release

		// Multi domain cases
		"Multiple domains, same GPO": {
			gpoListArgs:        "multiple-domains",
			objectName:         "bob@EXAMPLE.COM",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
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
			wantServerURL: "ldap://myserver.example.com",
		},
		"Same key in different domains are kept separated": {
			gpoListArgs:        "other-domain_one-value",
			objectName:         "bob@EXAMPLE.COM",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
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
			wantServerURL: "ldap://myserver.example.com",
		},

		"Two policies, with overrides": {
			gpoListArgs:        "one-value_standard",
			objectName:         "bob@EXAMPLE.COM",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
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
			wantServerURL: "ldap://myserver.example.com",
		},
		"Two policies, with reversed overrides": {
			gpoListArgs:        "standard_one-value",
			objectName:         "bob@EXAMPLE.COM",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			want: policies.Policies{GPOs: []policies.GPO{
				standardGPO,
				{ID: "one-value", Name: "one-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						// this value will be overridden with the higher one
						{Key: "C", Value: "oneValueC"},
					}}}},
			},
			wantServerURL: "ldap://myserver.example.com",
		},
		"Two policies, no overrides": {
			gpoListArgs:        "one-value_user-only",
			objectName:         "bob@EXAMPLE.COM",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
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
			wantServerURL: "ldap://myserver.example.com",
		},
		"Two policies, no overrides, reversed": {
			gpoListArgs:        "user-only_one-value",
			objectName:         "bob@EXAMPLE.COM",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
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
			wantServerURL: "ldap://myserver.example.com",
		},
		"Two policies, no overrides, one is not the same object type, machine ones are empty when parsing user": {
			gpoListArgs:        "machine-only_standard",
			objectName:         "bob@EXAMPLE.COM",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			want: policies.Policies{GPOs: []policies.GPO{{ID: "machine-only", Name: "machine-only-name", Rules: make(map[string][]entry.Entry)},
				standardGPO}},
			wantServerURL: "ldap://myserver.example.com",
		},

		"Disabled value overrides non disabled one": {
			gpoListArgs:        "disabled-value_standard",
			objectName:         "bob@EXAMPLE.COM",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			want: policies.Policies{GPOs: []policies.GPO{
				{ID: "disabled-value", Name: "disabled-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "C", Value: "", Disabled: true},
					}}},
				standardGPO,
			}},
			wantServerURL: "ldap://myserver.example.com",
		},
		"Disabled value is overridden": {
			gpoListArgs:        "standard_disabled-value",
			objectName:         "bob@EXAMPLE.COM",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			want: policies.Policies{GPOs: []policies.GPO{
				standardGPO,
				{ID: "disabled-value", Name: "disabled-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "C", Value: "", Disabled: true},
					}}},
			}},
			wantServerURL: "ldap://myserver.example.com",
		},

		"More policies, with multiple overrides": {
			gpoListArgs:        "user-only_one-value_standard",
			objectName:         "bob@EXAMPLE.COM",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
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
				standardGPO,
			}},
			wantServerURL: "ldap://myserver.example.com",
		},
		"Object domain is stripped": {
			gpoListArgs:        "standard",
			objectName:         "bob@example.com",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			want:               policies.Policies{GPOs: []policies.GPO{standardGPO}},
			wantServerURL:      "ldap://myserver.example.com",
		},
		"Filter non Ubuntu keys": {
			gpoListArgs:        "filtered",
			objectName:         "bob@EXAMPLE.COM",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			want: policies.Policies{GPOs: []policies.GPO{
				{ID: "filtered", Name: "filtered-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "A", Value: "standardA"},
						{Key: "C", Value: "standardC"},
					}}},
			}},
			wantServerURL: "ldap://myserver.example.com",
		},

		"No discovery for statistically configured domain controller": {
			gpoListArgs:        "standard",
			objectName:         "bob@EXAMPLE.COM",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			staticServerURL:    "ldap://myotherserver.example.com",
			want:               policies.Policies{GPOs: []policies.GPO{standardGPO}},
			wantServerURL:      "ldap://myotherserver.example.com",
		},

		// Error cases
		"Machine doesn’t match": {
			gpoListArgs:        "standard",
			objectName:         "NotHostname",
			objectClass:        ad.ComputerObject,
			userKrb5CCBaseName: "",
			wantErr:            true,
		},
		"Without previous call, needs userKrb5CCBaseName": {
			gpoListArgs:        "standard",
			objectName:         "bob@EXAMPLE.COM",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "",
			wantErr:            true,
		},
		"Unexisting CC original file for user": {
			gpoListArgs:                  "standard",
			objectName:                   "bob@EXAMPLE.COM",
			objectClass:                  ad.UserObject,
			userKrb5CCBaseName:           "kbr5cc_adsys_tests_bob",
			dontCreateOriginalKrb5CCName: true,
			wantErr:                      true,
		},
		"Unexisting CC original file for machine": {
			gpoListArgs:                  "standard",
			objectName:                   hostname,
			objectClass:                  ad.ComputerObject,
			dontCreateOriginalKrb5CCName: true,
			wantErr:                      true,
		},
		"No Active Directory server returned by sssd fails without static configuration": {
			gpoListArgs:        "standard",
			objectName:         "bob@EXAMPLE.COM",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			domain:             "emptyserver",
			wantErr:            true,
		},
		"SSSD dbus (IsOnline) call failed": {
			gpoListArgs:        "standard",
			objectName:         "bob@EXAMPLE.COM",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			domain:             "unexistingdbusobjectdomain",
			wantErr:            true,
		},
		// We can’t return an error from the dbus server objects without having a deadlock from godbus
		// This affects testing only.
		/*"SSSD ActiveServer call failed": {
			gpoListArgs:        "standard",
			objectName:         "bob@EXAMPLE.COM",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			domain:             "sssdactiveservercallfail",
			wantErr:            true,
		},
		*/
		"Error on user without @ in name": {
			gpoListArgs:        "standard",
			objectName:         "bob",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			want:               policies.Policies{GPOs: []policies.GPO{standardGPO}},
			wantServerURL:      "ldap://myserver.example.com",
			wantErr:            true,
		},
		"Corrupted policy file": {
			gpoListArgs:        "corrupted-policy",
			objectName:         "bob@EXAMPLE.COM",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			wantErr:            true,
		},
		"Policy can’t be downloaded": {
			gpoListArgs:        "no-gpt-ini",
			objectName:         "bob@EXAMPLE.COM",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			wantErr:            true,
		},
		"Symlinks can’t be created": {
			gpoListArgs:        "standard",
			objectName:         "bob@EXAMPLE.COM",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			turnKrb5CCRO:       true,
			wantErr:            true,
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel() // libsmbclient overrides SIGCHILD, but we have one global lock

			var krb5CCName, sssCacheDir string
			if tc.objectClass == ad.UserObject {
				krb5CCName = tc.userKrb5CCBaseName
				// only create original cc file when requested
				if !tc.dontCreateOriginalKrb5CCName && tc.userKrb5CCBaseName != "" {
					krb5CCName = setKrb5CC(t, tc.userKrb5CCBaseName)
				}
			} else if tc.objectClass == ad.ComputerObject {
				sssCacheDir = "testdata/sss/db"
				if tc.dontCreateOriginalKrb5CCName {
					sssCacheDir = "nonexisting/sss/db"
				}
			}

			if tc.domain == "" {
				tc.domain = "example.com"
			}

			cachedir, rundir := t.TempDir(), t.TempDir()
			adc, err := ad.New(context.Background(), tc.staticServerURL, tc.domain, bus,
				ad.WithCacheDir(cachedir), ad.WithRunDir(rundir), ad.WithoutKerberos(),
				ad.WithSSSCacheDir(sssCacheDir),
				ad.WithGPOListCmd(mockGPOListCmd(t, tc.gpoListArgs)),
				ad.WithVersionID(tc.versionID))
			require.NoError(t, err, "Setup: cannot create ad object")

			if tc.turnKrb5CCRO {
				require.NoError(t, os.Chmod(adc.Krb5CacheDir(), 0400), "Setup: can’t set krb5 origin cache directory read only")
				defer func() {
					if err := os.Chmod(adc.Krb5CacheDir(), 0600); err != nil {
						t.Logf("Teardown: couldn’t restore permission on %s: %v", adc.Krb5CacheDir(), err)
					}
				}()
			}

			entries, err := adc.GetPolicies(context.Background(), tc.objectName, tc.objectClass, krb5CCName)
			if tc.wantErr {
				require.NotNil(t, err, "GetPolicies should have errored out")
				return
			}

			require.NoError(t, err, "GetPolicies should return no error")
			require.Equal(t, tc.want, entries, "GetPolicies returns expected gpo entries in correct order")
			serverURL, isOffline := adc.GetStatus()
			assert.False(t, isOffline, "We report that we are online")
			if tc.staticServerURL == "" {
				assert.Equal(t, tc.wantServerURL, serverURL, "Server URL has been fetched dynamically")
			}
		})
	}
}

func TestGetPoliciesOffline(t *testing.T) {
	t.Parallel()

	bus := testutils.NewDbusConn(t)

	pols := policies.Policies{
		GPOs: []policies.GPO{
			{ID: "user-only", Name: "user-only-name", Rules: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "userOnlyA"},
					{Key: "B", Value: "userOnlyB"},
				}}},
			{ID: "one-value", Name: "one-value-name", Rules: map[string][]entry.Entry{
				"dconf": {
					{Key: "C", Value: "oneValueC"},
				}}},
			{ID: "standard", Name: "standard-name", Rules: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
				}}}},
	}

	tests := map[string]struct {
		getFromCache bool
		domain       string
		gpoListArg   string

		want    policies.Policies
		wantErr bool
	}{
		"Offline, get from cache": {
			getFromCache: true,
			domain:       "offline",
			gpoListArg:   "standard",
			want:         pols,
		},
		"Offline, ensure we fetch from cache and not fetch GPO list": {
			getFromCache: true,
			domain:       "offline",
			gpoListArg:   "-Exit2-", // this should not be used
			want:         pols,
		},

		"Error on SSSD reports online, but we are actually offline when fetching gpo list, even with a cache": {
			getFromCache: true,
			domain:       "example.com",
			gpoListArg:   "-Exit2-",
			wantErr:      true,
		},
		"Error offline with no cache": {
			getFromCache: false,
			domain:       "offline",
			gpoListArg:   "standard",
			wantErr:      true,
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cachedir, rundir := t.TempDir(), t.TempDir()
			adc, err := ad.New(context.Background(), "", tc.domain, bus,
				ad.WithCacheDir(cachedir), ad.WithRunDir(rundir), ad.WithoutKerberos(),
				ad.WithGPOListCmd(mockGPOListCmd(t, tc.gpoListArg)))
			require.NoError(t, err, "Setup: cannot create ad object")

			objectName := "useroffline@EXAMPLE.COM"

			krb5CCName := setKrb5CC(t, objectName)

			if tc.getFromCache {
				err := tc.want.Save(filepath.Join(adc.PoliciesCacheDir(), objectName))
				require.NoError(t, err, "Setup: cannot create policy cache file for user")
			}

			entries, err := adc.GetPolicies(context.Background(), objectName, ad.UserObject, krb5CCName)
			if tc.wantErr {
				require.NotNil(t, err, "GetPolicies should have errored out")
				return
			}

			require.NoError(t, err, "GetPolicies should return no error")
			require.Equal(t, tc.want, entries, "GetPolicies returns expected gpo entries in correct order")
			serverURL, isOffline := adc.GetStatus()
			assert.True(t, isOffline, "We report that we are offline")
			assert.Empty(t, serverURL, "Server URL has not been fetched in offline mode")
		})
	}
}

func TestGetPoliciesWorkflows(t *testing.T) {
	t.Parallel() // libsmbclient overrides SIGCHILD, but we have one global lock

	bus := testutils.NewDbusConn(t)

	gpoListArgs := "standard"
	objectClass := ad.UserObject

	standardPolicies := policies.Policies{GPOs: []policies.GPO{{ID: "standard", Name: "standard-name", Rules: map[string][]entry.Entry{
		"dconf": {
			{Key: "A", Value: "standardA"},
			{Key: "B", Value: "standardB"},
			{Key: "C", Value: "standardC"},
		}}}}}

	tests := map[string]struct {
		objectName1         string
		objectName2         string
		userKrb5CCBaseName1 string
		userKrb5CCBaseName2 string
		restart             bool

		want    policies.Policies
		wantErr bool
	}{
		"Second call is a refresh (without Krb5CCName specified)": {
			objectName1:         "bob@EXAMPLE.COM",
			objectName2:         "bob@EXAMPLE.COM",
			userKrb5CCBaseName1: "bob",
			userKrb5CCBaseName2: "EMPTY",
			want:                standardPolicies,
		},
		"Second call after service restarted": {
			restart:             true,
			objectName1:         "bob@EXAMPLE.COM",
			objectName2:         "bob@EXAMPLE.COM",
			userKrb5CCBaseName1: "bob",
			userKrb5CCBaseName2: "", // We did’t RENEW the ticket
			want:                standardPolicies,
		},
		"Second call with different user": {
			objectName1:         "bob@EXAMPLE.COM",
			objectName2:         "sponge@EXAMPLE.COM",
			userKrb5CCBaseName1: "bob",
			userKrb5CCBaseName2: "sponge",
			want:                standardPolicies,
		},
		"Second call after a relogin": {
			objectName1:         "bob@EXAMPLE.COM",
			objectName2:         "bob@EXAMPLE.COM",
			userKrb5CCBaseName1: "bob",
			userKrb5CCBaseName2: "bobNew",
			want:                standardPolicies,
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel() // libsmbclient overrides SIGCHILD, but we have one global lock

			krb5CCName := setKrb5CC(t, tc.userKrb5CCBaseName1)

			cachedir, rundir := t.TempDir(), t.TempDir()

			adc, err := ad.New(context.Background(), "ldap://UNUSED:1636/", "example.com", bus,
				ad.WithCacheDir(cachedir), ad.WithRunDir(rundir), ad.WithoutKerberos(),
				ad.WithSSSCacheDir("testdata/sss/db"),
				ad.WithGPOListCmd(mockGPOListCmd(t, gpoListArgs)))
			require.NoError(t, err, "Setup: cannot create ad object")

			// First call
			entries, err := adc.GetPolicies(context.Background(), tc.objectName1, objectClass, krb5CCName)
			require.NoError(t, err, "GetPolicies should return no error")
			require.Equal(t, tc.want, entries, "GetPolicies returns expected policy entries with correct overrides")

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
				adc, err = ad.New(context.Background(), "ldap://UNUSED:1636/", "example.com", bus,
					ad.WithCacheDir(cachedir), ad.WithRunDir(rundir), ad.WithoutKerberos(),
					ad.WithSSSCacheDir("testdata/sss/db"),
					ad.WithGPOListCmd(mockGPOListCmd(t, gpoListArgs)))
				require.NoError(t, err, "Cannot create second ad object")
			}

			// Second call
			entries, err = adc.GetPolicies(context.Background(), tc.objectName2, objectClass, krb5CCName)
			require.NoError(t, err, "GetPolicies should return no error")
			require.Equal(t, tc.want, entries, "GetPolicies returns expected policy entries with correct overrides")
		})
	}
}

func TestGetPoliciesConcurrently(t *testing.T) {
	t.Parallel() // libsmbclient overrides SIGCHILD, but we have one global lock

	bus := testutils.NewDbusConn(t)

	objectClass := ad.UserObject

	standardPolicies := policies.Policies{GPOs: []policies.GPO{{ID: "standard", Name: "standard-name", Rules: map[string][]entry.Entry{
		"dconf": {
			{Key: "A", Value: "standardA"},
			{Key: "B", Value: "standardB"},
			{Key: "C", Value: "standardC"},
		}}}}}

	tests := map[string]struct {
		objectName1 string
		objectName2 string
		gpo1        string
		gpo2        string

		want1   policies.Policies
		want2   policies.Policies
		wantErr bool
	}{
		"Same user, same GPO": {
			objectName1: "bob@EXAMPLE.COM",
			objectName2: "bob@EXAMPLE.COM",
			gpo1:        "standard",
			gpo2:        "standard",
			want1:       standardPolicies,
			want2:       standardPolicies,
		},
		// We can’t run this test currently as the mock will always return the same value for bob (both gpos):
		// both calls are identical.
		/*"Same user, different GPOs": {
		objectName1: "bob@EXAMPLE.COM",
		objectName2: "bob@EXAMPLE.COM",
		gpo1:        "standard",
		gpo2:        "one-value",
		want1: standardPolicies,
			want2: policies.Policies{GPOs: []policies.GPO{{ID: "one-value", Name: "one-value-name", Rules: map[string][]entry.Entry{
				"dconf": {
					{Key: "C", Value: "oneValueC"},
				}}},
			}}},*/
		"Different users, same GPO": {
			objectName1: "bob@EXAMPLE.COM",
			objectName2: "sponge@EXAMPLE.COM",
			gpo1:        "standard",
			gpo2:        "standard",
			want1:       standardPolicies,
			want2:       standardPolicies,
		},
		"Different users, different GPO": {
			objectName1: "bob@EXAMPLE.COM",
			objectName2: "sponge@EXAMPLE.COM",
			gpo1:        "standard",
			gpo2:        "one-value",
			want1:       standardPolicies,
			want2: policies.Policies{GPOs: []policies.GPO{{ID: "one-value", Name: "one-value-name", Rules: map[string][]entry.Entry{
				"dconf": {
					{Key: "C", Value: "oneValueC"},
				}}},
			}}},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel() // libsmbclient overrides SIGCHILD, but we have one global lock

			krb5CCName1 := setKrb5CC(t, tc.objectName1)
			krb5CCName2 := setKrb5CC(t, tc.objectName2)

			cachedir, rundir := t.TempDir(), t.TempDir()

			mockObjectName1 := tc.objectName1
			if i := strings.LastIndex(mockObjectName1, "@"); i > 0 {
				mockObjectName1 = mockObjectName1[:i]
			}
			mockObjectName2 := tc.objectName2
			if i := strings.LastIndex(mockObjectName2, "@"); i > 0 {
				mockObjectName2 = mockObjectName2[:i]
			}

			gpoListMeta := fmt.Sprintf("DEPENDS:%s@%s:%s@%s", mockObjectName1, tc.gpo1, mockObjectName2, tc.gpo2)
			if mockObjectName1 == mockObjectName2 {
				gpoListMeta = fmt.Sprintf("DEPENDS:%s@%s", mockObjectName1, tc.gpo1)
			}
			adc, err := ad.New(context.Background(), "ldap://UNUSED:1636/", "example.com", bus,
				ad.WithCacheDir(cachedir), ad.WithRunDir(rundir), ad.WithoutKerberos(),
				ad.WithSSSCacheDir("testdata/sss/db"),
				ad.WithGPOListCmd(mockGPOListCmd(t, gpoListMeta)))
			require.NoError(t, err, "Setup: cannot create ad object")

			wg := sync.WaitGroup{}
			wg.Add(2)
			go func() {
				defer wg.Done()
				got1, err := adc.GetPolicies(context.Background(), tc.objectName1, objectClass, krb5CCName1)
				require.NoError(t, err, "GetPolicies should return no error")
				assert.Equal(t, tc.want1, got1, "Got expected policies")
			}()
			go func() {
				defer wg.Done()
				got2, err := adc.GetPolicies(context.Background(), tc.objectName2, objectClass, krb5CCName2)
				require.NoError(t, err, "GetPolicies should return no error")
				assert.Equal(t, tc.want2, got2, "Got expected policies")
			}()
			wg.Wait()
		})
	}
}

func TestListUsersFromCache(t *testing.T) {
	t.Parallel()

	bus := testutils.NewDbusConn(t)

	tests := map[string]struct {
		ccCachesToCreate []string
		noCCacheDir      bool

		want    []string
		wantErr bool
	}{
		"One user": {
			ccCachesToCreate: []string{"bob@EXAMPLE.COM"},
			want:             []string{"bob@EXAMPLE.COM"},
		},
		"Two users": {
			ccCachesToCreate: []string{"bob@EXAMPLE.COM", "sponge@OTHERDOMAIN.BIZ"},
			want:             []string{"bob@EXAMPLE.COM", "sponge@OTHERDOMAIN.BIZ"},
		},
		"None": {
			ccCachesToCreate: []string{},
			want:             nil,
		},
		"Machines are ignored": {
			ccCachesToCreate: []string{"bob@EXAMPLE.COM", "sponge@OTHERDOMAIN.BIZ", "myMachine"},
			want:             []string{"bob@EXAMPLE.COM", "sponge@OTHERDOMAIN.BIZ"},
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

			adc, err := ad.New(context.Background(), "ldap://UNUSED:1636/", "example.com", bus,
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
		"One valid user":                          {target: "user@example.com", want: "user@example.com"},
		`One valid user with domain\user`:         {target: `example.com\user`, want: "user@example.com"},
		"One user without explicit domain suffix": {target: "user", defaultDomainSuffix: "example.com", want: "user@example.com"},

		// User match computer names
		"User name matching computer, setting as user": {target: hostname, objectClass: ad.UserObject, defaultDomainSuffix: "example.com",
			want: hostname + "@example.com"},
		"User name fqdn matching computer":  {target: hostname + "@example.com", want: hostname + "@example.com"},
		"Computer name without objectClass": {target: hostname, want: hostname},

		// Computer cases
		"Computer is left as such":        {target: "computername", objectClass: ad.ComputerObject, want: "computername"},
		"Computer with @ is left as such": {target: "computername@example.com", objectClass: ad.ComputerObject, want: "computername@example.com"},

		// Error cases
		`Error on multiple \ in name`:                        {target: `example.com\user\something`, wantErr: true},
		`Error on no default domain suffix and no fqdn user`: {target: `user`, wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			adc, err := ad.New(context.Background(), "ldap://UNUSED:1636/", "example.com", bus,
				ad.WithCacheDir(t.TempDir()), ad.WithRunDir(t.TempDir()),
				ad.WithDefaultDomainSuffix(tc.defaultDomainSuffix))
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

	// as in gpolist, we split on the @ if any
	objectName := args[len(args)-1]
	objectName = strings.Split(objectName, "@")[0]

	var gpos []string

	// Parameterized on user gpos
	if strings.HasPrefix(args[0], "DEPENDS:") {
		v := strings.TrimPrefix(args[0], "DEPENDS:")
		gpoItems := strings.Split(v, ":")
		for _, gpoItem := range gpoItems {
			i := strings.SplitN(gpoItem, "@", 2)
			if i[0] == objectName {
				gpos = append(gpos, i[1])
			}
		}
	} else {
		gpos = strings.Split(args[0], "_")
	}

	for _, gpo := range gpos {
		fmt.Fprintf(os.Stdout, "%s-name\tsmb://localhost:%d/SYSVOL/example.com/Policies/%s\n", gpo, ad.SmbPort, gpo)
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

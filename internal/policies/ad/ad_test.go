package ad_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/policies/ad"
	"github.com/ubuntu/adsys/internal/policies/policy"
)

func TestNew(t *testing.T) {
	t.Parallel()

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
			t.Parallel()
			runDir, cacheDir := t.TempDir(), t.TempDir()

			if tc.runDirRO {
				require.NoError(t, os.Chmod(runDir, 0400), "Setup: can’t set run directory to Read only")

			}
			if tc.cacheDirRO {
				require.NoError(t, os.Chmod(cacheDir, 0400), "Setup: can’t set cache directory to Read only")
			}
			kinitMock := ad.MockKinit{tc.kinitFail}

			adc, err := ad.New(context.Background(), "ldap://UNUSED:1636/", "localdomain",
				ad.WithRunDir(runDir),
				ad.WithCacheDir(cacheDir),
				ad.WithKinitCmd(kinitMock))
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

func TestGetPolicies(t *testing.T) {
	//t.Parallel() // libsmbclient overrides SIGCHILD, keep one AD object

	var krb5CCcontent = []byte("KRB5 Ticket file content")

	hostname, err := os.Hostname()
	require.NoError(t, err, "Setup: failed to get hostname")

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
	*/

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

		dontCreateOriginalKrb5CCName bool
		turnKrb5CCRO                 bool

		want    map[string]policy.Entry
		wantErr bool
	}{
		"Standard policy, user object": {
			gpoListArgs:        "standard",
			objectName:         "bob",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			want: map[string]policy.Entry{
				"Software/Ubuntu/A": {Key: "Software/Ubuntu/A", Value: "standardA"},
				"Software/Ubuntu/B": {Key: "Software/Ubuntu/B", Value: "standardB"},
				"Software/Ubuntu/C": {Key: "Software/Ubuntu/C", Value: "standardC"},
			},
		},
		"Standard policy, computer object": {
			gpoListArgs:        "standard",
			objectName:         hostname,
			objectClass:        ad.ComputerObject,
			userKrb5CCBaseName: "", // ignored for machine
			want: map[string]policy.Entry{
				"Software/Ubuntu/A": {Key: "Software/Ubuntu/A", Value: "standardA"},
				"Software/Ubuntu/D": {Key: "Software/Ubuntu/D", Value: "standardD"},
				"Software/Ubuntu/E": {Key: "Software/Ubuntu/E", Value: "standardE"},
			},
		},
		"User only policy, user object": {
			gpoListArgs:        "user-only",
			objectName:         "bob",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			want: map[string]policy.Entry{
				"Software/Ubuntu/A": {Key: "Software/Ubuntu/A", Value: "userOnlyA"},
				"Software/Ubuntu/B": {Key: "Software/Ubuntu/B", Value: "userOnlyB"},
			},
		},
		"User only policy, computer object": {
			gpoListArgs:        "user-only",
			objectName:         hostname,
			objectClass:        ad.ComputerObject,
			userKrb5CCBaseName: "",
			want:               map[string]policy.Entry{},
		},
		"Computer only policy, user object": {
			gpoListArgs:        "machine-only",
			objectName:         "bob",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			want:               map[string]policy.Entry{},
		},
		"Computer ignored CCBaseName": {
			gpoListArgs:        "standard",
			objectName:         hostname,
			objectClass:        ad.ComputerObject,
			userKrb5CCBaseName: "somethingtotallyarbitrary", // ignored for machine
			want: map[string]policy.Entry{
				"Software/Ubuntu/A": {Key: "Software/Ubuntu/A", Value: "standardA"},
				"Software/Ubuntu/D": {Key: "Software/Ubuntu/D", Value: "standardD"},
				"Software/Ubuntu/E": {Key: "Software/Ubuntu/E", Value: "standardE"},
			},
		},

		"Two policies, with overrides": {
			gpoListArgs:        "one-value_standard",
			objectName:         "bob",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			want: map[string]policy.Entry{
				"Software/Ubuntu/A": {Key: "Software/Ubuntu/A", Value: "standardA"},
				"Software/Ubuntu/B": {Key: "Software/Ubuntu/B", Value: "standardB"},
				"Software/Ubuntu/C": {Key: "Software/Ubuntu/C", Value: "oneValueC"},
			},
		},
		"Two policies, with reversed overrides": {
			gpoListArgs:        "standard_one-value",
			objectName:         "bob",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			want: map[string]policy.Entry{
				"Software/Ubuntu/A": {Key: "Software/Ubuntu/A", Value: "standardA"},
				"Software/Ubuntu/B": {Key: "Software/Ubuntu/B", Value: "standardB"},
				"Software/Ubuntu/C": {Key: "Software/Ubuntu/C", Value: "standardC"},
			},
		},
		"Two policies, no overrides": {
			gpoListArgs:        "one-value_user-only",
			objectName:         "bob",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			want: map[string]policy.Entry{
				"Software/Ubuntu/A": {Key: "Software/Ubuntu/A", Value: "userOnlyA"},
				"Software/Ubuntu/B": {Key: "Software/Ubuntu/B", Value: "userOnlyB"},
				"Software/Ubuntu/C": {Key: "Software/Ubuntu/C", Value: "oneValueC"},
			},
		},
		"Two policies, no overrides, reversed": {
			gpoListArgs:        "user-only_one-value",
			objectName:         "bob",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			want: map[string]policy.Entry{
				"Software/Ubuntu/A": {Key: "Software/Ubuntu/A", Value: "userOnlyA"},
				"Software/Ubuntu/B": {Key: "Software/Ubuntu/B", Value: "userOnlyB"},
				"Software/Ubuntu/C": {Key: "Software/Ubuntu/C", Value: "oneValueC"},
			},
		},
		"Two policies, no overrides, one is not the same object type": {
			gpoListArgs:        "machine-only_standard",
			objectName:         "bob",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			want: map[string]policy.Entry{
				"Software/Ubuntu/A": {Key: "Software/Ubuntu/A", Value: "standardA"},
				"Software/Ubuntu/B": {Key: "Software/Ubuntu/B", Value: "standardB"},
				"Software/Ubuntu/C": {Key: "Software/Ubuntu/C", Value: "standardC"},
			},
		},

		"Disabled value overrides non disabled one": {
			gpoListArgs:        "disabled-value_standard",
			objectName:         "bob",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			want: map[string]policy.Entry{
				"Software/Ubuntu/A": {Key: "Software/Ubuntu/A", Value: "standardA"},
				"Software/Ubuntu/B": {Key: "Software/Ubuntu/B", Value: "standardB"},
				"Software/Ubuntu/C": {Key: "Software/Ubuntu/C", Value: "", Disabled: true},
			},
		},
		"Disabled value is overridden": {
			gpoListArgs:        "standard_disabled-value",
			objectName:         "bob",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			want: map[string]policy.Entry{
				"Software/Ubuntu/A": {Key: "Software/Ubuntu/A", Value: "standardA"},
				"Software/Ubuntu/B": {Key: "Software/Ubuntu/B", Value: "standardB"},
				"Software/Ubuntu/C": {Key: "Software/Ubuntu/C", Value: "standardC"},
			},
		},

		"More policies, with multiple overrides": {
			gpoListArgs:        "user-only_one-value_standard",
			objectName:         "bob",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			want: map[string]policy.Entry{
				"Software/Ubuntu/A": {Key: "Software/Ubuntu/A", Value: "userOnlyA"},
				"Software/Ubuntu/B": {Key: "Software/Ubuntu/B", Value: "userOnlyB"},
				"Software/Ubuntu/C": {Key: "Software/Ubuntu/C", Value: "oneValueC"},
			},
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
			objectName:         "bob",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "",
			wantErr:            true,
		},
		"Unexisting CC original file for user": {
			gpoListArgs:                  "standard",
			objectName:                   "bob",
			objectClass:                  ad.UserObject,
			userKrb5CCBaseName:           "kbr5cc_adsys_tests_bob",
			dontCreateOriginalKrb5CCName: true,
			wantErr:                      true,
		},
		"Unexisting CC original file for machine": {
			gpoListArgs:                  "standard",
			objectName:                   hostname,
			objectClass:                  ad.ComputerObject,
			userKrb5CCBaseName:           "",
			dontCreateOriginalKrb5CCName: true,
			wantErr:                      true,
		},
		"Corrupted policy file": {
			gpoListArgs:        "corrupted-policy",
			objectName:         "bob",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			wantErr:            true,
		},
		"Policy can’t be downloaded": {
			gpoListArgs:        "no-gpt-ini",
			objectName:         "bob",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			wantErr:            true,
		},
		"Symlinks can’t be created": {
			gpoListArgs:        "standard",
			objectName:         "bob",
			objectClass:        ad.UserObject,
			userKrb5CCBaseName: "kbr5cc_adsys_tests_bob",
			turnKrb5CCRO:       true,
			wantErr:            true,
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			//t.Parallel() // libsmbclient overrides SIGCHILD, keep one AD object

			// only create original cc file when requested
			krb5CCName := tc.userKrb5CCBaseName
			if krb5CCName != "" && !tc.dontCreateOriginalKrb5CCName {
				f, err := ioutil.TempFile("", tc.userKrb5CCBaseName+"_*")
				require.NoError(t, err, "Setup: failed to create temporary krb5 cache file")
				defer f.Close()
				krb5CCName = f.Name()
				defer os.Remove(krb5CCName) // clean up
				_, err = f.Write(krb5CCcontent)
				require.NoError(t, err, "Setup: failed to write to temporary krb5 cache file")
				require.NoError(t, f.Close(), "Setup: failed to close temporary krb5 cache file")
			}

			cachedir, rundir := t.TempDir(), t.TempDir()
			hostKrb5CCName := filepath.Join(rundir, "krb5cc", hostname)
			if tc.dontCreateOriginalKrb5CCName {
				hostKrb5CCName = ""
			}
			adc, err := ad.New(context.Background(), "ldap://UNUSED:1636/", "warthogs.biz",
				ad.WithCacheDir(cachedir), ad.WithRunDir(rundir), ad.WithoutKerberos(),
				ad.WithKinitCmd(ad.MockKinitWithComputer{hostKrb5CCName}),
				ad.WithGPOListCmd(mockGPOListCmd(t, tc.gpoListArgs)))
			require.NoError(t, err, "Setup: cannot create ad object")

			if tc.turnKrb5CCRO {
				require.NoError(t, os.Chmod(adc.Krb5CacheDir(), 0400), "Setup: can’t set krb5 origin cache directory read only")
				defer func() {
					if err := os.Chmod(adc.Krb5CacheDir(), 0700); err != nil {
						t.Logf("Teardown: couldn’t restore permission on %s: %v", adc.Krb5CacheDir(), err)
					}
				}()
			}

			entries, err := adc.GetPolicies(context.Background(), tc.objectName, tc.objectClass, krb5CCName)
			if tc.wantErr {
				require.NotNil(t, err, "GetPolicies should have errored out")
			} else {
				require.NoError(t, err, "GetPolicies should return no error")
			}
			require.Equal(t, tc.want, entries, "GetPolicies returns expected policy entries with correct overrides")
		})
	}
}

func TestGetPoliciesWorkflows(t *testing.T) {
	//t.Parallel() // libsmbclient overrides SIGCHILD, keep one AD object

	gpoListArgs := "standard"
	objectClass := ad.UserObject

	tests := map[string]struct {
		objectName1         string
		objectName2         string
		userKrb5CCBaseName1 string
		userKrb5CCBaseName2 string
		restart             bool

		want    map[string]policy.Entry
		wantErr bool
	}{
		"Second call is a refresh (without Krb5CCName specified)": {
			objectName1:         "bob",
			objectName2:         "bob",
			userKrb5CCBaseName1: "bob",
			userKrb5CCBaseName2: "EMPTY",
			want: map[string]policy.Entry{
				"Software/Ubuntu/A": {Key: "Software/Ubuntu/A", Value: "standardA"},
				"Software/Ubuntu/B": {Key: "Software/Ubuntu/B", Value: "standardB"},
				"Software/Ubuntu/C": {Key: "Software/Ubuntu/C", Value: "standardC"},
			},
		},
		"Second call after service restarted": {
			restart:             true,
			objectName1:         "bob",
			objectName2:         "bob",
			userKrb5CCBaseName1: "bob",
			userKrb5CCBaseName2: "", // We did’t RENEW the ticket
			want: map[string]policy.Entry{
				"Software/Ubuntu/A": {Key: "Software/Ubuntu/A", Value: "standardA"},
				"Software/Ubuntu/B": {Key: "Software/Ubuntu/B", Value: "standardB"},
				"Software/Ubuntu/C": {Key: "Software/Ubuntu/C", Value: "standardC"},
			},
		},
		"Second call with different user": {
			objectName1:         "bob",
			objectName2:         "sponge",
			userKrb5CCBaseName1: "bob",
			userKrb5CCBaseName2: "sponge",
			want: map[string]policy.Entry{
				"Software/Ubuntu/A": {Key: "Software/Ubuntu/A", Value: "standardA"},
				"Software/Ubuntu/B": {Key: "Software/Ubuntu/B", Value: "standardB"},
				"Software/Ubuntu/C": {Key: "Software/Ubuntu/C", Value: "standardC"},
			},
		},
		"Second call after a relogin": {
			objectName1:         "bob",
			objectName2:         "bob",
			userKrb5CCBaseName1: "bob",
			userKrb5CCBaseName2: "bobNew",
			want: map[string]policy.Entry{
				"Software/Ubuntu/A": {Key: "Software/Ubuntu/A", Value: "standardA"},
				"Software/Ubuntu/B": {Key: "Software/Ubuntu/B", Value: "standardB"},
				"Software/Ubuntu/C": {Key: "Software/Ubuntu/C", Value: "standardC"},
			},
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			//t.Parallel() // libsmbclient overrides SIGCHILD, keep one AD object

			krb5CCName, cleanup := setKrb5CC(t, tc.userKrb5CCBaseName1)
			defer cleanup()

			cachedir, rundir := t.TempDir(), t.TempDir()

			adc, err := ad.New(context.Background(), "ldap://UNUSED:1636/", "warthogs.biz",
				ad.WithCacheDir(cachedir), ad.WithRunDir(rundir), ad.WithoutKerberos(),
				ad.WithKinitCmd(ad.MockKinit{}),
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
					krb5CCName, cleanup = setKrb5CC(t, tc.userKrb5CCBaseName2)
					defer cleanup()
				}
			}

			// Restart: recreate ad object
			if tc.restart {
				adc, err = ad.New(context.Background(), "ldap://UNUSED:1636/", "warthogs.biz",
					ad.WithCacheDir(cachedir), ad.WithRunDir(rundir), ad.WithoutKerberos(),
					ad.WithKinitCmd(ad.MockKinit{}),
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

func TestMockGPOList(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	defer os.Exit(0)

	krb5File := os.Getenv("KRB5CCNAME")
	if _, err := os.Lstat(krb5File); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Expecting symlink %s to exists", krb5File)
		os.Exit(1)
	}
	if _, err := os.Stat(krb5File); os.IsNotExist(err) {
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

	gpos := strings.Split(args[0], "_")
	for _, gpo := range gpos {
		fmt.Fprintf(os.Stdout, "%s\tsmb://localhost:%d/SYSVOL/warthogs.biz/Policies/%s\n", gpo, ad.SmbPort, gpo)
	}
}

func mockGPOListCmd(t *testing.T, args ...string) []string {
	t.Helper()

	cArgs := []string{"env", "GO_WANT_HELPER_PROCESS=1", os.Args[0], "-test.run=TestMockGPOList", "--"}
	cArgs = append(cArgs, args...)
	return cArgs
}

func setKrb5CC(t *testing.T, ccRootName string) (string, func()) {
	t.Helper()

	f, err := ioutil.TempFile("", fmt.Sprintf("kbr5cc_adsys_tests_%s_*", ccRootName))
	require.NoError(t, err, "Setup: failed to create temporary krb5 cache file")
	defer f.Close()
	krb5CCName := f.Name()
	_, err = f.Write([]byte("KRB5 Ticket file content"))
	require.NoError(t, err, "Setup: failed to write to temporary krb5 cache file")
	require.NoError(t, f.Close(), "Setup: failed to close temporary krb5 cache file")
	return krb5CCName, func() {
		os.Remove(krb5CCName) // clean up
	}
}

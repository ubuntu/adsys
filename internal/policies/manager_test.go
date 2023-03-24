package policies_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/termie/go-shutil"
	"github.com/ubuntu/adsys/internal/consts"
	"github.com/ubuntu/adsys/internal/policies"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestApplyPolicies(t *testing.T) {
	//t.Parallel()

	hostname, err := os.Hostname()
	require.NoError(t, err, "Setup: failed to get hostname for tests.")

	bus := testutils.NewDbusConn(t)

	subscriptionDbus := bus.Object(consts.SubscriptionDbusRegisteredName,
		dbus.ObjectPath(consts.SubscriptionDbusObjectPath))

	tests := map[string]struct {
		policiesDir                     string
		secondCallWithNoRules           bool
		scriptSessionEndedForSecondCall bool
		makeDirReadOnly                 string
		isNotSubscribed                 bool
		secondCallWithNoSubscription    bool
		noUbuntuProxyManager            bool

		wantErr bool
	}{
		"Succeed": {policiesDir: "all_entry_types"},
		"Second call with no rules deletes everything":                           {policiesDir: "all_entry_types", secondCallWithNoRules: true, scriptSessionEndedForSecondCall: true},
		"Second call with no rules don't remove scripts if session hasn’t ended": {policiesDir: "all_entry_types", secondCallWithNoRules: true, scriptSessionEndedForSecondCall: false},

		// no subscription filterings
		"No subscription is only dconf content":                                         {policiesDir: "all_entry_types", isNotSubscribed: true},
		"Second call with no subscription should remove everything but dconf content":   {policiesDir: "all_entry_types", secondCallWithNoSubscription: true, scriptSessionEndedForSecondCall: true},
		"Second call with no subscription don't remove scripts if session hasn’t ended": {policiesDir: "all_entry_types", secondCallWithNoSubscription: true, scriptSessionEndedForSecondCall: false},

		// Error cases
		"Error when applying dconf policy":     {policiesDir: "dconf_failing", wantErr: true},
		"Error when applying privilege policy": {makeDirReadOnly: "etc/sudoers.d", policiesDir: "all_entry_types", wantErr: true},
		"Error when applying scripts policy":   {makeDirReadOnly: "run/adsys/machine", policiesDir: "all_entry_types", wantErr: true},
		"Error when applying apparmor policy":  {makeDirReadOnly: "etc/apparmor.d/adsys", policiesDir: "all_entry_types", wantErr: true},
		"Error when applying mount policy":     {makeDirReadOnly: "etc/systemd/system", policiesDir: "all_entry_types", wantErr: true},
		"Error when applying proxy policy":     {noUbuntuProxyManager: true, policiesDir: "all_entry_types", wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			// We change the dbus returned values to simulate a subscription
			//t.Parallel()

			pols, err := policies.NewFromCache(context.Background(), filepath.Join("testdata", "cache", "policies", tc.policiesDir))
			require.NoError(t, err, "Setup: can not load policies list")
			defer pols.Close()

			fakeRootDir := t.TempDir()
			cacheDir := filepath.Join(fakeRootDir, "var", "cache", "adsys")
			runDir := filepath.Join(fakeRootDir, "run", "adsys")
			dconfDir := filepath.Join(fakeRootDir, "etc", "dconf")
			policyKitDir := filepath.Join(fakeRootDir, "etc", "polkit-1")
			sudoersDir := filepath.Join(fakeRootDir, "etc", "sudoers.d")
			apparmorDir := filepath.Join(fakeRootDir, "etc", "apparmor.d", "adsys")
			systemUnitDir := filepath.Join(fakeRootDir, "etc", "systemd", "system")
			loadedPoliciesFile := filepath.Join(fakeRootDir, "sys", "kernel", "security", "apparmor", "profiles")

			err = os.MkdirAll(filepath.Dir(loadedPoliciesFile), 0700)
			require.NoError(t, err, "Setup: can not create loadedPoliciesFile dir")
			err = os.WriteFile(loadedPoliciesFile, []byte("someprofile (enforce)\n"), 0600)
			require.NoError(t, err, "Setup: can not create loadedPoliciesFile")

			status := true
			if tc.isNotSubscribed {
				status = false
			}
			require.NoError(t, subscriptionDbus.SetProperty(consts.SubscriptionDbusInterface+".Attached", status), "Setup: can not set subscription status to %q", status)
			defer func() {
				require.NoError(t, subscriptionDbus.SetProperty(consts.SubscriptionDbusInterface+".Attached", false), "Teardown: can not restore subscription status")
			}()

			m, err := policies.NewManager(bus,
				hostname,
				policies.WithCacheDir(cacheDir),
				policies.WithRunDir(runDir),
				policies.WithDconfDir(dconfDir),
				policies.WithPolicyKitDir(policyKitDir),
				policies.WithSudoersDir(sudoersDir),
				policies.WithApparmorDir(apparmorDir),
				policies.WithApparmorFsDir(filepath.Dir(loadedPoliciesFile)),
				policies.WithApparmorParserCmd([]string{"/bin/true"}),
				policies.WithSystemUnitDir(systemUnitDir),
				policies.WithProxyApplier(&mockProxyApplier{wantApplyError: tc.noUbuntuProxyManager}),
				policies.WithSystemdCaller(&testutils.MockSystemdCaller{}),
			)
			require.NoError(t, err, "Setup: couldn’t get a new policy manager")

			err = os.MkdirAll(filepath.Join(cacheDir, policies.PoliciesCacheBaseName), 0750)
			require.NoError(t, err, "Setup: cannot create policies cache directory")

			if tc.makeDirReadOnly != "" {
				require.NoError(t, os.MkdirAll(filepath.Join(fakeRootDir, tc.makeDirReadOnly), 0750), "Setup: can not create directory")
				testutils.MakeReadOnly(t, filepath.Join(fakeRootDir, tc.makeDirReadOnly))
			}

			err = m.ApplyPolicies(context.Background(), "hostname", true, &pols)
			if tc.wantErr {
				require.Error(t, err, "ApplyPolicy should return an error but got none")
				return
			}
			require.NoError(t, err, "ApplyPolicy should return no error but got one")

			// Fake starting scripts session when we ran scripts
			runningFlag := filepath.Join(runDir, "machine", "scripts", ".running")
			if !tc.isNotSubscribed && tc.policiesDir != "dconf_failing" {
				require.NoError(t, os.WriteFile(runningFlag, nil, 0600), "Setup: can't mimick session in progress")
			}

			if tc.scriptSessionEndedForSecondCall {
				require.NoError(t, os.Remove(runningFlag), "Setup: can not remove .running file before second call")
			}

			var runSecondCall bool
			if tc.secondCallWithNoRules {
				runSecondCall = true
				pols, err = policies.New(context.Background(), nil, "")
				require.NoError(t, err, "Setup: can not empty policies before second call")
			} else if tc.secondCallWithNoSubscription {
				runSecondCall = true
				require.NoError(t, subscriptionDbus.SetProperty(consts.SubscriptionDbusInterface+".Attached", false), "Setup: can not set subscription status for second call to disabled")
			}
			if runSecondCall {
				err = m.ApplyPolicies(context.Background(), "hostname", true, &pols)
				require.NoError(t, err, "ApplyPolicy should return no error but got one")
			}

			testutils.CompareTreesWithFiltering(t, fakeRootDir, testutils.GoldenPath(t), testutils.Update())
		})
	}
}

func TestDumpPolicies(t *testing.T) {
	t.Parallel()

	bus := testutils.NewDbusConn(t)

	hostname, err := os.Hostname()
	require.NoError(t, err, "Setup: failed to get hostname")

	tests := map[string]struct {
		cachePoliciesUser  string
		cachePolicyMachine string
		target             string
		computerOnly       bool
		withRules          bool
		withOverridden     bool

		wantErr bool
	}{
		"One GPO User": {
			cachePoliciesUser: "one_gpo",
		},
		"One GPO Machine": {
			cachePolicyMachine: "one_gpo",
			target:             hostname,
			computerOnly:       true,
		},
		"One GPO User + Machine": {
			cachePoliciesUser:  "one_gpo",
			cachePolicyMachine: "one_gpo_other",
		},
		"Multiple GPOs": {
			cachePoliciesUser: "two_gpos_no_override",
		},

		// Show rules
		"One GPO with rules": {
			cachePoliciesUser: "one_gpo",
			withRules:         true,
		},
		"Machine only GPO with rules": {
			cachePolicyMachine: "one_gpo",
			target:             hostname,
			computerOnly:       true,
			withRules:          true,
		},
		"Multiple GPOs with rules, no override": {
			cachePoliciesUser: "two_gpos_no_override",
			withRules:         true,
		},
		"Multiple GPOs with rules, override hidden": {
			cachePoliciesUser: "two_gpos_with_overrides",
			withRules:         true,
		},
		"Multiple GPOs with rules, override, shown": {
			cachePoliciesUser: "two_gpos_with_overrides",
			withRules:         true,
			withOverridden:    true,
		},

		// machine and user GPO with overrides between machine and user
		"Overrides between machine and user GPOs, hidden": {
			cachePoliciesUser:  "one_gpo",
			cachePolicyMachine: "two_gpos_override_one_gpo",
			withRules:          true,
		},
		"Overrides between machine and user GPOs, shown": {
			cachePoliciesUser:  "one_gpo",
			cachePolicyMachine: "two_gpos_override_one_gpo",
			withRules:          true,
			withOverridden:     true,
		},

		// Edge cases
		"Same GPO Machine and User": {
			cachePoliciesUser:  "one_gpo",
			cachePolicyMachine: "one_gpo",
		},
		"Same GPO Machine and User with rules": {
			cachePoliciesUser:  "one_gpo",
			cachePolicyMachine: "one_gpo",
			withRules:          true,
		},
		"Same GPO Machine and User with rules and overrides": {
			cachePoliciesUser:  "one_gpo",
			cachePolicyMachine: "one_gpo",
			withRules:          true,
			withOverridden:     true,
		},

		// Error cases
		"Error on missing target cache": {
			wantErr: true,
		},
		"Error on missing machine cache when targeting user": {
			cachePoliciesUser:  "one_gpo",
			cachePolicyMachine: "-",
			wantErr:            true,
		},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cacheDir, runDir := t.TempDir(), t.TempDir()
			m, err := policies.NewManager(bus, hostname, policies.WithCacheDir(cacheDir), policies.WithRunDir(runDir))
			require.NoError(t, err, "Setup: couldn’t get a new policy manager")

			err = os.MkdirAll(filepath.Join(cacheDir, policies.PoliciesCacheBaseName), 0750)
			require.NoError(t, err, "Setup: cant not create policies cache directory")

			if tc.cachePoliciesUser != "" {
				err := shutil.CopyTree(filepath.Join("testdata", "cache", "policies", tc.cachePoliciesUser), filepath.Join(cacheDir, policies.PoliciesCacheBaseName, "user"), nil)
				require.NoError(t, err, "Setup: couldn’t copy user policies cache")
			}
			if tc.cachePolicyMachine == "" {
				machinePolicyCache := filepath.Join(cacheDir, policies.PoliciesCacheBaseName, hostname)
				err = os.MkdirAll(machinePolicyCache, 0750)
				require.NoError(t, err, "Setup: cant not create machine policies cache directory")
				f, err := os.Create(filepath.Join(machinePolicyCache, "policies"))
				require.NoError(t, err, "Setup: failed to create empty machine policies cache")
				f.Close()
			} else if tc.cachePolicyMachine != "-" {
				err := shutil.CopyTree(filepath.Join("testdata", "cache", "policies", tc.cachePolicyMachine), filepath.Join(cacheDir, policies.PoliciesCacheBaseName, hostname), nil)
				require.NoError(t, err, "Setup: couldn’t copy machine policies cache")
			}

			if tc.target == "" {
				tc.target = "user"
			}
			got, err := m.DumpPolicies(context.Background(), tc.target, tc.computerOnly, tc.withRules, tc.withOverridden)
			if tc.wantErr {
				require.Error(t, err, "DumpPolicies should return an error but got none")
				return
			}
			require.NoError(t, err, "DumpPolicies should return no error but got one")

			want := testutils.LoadWithUpdateFromGolden(t, got)
			require.Equal(t, want, got, "DumpPolicies returned expected output")
		})
	}
}

func TestLastUpdateFor(t *testing.T) {
	t.Parallel()

	bus := testutils.NewDbusConn(t)

	hostname, err := os.Hostname()
	require.NoError(t, err, "Setup: failed to get hostname")

	tests := map[string]struct {
		target    string
		isMachine bool

		wantErr bool
	}{
		"Returns user's last update time":       {target: "user"},
		"Returns machine's last update time":    {target: hostname, isMachine: true},
		"Target is ignored for machine request": {target: "does_not_exit", isMachine: true},

		// Error cases
		"Error when target does not exist": {target: "does_not_exit", wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cacheDir, runDir := t.TempDir(), t.TempDir()
			m, err := policies.NewManager(bus, hostname, policies.WithCacheDir(cacheDir), policies.WithRunDir(runDir))
			require.NoError(t, err, "Setup: couldn’t get a new policy manager")

			err = os.MkdirAll(filepath.Join(cacheDir, policies.PoliciesCacheBaseName), 0750)
			require.NoError(t, err, "Setup: cant not create policies cache directory")

			start := time.Now()
			// Starts and ends are monotic, while os.Stat is wall clock, we have to wait for measuring difference…
			time.Sleep(100 * time.Millisecond)
			f, err := os.Create(filepath.Join(cacheDir, policies.PoliciesCacheBaseName, "user"))
			require.NoError(t, err, "Setup: couldn’t copy user cache")
			f.Close()
			f, err = os.Create(filepath.Join(cacheDir, policies.PoliciesCacheBaseName, hostname))
			require.NoError(t, err, "Setup: couldn’t copy user cache")
			f.Close()

			got, err := m.LastUpdateFor(context.Background(), tc.target, tc.isMachine)
			if tc.wantErr {
				require.Error(t, err, "LastUpdateFor should return an error but got none")
				return
			}
			require.NoError(t, err, "LastUpdateFor should return no error but got one")
			end := time.Now()

			assert.True(t, got.After(start), "expected got after start")
			assert.True(t, got.Before(end), "expected got before end")
		})
	}
}

func TestGetSubscriptionState(t *testing.T) {
	//t.Parallel()

	bus := testutils.NewDbusConn(t)
	subscriptionDbus := bus.Object(consts.SubscriptionDbusRegisteredName,
		dbus.ObjectPath(consts.SubscriptionDbusObjectPath))

	hostname, err := os.Hostname()
	require.NoError(t, err, "Setup: failed to get hostname for tests.")

	tests := map[string]struct {
		status bool

		want bool
	}{
		"Returns enablement status (enabled)":  {status: true, want: true},
		"Returns enablement status (disabled)": {status: false, want: false},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			// We change the dbus returned values to simulate a subscription
			//t.Parallel()

			require.NoError(t, subscriptionDbus.SetProperty(consts.SubscriptionDbusInterface+".Attached", tc.status), "Setup: can not set subscription status to %q", tc.status)
			defer func() {
				require.NoError(t, subscriptionDbus.SetProperty(consts.SubscriptionDbusInterface+".Attached", false), "Teardown: can not restore subscription status")
			}()

			cacheDir, runDir := t.TempDir(), t.TempDir()
			m, err := policies.NewManager(bus, hostname, policies.WithCacheDir(cacheDir), policies.WithRunDir(runDir))
			require.NoError(t, err, "Setup: couldn’t get a new policy manager")

			got := m.GetSubscriptionState(context.Background())
			assert.Equal(t, tc.want, got, "GetStatus should return %q but got %q", tc.want, got)
		})
	}
}

// mockProxyApplier is a mock for the proxy apply object.
type mockProxyApplier struct {
	wantApplyError bool
}

// Call mocks the proxy apply call.
func (d *mockProxyApplier) Call(_ string, _ dbus.Flags, _ ...interface{}) *dbus.Call {
	var errApply error

	if d.wantApplyError {
		errApply = errors.New("proxy apply error")
	}

	return &dbus.Call{Err: errApply}
}

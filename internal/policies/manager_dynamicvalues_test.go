package policies_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/policies"
	"github.com/ubuntu/adsys/internal/policies/dynamicvalues"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestDynamicValuesContext(t *testing.T) {
	t.Parallel()

	bus := testutils.NewDbusConn(t)

	tests := map[string]struct {
		hostname   string
		objectName string
		isComputer bool

		want    dynamicvalues.Context
		wantErr bool
	}{
		"Computer policy uses the machine domain": {
			hostname: "workstation01", objectName: "workstation01", isComputer: true,
			want: dynamicvalues.Context{
				Hostname:     "workstation01",
				FQDNHostname: "workstation01.example.com",
				Domain:       "example.com",
				IsComputer:   true,
			},
		},
		"User policy derives user and domain from the object name": {
			hostname: "workstation01", objectName: "bob@example.com",
			want: dynamicvalues.Context{
				User:         "bob",
				FQDNUser:     "bob@example.com",
				Hostname:     "workstation01",
				FQDNHostname: "workstation01.example.com",
				Domain:       "example.com",
			},
		},
		"User from a child domain keeps the user domain but machine FQDN hostname": {
			hostname: "workstation01", objectName: "bob@child.example.com",
			want: dynamicvalues.Context{
				User:         "bob",
				FQDNUser:     "bob@child.example.com",
				Hostname:     "workstation01",
				FQDNHostname: "workstation01.example.com",
				Domain:       "child.example.com",
			},
		},
		"Already fully-qualified hostname is not suffixed again": {
			hostname: "workstation01.example.com", objectName: "workstation01.example.com", isComputer: true,
			want: dynamicvalues.Context{
				Hostname:     "workstation01.example.com",
				FQDNHostname: "workstation01.example.com",
				Domain:       "example.com",
				IsComputer:   true,
			},
		},

		"Error on user object name without a domain": {
			hostname: "workstation01", objectName: "bob", wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cacheDir := t.TempDir()
			runDir := t.TempDir()
			m, err := policies.NewManager(bus, tc.hostname, mockBackend{},
				policies.WithCacheDir(cacheDir), policies.WithRunDir(runDir))
			require.NoError(t, err, "Setup: couldn't create manager")

			got, err := m.DynamicValuesContext(tc.objectName, tc.isComputer)
			if tc.wantErr {
				require.Error(t, err, "DynamicValuesContext should have errored but didn't")
				return
			}
			require.NoError(t, err, "DynamicValuesContext returned an unexpected error")
			require.Equal(t, tc.want, got, "DynamicValuesContext returned an unexpected context")
		})
	}
}

func TestExpandDynamicValues(t *testing.T) {
	t.Parallel()

	userCtx := dynamicvalues.Context{User: "bob", FQDNUser: "bob@example.com", Domain: "example.com"}

	t.Run("Expands enabled entries and skips disabled ones", func(t *testing.T) {
		t.Parallel()

		rules := map[string][]entry.Entry{
			"dconf": {
				{Key: "com/x/a", Value: "smb://h/${USER}"},
				{Key: "com/x/b", Value: "${TYPO}", Disabled: true},
			},
			"mount": {
				{Key: "user-mounts", Value: "smb://h/${USER}/data"},
			},
		}

		require.NoError(t, policies.ExpandDynamicValues(rules, userCtx),
			"ExpandDynamicValues should not error")
		require.Equal(t, "smb://h/bob", rules["dconf"][0].Value, "enabled entry should be expanded")
		require.Equal(t, "${TYPO}", rules["dconf"][1].Value, "disabled entry should be left untouched")
		require.Equal(t, "smb://h/bob/data", rules["mount"][0].Value, "mount entry should be expanded")
	})

	t.Run("Returns an error on an unknown variable in an enabled entry", func(t *testing.T) {
		t.Parallel()

		rules := map[string][]entry.Entry{
			"dconf": {{Key: "com/x/a", Value: "${TYPO}"}},
		}
		require.Error(t, policies.ExpandDynamicValues(rules, userCtx),
			"ExpandDynamicValues should error on an unknown variable")
	})
}

// TestExpandDynamicValuesKeepsGPOsRaw protects the cache invariant: expanding the
// rules returned by GetUniqueRules must not mutate the underlying GPOs, so the
// policies cache keeps the admin's original templated values.
func TestExpandDynamicValuesKeepsGPOsRaw(t *testing.T) {
	t.Parallel()

	gpos := []policies.GPO{{
		ID:   "id",
		Name: "name",
		Rules: map[string][]entry.Entry{
			"dconf": {{Key: "com/x/a", Value: "smb://h/${USER}", Meta: "s"}},
		},
	}}

	pols, err := policies.New(context.Background(), gpos, "")
	require.NoError(t, err, "Setup: can't create policies")
	defer pols.Close()

	rules := pols.GetUniqueRules()
	require.NoError(t, policies.ExpandDynamicValues(rules, dynamicvalues.Context{User: "bob"}),
		"ExpandDynamicValues should not error")

	require.Equal(t, "smb://h/bob", rules["dconf"][0].Value, "returned rules should be expanded")
	require.Equal(t, "smb://h/${USER}", pols.GPOs[0].Rules["dconf"][0].Value,
		"underlying GPOs must keep the raw, un-expanded value")
}

func TestApplyPoliciesFailsOnUnknownDynamicValue(t *testing.T) {
	t.Parallel()

	bus := testutils.NewDbusConn(t)

	cacheDir := t.TempDir()
	runDir := t.TempDir()
	dconfDir := t.TempDir()

	hostname, err := os.Hostname()
	require.NoError(t, err, "Setup: failed to get hostname")

	m, err := policies.NewManager(bus, hostname, mockBackend{},
		policies.WithCacheDir(cacheDir),
		policies.WithRunDir(runDir),
		policies.WithDconfDir(dconfDir),
	)
	require.NoError(t, err, "Setup: couldn't create manager")

	// A dconf rule is never filtered out, so the invalid template is reached and
	// expansion fails before any manager goroutine starts.
	gpos := []policies.GPO{{
		ID:   "id",
		Name: "name",
		Rules: map[string][]entry.Entry{
			"dconf": {{Key: "com/x/a", Value: "${TYPO}", Meta: "s"}},
		},
	}}
	pols, err := policies.New(context.Background(), gpos, "")
	require.NoError(t, err, "Setup: can't create policies")
	defer pols.Close()

	err = m.ApplyPolicies(context.Background(), hostname, true, &pols)
	require.Error(t, err, "ApplyPolicies should fail when an entry has an unknown dynamic value")
}

package policies_test

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/consts"
	"github.com/ubuntu/adsys/internal/policies"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/testutils"
)

var update bool

func TestGetUniqueRules(t *testing.T) {
	t.Parallel()

	standardGPO := policies.GPO{ID: "standard", Name: "standard-name", Rules: map[string][]entry.Entry{
		"dconf": {
			{Key: "A", Value: "standardA"},
			{Key: "B", Value: "standardB"},
			{Key: "C", Value: "standardC"},
		}}}

	tests := map[string]struct {
		gpos []policies.GPO

		want map[string][]entry.Entry
	}{
		"One GPO": {
			gpos: []policies.GPO{standardGPO},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
				},
			}},
		"Order key ascii": {
			gpos: []policies.GPO{{ID: "standard", Name: "standard-name", Rules: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "Z", Value: "standardZ"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
				}}}},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
					{Key: "Z", Value: "standardZ"},
				},
			}},

		// Multiple domains cases
		"Multiple domains, same GPOs": {
			gpos: []policies.GPO{
				{ID: "gpomultidomain", Name: "gpomultidomain-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "A", Value: "standardA"},
						{Key: "B", Value: "standardB"},
						{Key: "C", Value: "standardC"},
					},
					"otherdomain": {
						{Key: "Key1", Value: "otherdomainKey1"},
						{Key: "Key2", Value: "otherdomainKey2"},
					}}}},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
				},
				"otherdomain": {
					{Key: "Key1", Value: "otherdomainKey1"},
					{Key: "Key2", Value: "otherdomainKey2"},
				},
			}},
		"Multiple domains, different GPOs": {
			gpos: []policies.GPO{standardGPO,
				{ID: "gpo2", Name: "gpo2-name", Rules: map[string][]entry.Entry{
					"otherdomain": {
						{Key: "Key1", Value: "otherdomainKey1"},
						{Key: "Key2", Value: "otherdomainKey2"},
					}}}},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
				},
				"otherdomain": {
					{Key: "Key1", Value: "otherdomainKey1"},
					{Key: "Key2", Value: "otherdomainKey2"},
				},
			}},
		"Same key in different domains are kept separated": {
			gpos: []policies.GPO{
				{ID: "gpoDomain1", Name: "gpoDomain1-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "Common", Value: "commonValueDconf"},
					},
					"otherdomain": {
						{Key: "Common", Value: "commonValueOtherDomain"},
					}}}},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "Common", Value: "commonValueDconf"},
				},
				"otherdomain": {
					{Key: "Common", Value: "commonValueOtherDomain"},
				},
			}},

		// Override cases
		// This is ordered for each type by key ascii order
		"Two policies, with overrides": {
			gpos: []policies.GPO{
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
					}}},
			},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "oneValueC"},
				},
			}},
		"Two policies, with reversed overrides": {
			gpos: []policies.GPO{
				standardGPO,
				{ID: "one-value", Name: "one-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						// this value will be overridden with the higher one
						{Key: "C", Value: "oneValueC"},
					}}},
			},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
				},
			}},
		"Two policies, no overrides": {
			gpos: []policies.GPO{
				{ID: "one-value", Name: "one-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "C", Value: "oneValueC"},
					}}},
				{ID: "user-only", Name: "user-only-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "A", Value: "userOnlyA"},
						{Key: "B", Value: "userOnlyB"},
					}}},
			},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "userOnlyA"},
					{Key: "B", Value: "userOnlyB"},
					{Key: "C", Value: "oneValueC"},
				},
			}},
		"Two policies, no overrides, reversed": {
			gpos: []policies.GPO{
				{ID: "user-only", Name: "user-only-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "A", Value: "userOnlyA"},
						{Key: "B", Value: "userOnlyB"},
					}}},
				{ID: "one-value", Name: "one-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "C", Value: "oneValueC"},
					}}},
			},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "userOnlyA"},
					{Key: "B", Value: "userOnlyB"},
					{Key: "C", Value: "oneValueC"},
				},
			}},

		"Disabled value overrides non disabled one": {
			gpos: []policies.GPO{
				{ID: "disabled-value", Name: "disabled-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "C", Value: "", Disabled: true},
					}}},
				standardGPO,
			},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Disabled: true},
				},
			}},
		"Disabled value is overridden": {
			gpos: []policies.GPO{
				standardGPO,
				{ID: "disabled-value", Name: "disabled-value-name", Rules: map[string][]entry.Entry{
					"dconf": {
						{Key: "C", Value: "", Disabled: true},
					}}},
			},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA"},
					{Key: "B", Value: "standardB"},
					{Key: "C", Value: "standardC"},
				},
			}},

		"More policies, with multiple overrides": {
			gpos: []policies.GPO{
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
			},
			want: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "userOnlyA"},
					{Key: "B", Value: "userOnlyB"},
					{Key: "C", Value: "oneValueC"},
				},
			}},

		// append/prepend cases
		"Append policy entry, one GPO": {
			gpos: []policies.GPO{
				{ID: "standard", Name: "standard-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "standardA", Strategy: entry.StrategyAppend},
					}}},
			},
			want: map[string][]entry.Entry{
				"domain": {
					{Key: "A", Value: "standardA", Strategy: entry.StrategyAppend},
				},
			}},
		"Append policy entry, one GPO, disabled key is ignored": {
			gpos: []policies.GPO{
				{ID: "standard", Name: "standard-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "standardA", Strategy: entry.StrategyAppend, Disabled: true},
					}}},
			},
			want: map[string][]entry.Entry{
				"domain": nil,
			}},
		"Append policy entry, multiple GPOs": {
			gpos: []policies.GPO{
				{ID: "closest", Name: "closest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "closest value", Strategy: entry.StrategyAppend},
					}}},
				{ID: "furthest", Name: "furthest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "furthest value", Strategy: entry.StrategyAppend},
					}}},
			},
			want: map[string][]entry.Entry{
				"domain": {
					{Key: "A", Value: "furthest value\nclosest value", Strategy: entry.StrategyAppend},
				},
			}},
		"Append policy entry, multiple GPOs, disabled key is ignored, first": {
			gpos: []policies.GPO{
				{ID: "closest", Name: "closest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "closest value", Strategy: entry.StrategyAppend, Disabled: true},
					}}},
				{ID: "furthest", Name: "furthest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "furthest value", Strategy: entry.StrategyAppend},
					}}},
			},
			want: map[string][]entry.Entry{
				"domain": {
					{Key: "A", Value: "furthest value", Strategy: entry.StrategyAppend},
				},
			}},
		"Append policy entry, multiple GPOs, disabled key is ignored, second": {
			gpos: []policies.GPO{
				{ID: "closest", Name: "closest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "closest value", Strategy: entry.StrategyAppend},
					}}},
				{ID: "furthest", Name: "furthest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "furthest value", Strategy: entry.StrategyAppend, Disabled: true},
					}}},
			},
			want: map[string][]entry.Entry{
				"domain": {
					{Key: "A", Value: "closest value", Strategy: entry.StrategyAppend},
				},
			}},
		"Append policy entry, closest meta wins": {
			gpos: []policies.GPO{
				{ID: "closest", Name: "closest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "closest value", Meta: "closest meta", Strategy: entry.StrategyAppend},
					}}},
				{ID: "furthest", Name: "furthest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "furthest value", Meta: "furthest meta", Strategy: entry.StrategyAppend},
					}}},
			},
			want: map[string][]entry.Entry{
				"domain": {
					{Key: "A", Value: "furthest value\nclosest value", Meta: "closest meta", Strategy: entry.StrategyAppend},
				},
			}},

		// Mix append and override: closest win
		"Mix meta on GPOs, furthest policy entry is append, closest is override": {
			gpos: []policies.GPO{
				{ID: "closest", Name: "closest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "closest value"},
					}}},
				{ID: "furthest", Name: "furthest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "furthest value", Strategy: entry.StrategyAppend},
					}}},
			},
			want: map[string][]entry.Entry{
				"domain": {
					{Key: "A", Value: "closest value"},
				},
			}},
		"Mix meta on GPOs, closest policy entry is append, furthest override is ignored": {
			gpos: []policies.GPO{
				{ID: "closest", Name: "closest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "closest value", Strategy: entry.StrategyAppend},
					}}},
				{ID: "furthest", Name: "furthest-name", Rules: map[string][]entry.Entry{
					"domain": {
						{Key: "A", Value: "furthest value"},
					}}},
			},
			want: map[string][]entry.Entry{
				"domain": {
					{Key: "A", Value: "closest value", Strategy: entry.StrategyAppend},
				},
			}},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			pols := policies.Policies{
				GPOs: tc.gpos,
			}
			got := pols.GetUniqueRules()
			require.Equal(t, tc.want, got, "GetUniqueRules returns expected policy entries with correct overrides")
		})
	}
}

func TestCachePolicies(t *testing.T) {
	pols := policies.Policies{
		GPOs: []policies.GPO{
			{ID: "one-value", Name: "one-value-name", Rules: map[string][]entry.Entry{
				"dconf": {
					{Key: "C", Value: "oneValueC"},
				}}},
			{ID: "standard", Name: "standard-name", Rules: map[string][]entry.Entry{
				"dconf": {
					{Key: "A", Value: "standardA", Meta: "My meta"},
					{Key: "B", Value: "standardB", Disabled: true},
					// this value will be overridden with the higher one
					{Key: "C", Value: "standardC"},
				}}},
		},
	}

	p := filepath.Join(t.TempDir(), "policies-cache")
	err := pols.Save(p)
	require.NoError(t, err, "Save policies without error")

	got, err := policies.NewFromCache(p)
	require.NoError(t, err, "Got policies without error")

	require.Equal(t, pols, got, "Reloaded policies after caching should be the same")
}

func TestMain(m *testing.M) {
	flag.BoolVar(&update, "update", false, "update golden files")
	flag.Parse()

	// Don’t setup samba or sssd for mock helpers
	if !strings.Contains(strings.Join(os.Args, " "), "TestMock") {
		// Ubuntu Advantage
		defer testutils.StartLocalSystemBus()()

		conn, err := dbus.SystemBusPrivate()
		if err != nil {
			log.Fatalf("Setup: can’t get a private system bus: %v", err)
		}
		defer func() {
			if err = conn.Close(); err != nil {
				log.Fatalf("Teardown: can’t close system dbus connection: %v", err)
			}
		}()
		if err = conn.Auth(nil); err != nil {
			log.Fatalf("Setup: can’t auth on private system bus: %v", err)
		}
		if err = conn.Hello(); err != nil {
			log.Fatalf("Setup: can’t send hello message on private system bus: %v", err)
		}

		intro := fmt.Sprintf(`
		<node>
			<interface name="%s">
				<property name='Status' type='s' access="readwrite"/>
			</interface>%s%s</node>`, consts.SubcriptionDbusInterface, introspect.IntrospectDataString, prop.IntrospectDataString)
		ua := struct{}{}
		if err := conn.Export(ua, consts.SubcriptionDbusObjectPath, consts.SubcriptionDbusInterface); err != nil {
			log.Fatalf("Setup: could not export subscription object: %v", err)
		}

		propsSpec := map[string]map[string]*prop.Prop{
			consts.SubcriptionDbusInterface: {
				"Status": {
					Value:    "",
					Writable: true,
					Emit:     prop.EmitTrue,
					Callback: func(c *prop.Change) *dbus.Error { return nil },
				},
			},
		}
		_, err = prop.Export(conn, consts.SubcriptionDbusObjectPath, propsSpec)
		if err != nil {
			log.Fatalf("Setup: could not export property for subscription object: %v", err)
		}

		if err := conn.Export(introspect.Introspectable(intro), consts.SubcriptionDbusObjectPath,
			"org.freedesktop.DBus.Introspectable"); err != nil {
			log.Fatalf("Setup: could not export introspectable subscription object: %v", err)
		}

		reply, err := conn.RequestName(consts.SubcriptionDbusRegisteredName, dbus.NameFlagDoNotQueue)
		if err != nil {
			log.Fatalf("Setup: Failed to acquire sssd name on local system bus: %v", err)
		}
		if reply != dbus.RequestNameReplyPrimaryOwner {
			log.Fatalf("Setup: Failed to acquire sssd name on local system bus: name is already taken")
		}
	}

	m.Run()
}

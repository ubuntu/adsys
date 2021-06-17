package adsysservice_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/adsysservice"
	"github.com/ubuntu/adsys/internal/authorizer"
)

type mockAuthorizer struct {
}

func (mockAuthorizer) IsAllowedFromContext(context.Context, authorizer.Action) error {
	return nil
}

type sssd struct{}

func (s sssd) ActiveServer(_ string) (string, *dbus.Error) {
	return "my-discovered-url", nil
}

func TestNew(t *testing.T) {
	t.Parallel()

	const intro = `
	<node>
		<interface name="org.freedesktop.sssd.infopipe.Domains.Domain">
			<method name="ActiveServer">
				<arg direction="in" type="s"/>
				<arg direction="out" type="s"/>
			</method>
		</interface>` + introspect.IntrospectDataString + `</node>`

	conn := newDbusConn(t)
	var sssdDomain sssd
	conn.Export(sssdDomain, "/org/freedesktop/sssd/infopipe/Domains/fordiscovery_2ecom", "org.freedesktop.sssd.infopipe.Domains.Domain")
	conn.Export(introspect.Introspectable(intro), "/org/freedesktop/sssd/infopipe/Domains/fordiscovery_2ecom",
		"org.freedesktop.DBus.Introspectable")
	reply, err := conn.RequestName("org.freedesktop.sssd.infopipe", dbus.NameFlagDoNotQueue)
	require.NoError(t, err, "Setup: Failed to aquire sssd name on local system bus")
	if reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("Setup: Failed to aquire sssd name on local system bus: name is already taken")
	}

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

		// unexisting sssd with domain or existing sssd without ad_server is the same code path
		"AD server in discovery mode": {readUnexistingSssdConf: true, domain: "fordiscovery.com"},

		// Error cases
		"Ad New fails prevents adsysservice creation":               {url: "my-ldap-url", domain: "example.com", AdNewFail: true, existingAdsysDirs: true, wantNewErr: true},
		"No url and domain while sssdconf does not exists":          {readUnexistingSssdConf: true, wantNewErr: true},
		"No url can be found in discovery mode but we had a domain": {readUnexistingSssdConf: true, domain: "example.com", wantNewErr: true},
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

			auth := mockAuthorizer{}

			if tc.AdNewFail {
				err := os.Chmod(adsysCacheDir, 0000)
				require.NoError(t, err, "Setup: Could not prevent writing to cache directory")
				defer func() {
					err := os.Chmod(adsysCacheDir, 0700)
					require.NoError(t, err, "Teardown: Could not restore writing to cache directory")
				}()
			}

			options := []adsysservice.Option{
				adsysservice.WithCacheDir(adsysCacheDir),
				adsysservice.WithRunDir(adsysRunDir),
				adsysservice.WithDconfDir(dconfDir),
				adsysservice.WithSSSCacheDir(sssCacheDir),
				adsysservice.WithMockAuthorizer(&auth),
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

// newDbusConn returns a system dbus connection which will be tore down when tests ends
func newDbusConn(t *testing.T) *dbus.Conn {
	t.Helper()

	bus, err := dbus.SystemBusPrivate()
	require.NoError(t, err, "Setup: can’t get a private system bus")

	t.Cleanup(func() {
		err = bus.Close()
		require.NoError(t, err, "Teardown: can’t close system dbus connection")
	})
	err = bus.Auth(nil)
	require.NoError(t, err, "Setup: can’t auth on private system bus")
	err = bus.Hello()
	require.NoError(t, err, "Setup: can’t send hello message on private system bus")

	return bus
}

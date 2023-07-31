package adsysservice_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/ad/backends/sss"
	"github.com/ubuntu/adsys/internal/ad/backends/winbind"
	"github.com/ubuntu/adsys/internal/adsysservice"
	"github.com/ubuntu/adsys/internal/consts"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestNew(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		backend  string
		sssdConf string

		roDir             string
		existingAdsysDirs bool

		wantBackend string
		wantNewErr  bool
	}{
		"New and Quit succeeds and defaults to sssd, first run": {wantBackend: "sssd"},
		"Adsys directory can already exists":                    {existingAdsysDirs: true, wantBackend: "sssd"},

		// Backend selection
		"Unknown backend defaults to sssd":  {backend: "unknown-backend", wantBackend: "sssd"},
		"Select sssd backend explicitly":    {backend: "sssd", wantBackend: "sssd"},
		"Select winbind backend explicitly": {backend: "winbind", wantBackend: "winbind"},

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
			adsysStateDir := filepath.Join(temp, "var", "lib")
			adsysRunDir := filepath.Join(temp, "parentrun", "run")
			dconfDir := filepath.Join(temp, "dconf")
			sudoersDir := filepath.Join(temp, "sudoers.d")
			policyKitDir := filepath.Join(temp, "polkit-1")
			apparmorDir := filepath.Join(temp, "apparmor.d", "adsys")
			apparmorFsDir := filepath.Join(temp, "apparmorfs")
			globalTrustDir := filepath.Join(temp, "ca-certificates")
			if tc.existingAdsysDirs {
				require.NoError(t, os.MkdirAll(adsysCacheDir, 0700), "Setup: could not create adsys cache directory")
				require.NoError(t, os.MkdirAll(adsysRunDir, 0700), "Setup: could not create adsys run directory")
			}

			sssdConfig := sss.Config{
				Conf:     tc.sssdConf,
				CacheDir: t.TempDir(),
			}

			winbindConfig := winbind.Config{
				ADServer: "dc.example.com",
				ADDomain: "example.com",
			}

			if tc.roDir != "" {
				dest := filepath.Join(temp, tc.roDir)
				require.NoError(t, os.MkdirAll(dest, 0700), "Setup: can't create directory to make it Read Only")
				testutils.MakeReadOnly(t, dest)
			}

			options := []adsysservice.Option{
				adsysservice.WithCacheDir(adsysCacheDir),
				adsysservice.WithStateDir(adsysStateDir),
				adsysservice.WithRunDir(adsysRunDir),
				adsysservice.WithDconfDir(dconfDir),
				adsysservice.WithSudoersDir(sudoersDir),
				adsysservice.WithPolicyKitDir(policyKitDir),
				adsysservice.WithApparmorDir(apparmorDir),
				adsysservice.WithApparmorFsDir(apparmorFsDir),
				adsysservice.WithGlobalTrustDir(globalTrustDir),
				adsysservice.WithSSSConfig(sssdConfig),
				adsysservice.WithWinbindConfig(winbindConfig),
			}

			if tc.backend != "" {
				options = append(options, adsysservice.WithADBackend(tc.backend))
			}

			s, err := adsysservice.New(context.Background(), options...)
			if tc.wantNewErr {
				require.Error(t, err, "New should return an error but did not")
				return
			}
			require.NoError(t, err, "New should not return an error")

			// This needs to be last as it closes the underlying dbus connection
			defer s.Quit(context.Background())

			_, err = os.Stat(adsysCacheDir)
			require.NoError(t, err, "adsys cache directory exists as expected")
			_, err = os.Stat(adsysRunDir)
			require.NoError(t, err, "adsys run directory exists as expected")

			require.Equal(t, tc.wantBackend, s.SelectedBackend(), "Backend is the expected one")
		})
	}
}

func TestMain(m *testing.M) {
	// export SSSD domain
	defer testutils.StartLocalSystemBus()()

	conn, err := dbus.SystemBusPrivate()
	if err != nil {
		log.Fatalf("Setup: can't get a private system bus: %v", err)
	}
	defer func() {
		if err = conn.Close(); err != nil {
			log.Fatalf("Teardown: can't close system dbus connection: %v", err)
		}
	}()
	if err = conn.Auth(nil); err != nil {
		log.Fatalf("Setup: can't auth on private system bus: %v", err)
	}
	if err = conn.Hello(); err != nil {
		log.Fatalf("Setup: can't send hello message on private system bus: %v", err)
	}
	intro := fmt.Sprintf(`
	<node>
		<interface name="%s">
			<method name="ActiveServer">
				<arg direction="in" type="s"/>
				<arg direction="out" type="s"/>
			</method>
			<method name="IsOnline">
				<arg direction="out" type="b"/>
			</method>
		</interface>̀%s</node>`, consts.SSSDDbusInterface, introspect.IntrospectDataString)

	endpoint := "example_2ecom"
	ssss := sssdbus{}
	if err := conn.Export(ssss, dbus.ObjectPath(consts.SSSDDbusBaseObjectPath+"/"+endpoint), consts.SSSDDbusInterface); err != nil {
		log.Fatalf("Setup: could not export %s %v", endpoint, err)
	}
	if err := conn.Export(introspect.Introspectable(intro), dbus.ObjectPath(consts.SSSDDbusBaseObjectPath+"/"+endpoint),
		"org.freedesktop.DBus.Introspectable"); err != nil {
		log.Fatalf("Setup: could not export introspectable for %s: %v", endpoint, err)
	}
	reply, err := conn.RequestName(consts.SSSDDbusRegisteredName, dbus.NameFlagDoNotQueue)
	if err != nil {
		log.Fatalf("Setup: Failed to acquire sssd name on local system bus: %v", err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		log.Fatalf("Setup: Failed to acquire sssd name on local system bus: name is already taken")
	}

	// systemd starts time
	propsSpec := map[string]map[string]*prop.Prop{
		consts.SystemdDbusManagerInterface: {
			"GeneratorsStartTimestamp": {
				Value:    uint64(1234),
				Writable: false,
				Emit:     prop.EmitTrue,
				Callback: func(c *prop.Change) *dbus.Error {
					return nil
				},
			},
		},
	}
	err = conn.Export(struct{}{}, consts.SystemdDbusObjectPath, consts.SystemdDbusManagerInterface)
	if err != nil {
		log.Fatalf("Setup: Failed to export systemd object on local system bus: %v", err)
	}
	_, err = prop.Export(conn, consts.SystemdDbusObjectPath, propsSpec)
	if err != nil {
		log.Fatalf("Setup: Failed to export property for systemd object on local system bus: %v", err)
	}
	reply, err = conn.RequestName(consts.SystemdDbusRegisteredName, dbus.NameFlagDoNotQueue)
	if err != nil {
		log.Fatalf("Setup: Failed to acquire systemd name on local system bus: %v", err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		log.Fatalf("Setup: Failed to acquire systemd name on local system bus: name is already taken")
	}

	m.Run()
}

type sssdbus struct{}

func (s sssdbus) ActiveServer(_ string) (string, *dbus.Error) {
	return "", dbus.NewError("something.sssd.Error", []interface{}{"This is not used"})
}

func (s sssdbus) IsOnline() (bool, *dbus.Error) {
	return true, nil
}

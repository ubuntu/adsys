package sss_test

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/ad/backends/sss"
	"github.com/ubuntu/adsys/internal/consts"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestNew(t *testing.T) {
	t.Parallel()

	bus := testutils.NewDbusConn(t)

	tests := map[string]struct {
		sssdConf     string
		sssdCacheDir string

		wantErr bool
	}{
		"Regular config":               {sssdConf: "example.com"},
		"Multiple domains, pick first": {sssdConf: "multiple-domains"},

		// Active server cases
		"Ad server defined in config has priority over active server": {sssdConf: "example.com-with-server"},
		"Ad server defined in config does not need active server":     {sssdConf: "no-active-server-example.com-with-server"},
		"Ad server starting with ldap prefix does not stutter":        {sssdConf: "example.com-with-server-start-ldap"},

		// Special cases
		"SSSd domain can not match ad domain":                      {sssdConf: "domain-no-match-addomain"},
		"DBUS service not needed when we don’t need active server": {sssdConf: "domain-without-dbus.example.com-with-server"},
		"Default domain suffix is read":                            {sssdConf: "example.com-with-default-domain-suffix"},

		// Special cases for config parameters
		"Regular config, with cache dir": {sssdConf: "example.com", sssdCacheDir: "/some/specific/cachedir"},
		// Depending on the computer setup, this is using default /etc/sssd/sssd.conf,
		// So, it can fails or work. Decide depending on the file existence.
		"No sssd conf loads the default": {sssdConf: ""},

		// Error cases
		"Error on sssd conf does not exists":                    {sssdConf: "does_no_exists", wantErr: true},
		"Error on no domains field":                             {sssdConf: "no-domains", wantErr: true},
		"Error on empty domains field":                          {sssdConf: "empty-domains", wantErr: true},
		"Error on no sssd section":                              {sssdConf: "no-sssd-section", wantErr: true},
		"Error on sssd domain section missing":                  {sssdConf: "sssddomain-missing", wantErr: true},
		"Error on no config nor active server provided":         {sssdConf: "no-active-server-example.com", wantErr: true},
		"Error on active server erroring out":                   {sssdConf: "active-server-err.example.com", wantErr: true},
		"Error on no DBUS service when active server is needed": {sssdConf: "domain-without-dbus.example.com", wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			config := sss.Config{}
			if tc.sssdConf != "" {
				config.Conf = filepath.Join("testdata", "configs", tc.sssdConf)
			} else {
				// We are using the default, depending on the machine, this can fails if it doesn't exist
				if _, err := os.Stat(consts.DefaultSSSConf); errors.Is(err, os.ErrNotExist) {
					tc.wantErr = true
				}
			}

			if tc.sssdCacheDir != "" {
				config.CacheDir = tc.sssdCacheDir
			}

			sssd, err := sss.New(context.Background(), config, bus)
			if tc.wantErr {
				require.Error(t, err, "New should have errored out")
				return
			}
			require.NoError(t, err, "New should return no error")

			if tc.sssdConf == "" {
				return // nothing else we can check on the machine's default sssd conf
			}

			var got bytes.Buffer
			got.WriteString(fmt.Sprintf("* Domain(): %s\n", sssd.Domain()))
			got.WriteString(fmt.Sprintf("* ServerURL(): %s\n", sssd.ServerURL()))
			got.WriteString(fmt.Sprintf("* HostKrb5CCNAME(): %s\n", sssd.HostKrb5CCNAME()))
			got.WriteString(fmt.Sprintf("* DefaultDomainSuffix(): %s\n", sssd.DefaultDomainSuffix()))
			got.WriteString(fmt.Sprintf("* Config():\n%s\n", sssd.Config()))

			want := testutils.LoadWithUpdateFromGolden(t, got.String())
			require.Equal(t, want, got.String(), "Got expected loaded values in sssd config object")
		})
	}
}

func TestIsOnline(t *testing.T) {
	t.Parallel()

	bus := testutils.NewDbusConn(t)

	tests := map[string]struct {
		sssdConf string

		wantOnline bool
		wantErr    bool
	}{
		"Is online":     {sssdConf: "example.com", wantOnline: true},
		"Is not online": {sssdConf: "offline-example.com", wantOnline: false},

		// Error cases
		"Error on IsOnline dbus call failing":                   {sssdConf: "is-online-err-example.com", wantErr: true},
		"Error on no DBUS service when IsOnline dbus is called": {sssdConf: "domain-without-dbus.example.com-with-server", wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			config := sss.Config{
				Conf: filepath.Join("testdata", "configs", tc.sssdConf),
			}

			sssd, err := sss.New(context.Background(), config, bus)
			require.NoError(t, err, "New should return no error")

			got, err := sssd.IsOnline()
			if tc.wantErr {
				require.Error(t, err, "IsOnline should have errored out")
				return
			}
			require.NoError(t, err, "IsOnline should return no error")

			require.Equal(t, tc.wantOnline, got, "IsOnline should return expected online state")
		})
	}
}

type sssdus struct {
	endpoint       string
	offline        bool
	noActiveServer bool

	activeServerErr bool
	isOnlineErr     bool
}

func (s sssdus) ActiveServer(_ string) (string, *dbus.Error) {
	if s.noActiveServer {
		return "", nil
	}
	if s.activeServerErr {
		return "", dbus.NewError("something.sssd.Error", []interface{}{"Active Server dbus call Error"})
	}
	return "dynamic_active_server." + strings.ReplaceAll(s.endpoint, "_2e", "."), nil
}

func (s sssdus) IsOnline() (bool, *dbus.Error) {
	if s.isOnlineErr {
		return false, dbus.NewError("something.sssd.Error", []interface{}{"IsOnline dbus call Error"})
	}
	return !s.offline, nil
}

func TestMain(m *testing.M) {
	testutils.InstallUpdateFlag()
	// TODO: do we want to alway print debug?
	debug := flag.Bool("verbose", false, "Print debug log level information within the test")
	flag.Parse()
	if *debug {
		logrus.StandardLogger().SetLevel(logrus.DebugLevel)
	}

	// export SSSD domains
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

	for _, s := range []sssdus{
		{
			endpoint: "example_2ecom",
		},
		{
			endpoint: "offline_2eexample_2ecom",
			offline:  true,
		},
		{
			endpoint:       "noactiveserver_2eexample_2ecom",
			noActiveServer: true,
		},
		{
			endpoint:        "activeservererr_2eexample_2ecom",
			activeServerErr: true,
		},
		{
			endpoint:    "isonlineerr_2eexample_2ecom",
			isOnlineErr: true,
		},
	} {
		if err := conn.Export(s, dbus.ObjectPath(consts.SSSDDbusBaseObjectPath+"/"+s.endpoint), consts.SSSDDbusInterface); err != nil {
			log.Fatalf("Setup: could not export %s %v", s.endpoint, err)
		}
		if err := conn.Export(introspect.Introspectable(intro), dbus.ObjectPath(consts.SSSDDbusBaseObjectPath+"/"+s.endpoint),
			"org.freedesktop.DBus.Introspectable"); err != nil {
			log.Fatalf("Setup: could not export introspectable for %s: %v", s.endpoint, err)
		}
	}
	reply, err := conn.RequestName(consts.SSSDDbusRegisteredName, dbus.NameFlagDoNotQueue)
	if err != nil {
		log.Fatalf("Setup: Failed to acquire sssd name on local system bus: %v", err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		log.Fatalf("Setup: Failed to acquire sssd name on local system bus: name is already taken")
	}

	m.Run()
}

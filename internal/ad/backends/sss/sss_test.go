package sss_test

import (
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

func TestSSSD(t *testing.T) {
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

		// IsOnline case
		"Is not online": {sssdConf: "offline-example.com"},

		// Special cases
		"Can handle special DNS domain characters": {sssdConf: "special-characters.example.com"},
		"SSSd domain can not match ad domain":      {sssdConf: "domain-no-match-addomain"},
		"Default domain suffix is read":            {sssdConf: "example.com-with-default-domain-suffix"},
		"Use domain from section if no ad_domain":  {sssdConf: "example.com-without-ad_domain"},
		"Ignore upper cases in domain name":        {sssdConf: "EXAMPLE.COM"},

		// Special cases for config parameters
		"Regular config, with cache dir": {sssdConf: "example.com", sssdCacheDir: "/some/specific/cachedir"},
		// Depending on the computer setup, this is using default /etc/sssd/sssd.conf,
		// So, it can fails or work. Decide depending on the file existence.
		"No sssd conf loads the default": {sssdConf: ""},

		// ServerFQDN error cases (this doesn't fail New)
		"ServerFQDN() does not fail when we do not need an active server":        {sssdConf: "active-server-err.example.com-with-server"},
		"Error returned by ServerFQDN() on no config nor active server provided": {sssdConf: "no-active-server-example.com"},
		"Error returned by ServerFQDN() when calls is erroring out":              {sssdConf: "active-server-err.example.com"},

		// IsOnline error case (this doesn't fail New)
		"Error returned by IsOnline()  when calls is erroring out": {sssdConf: "is-online-err-example.com"},

		// Common ServerFQDN and IsOnline error cases (this doesn't fail New)
		"Error returned by ServerFQDN() and IsOnline() when DBUS has no object": {sssdConf: "domain-without-dbus.example.com"},

		// Error cases
		"Error on sssd conf does not exists":   {sssdConf: "does_no_exists", wantErr: true},
		"Error on no domains field":            {sssdConf: "no-domains", wantErr: true},
		"Error on empty domains field":         {sssdConf: "empty-domains", wantErr: true},
		"Error on no sssd section":             {sssdConf: "no-sssd-section", wantErr: true},
		"Error on sssd domain section missing": {sssdConf: "sssddomain-missing", wantErr: true},
		"Error on sssd domain empty section":   {sssdConf: "sssddomain-empty-section", wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			config := sss.Config{}
			if tc.sssdConf != "" {
				config.Conf = filepath.Join(testutils.TestFamilyPath(t), "configs", tc.sssdConf)
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

			got := testutils.FormatBackendCalls(t, sssd)
			want := testutils.LoadWithUpdateFromGolden(t, got)
			require.Equal(t, want, got, "Got expected loaded values in sssd config object")
		})
	}
}

type sssdbus struct {
	endpoint       string
	offline        bool
	noActiveServer bool

	activeServerErr bool
	isOnlineErr     bool
}

func (s sssdbus) ActiveServer(_ string) (string, *dbus.Error) {
	if s.noActiveServer {
		return "", nil
	}
	if s.activeServerErr {
		return "", dbus.NewError("something.sssd.Error", []interface{}{"Active Server dbus call Error"})
	}
	return "dynamic_active_server." + strings.ReplaceAll(strings.ReplaceAll(s.endpoint, "_2e", "."), "_2d", "-"), nil
}

func (s sssdbus) IsOnline() (bool, *dbus.Error) {
	if s.isOnlineErr {
		return false, dbus.NewError("something.sssd.Error", []interface{}{"IsOnline dbus call Error"})
	}
	return !s.offline, nil
}

func TestMain(m *testing.M) {
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

	for _, s := range []sssdbus{
		{
			endpoint: "example_2ecom",
		},
		{
			endpoint: "special_2dcharacters_2eexample_2ecom",
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

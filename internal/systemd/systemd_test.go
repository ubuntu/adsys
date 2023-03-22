package systemd_test

import (
	"context"
	"flag"
	"fmt"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/consts"
	"github.com/ubuntu/adsys/internal/systemd"
	"github.com/ubuntu/adsys/internal/testutils"
)

var ctx = context.Background()

func TestManageUnit(t *testing.T) {
	t.Parallel()

	bus := testutils.NewDbusConn(t)

	systemdCaller, err := systemd.New(bus)
	require.NoError(t, err, "Setup: failed to create systemd caller")

	tests := map[string]struct {
		unitName string
		action   string

		wantErr bool
	}{
		"Start unit that exists":   {action: "start"},
		"Stop unit that exists":    {action: "stop"},
		"Enable unit that exists":  {action: "enable"},
		"Disable unit that exists": {action: "disable"},

		// Error cases
		"Error when starting unit that doesn't exist": {unitName: absentUnit, action: "start", wantErr: true},
		"Error when starting failing unit":            {unitName: failingUnit, action: "start", wantErr: true},

		"Error when stopping unit that doesn't exist": {unitName: absentUnit, action: "stop", wantErr: true},
		"Error when stopping failing unit":            {unitName: failingUnit, action: "stop", wantErr: true},

		"Error when enabling unit that doesn't exist":  {unitName: absentUnit, action: "enable", wantErr: true},
		"Error when disabling unit that doesn't exist": {unitName: absentUnit, action: "disable", wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if tc.unitName == "" {
				tc.unitName = "existing-service.service"
			}

			var err error
			switch tc.action {
			case "start":
				err = systemdCaller.StartUnit(ctx, tc.unitName)
			case "stop":
				err = systemdCaller.StopUnit(ctx, tc.unitName)
			case "enable":
				err = systemdCaller.EnableUnit(ctx, tc.unitName)
			case "disable":
				err = systemdCaller.DisableUnit(ctx, tc.unitName)
			default:
				panic("unknown systemd action")
			}

			if tc.wantErr {
				require.Error(t, err, fmt.Sprintf("Action %s should have failed but it didn't", tc.action))
				return
			}
			require.NoError(t, err, fmt.Sprintf("Action %s shouldn't have failed but it did", tc.action))
		})
	}
}

func TestDaemonReload(t *testing.T) {
	t.Parallel()

	bus := testutils.NewDbusConn(t)

	systemdCaller, err := systemd.New(bus)
	require.NoError(t, err, "Setup: failed to create systemd caller")

	err = systemdCaller.DaemonReload(ctx)
	require.NoError(t, err, "DaemonReload shouldn't have failed but it did")

	s.setErrorOnReload()

	err = systemdCaller.DaemonReload(ctx)
	require.Error(t, err, "DaemonReload should have failed but it didn't")
}

func TestMain(m *testing.M) {
	// export systemd structure
	defer testutils.StartLocalSystemBus()()

	debug := flag.Bool("verbose", false, "Print debug log level information within the test")
	flag.Parse()

	var connOpts []dbus.ConnOption
	if *debug {
		log.SetLevel(log.DebugLevel)
		log.SetFormatter(&log.TextFormatter{
			DisableTimestamp: true,
			DisableQuote:     true,
		})

		connOpts = append(connOpts,
			dbus.WithIncomingInterceptor(func(msg *dbus.Message) {
				log.Debug("DBUS <-:", msg)
			}),
			dbus.WithOutgoingInterceptor(func(msg *dbus.Message) {
				log.Debug("DBUS ->:", msg)
			}),
		)
	}

	conn, err := dbus.SystemBusPrivate(connOpts...)
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

	s = systemdBus{conn: conn}

	// Export methods
	if err := conn.Export(&s, dbus.ObjectPath(consts.SystemdDbusObjectPath), consts.SystemdDbusManagerInterface); err != nil {
		log.Fatalf("Setup: could not export systemd object %v", err)
	}
	if err = conn.Export(introspect.NewIntrospectable(&introspect.Node{
		Name: consts.SystemdDbusObjectPath,
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			{
				Name:    consts.SystemdDbusManagerInterface,
				Methods: introspect.Methods(&s),
			},
		},
	}), consts.SystemdDbusObjectPath, introspect.IntrospectData.Name); err != nil {
		log.Fatalf("Setup: could not export systemd introspection object %v", err)
	}

	// Request systemd name
	reply, err := conn.RequestName(consts.SystemdDbusRegisteredName, dbus.NameFlagDoNotQueue)
	if err != nil {
		log.Fatalf("Setup: Failed to acquire systemd name on local system bus: %v", err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		log.Fatalf("Setup: Failed to acquire systemd name on local system bus: name is already taken")
	}

	m.Run()
}

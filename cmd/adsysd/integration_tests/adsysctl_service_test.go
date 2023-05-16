package adsys_test

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/termie/go-shutil"
	"github.com/ubuntu/adsys/cmd/adsysd/client"
	"github.com/ubuntu/adsys/cmd/adsysd/daemon"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestServiceStop(t *testing.T) {
	tests := map[string]struct {
		daemonAnswer     string
		daemonNotStarted bool
		force            bool

		wantErr bool
	}{
		"Stop daemon": {daemonAnswer: "polkit_yes"},

		"Force stop doesn’t exit on error": {daemonAnswer: "polkit_yes", force: true, wantErr: false},

		// Error cases
		"Error on stop daemon denied":    {daemonAnswer: "polkit_no", wantErr: true},
		"Error on daemon not responding": {daemonNotStarted: true, wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			dbusAnswer(t, tc.daemonAnswer)

			conf := createConf(t)
			if !tc.daemonNotStarted {
				defer runDaemon(t, conf)()
			}

			args := []string{"service", "stop"}
			if tc.force {
				args = append(args, "-f")
			}
			out, err := runClient(t, conf, args...)
			assert.Empty(t, out, "Nothing printed on stdout")
			if tc.wantErr {
				require.Error(t, err, "client should exit with an error")
				return
			}
			require.NoError(t, err, "client should exit with no error")
		})
	}
}

func TestServiceStopWaitForHangingClient(t *testing.T) {
	dbusAnswer(t, "polkit_yes")

	conf := createConf(t)
	d := daemon.New()
	changeAppArgs(t, d, conf)

	daemonStopped := make(chan struct{})
	go func() {
		defer close(daemonStopped)
		err := d.Run()
		require.NoError(t, err, "daemon should exit with no error")
	}()
	d.WaitReady()

	outCat, stopCat, err := startCmd(t, false, "adsysctl", "-vv", "-c", conf, "service", "cat")
	require.NoError(t, err, "cat should start successfully")

	// Let cat connecting to daemon and daemon forwarding logs
	time.Sleep(time.Second)

	// Stop without forcing: shouldn’t be able to stop it
	_, stopStop, err := startCmd(t, false, "adsysctl", "-c", conf, "service", "stop")
	require.NoError(t, err, "stop should start successfully (graceful stop requested)")
	defer stopStop()

	// Let’s wait 5 seconds to ensure it hadn’t stopped
	select {
	case <-daemonStopped:
		log.Fatal("Daemon stopped when we expected to hang out")
	case <-time.After(5 * time.Second):
	}

	stopCat()
	assert.NotEmpty(t, outCat(), "Cat has captured some outputs")

	// Let’s give it 3 seconds to stop
	select {
	case <-time.After(3 * time.Second):
		log.Fatal("Daemon hadn’t stopped quickly once Cat has quit")
	case <-daemonStopped:
	}
}

func TestServiceStopForcedWithHangingClient(t *testing.T) {
	dbusAnswer(t, "polkit_yes")

	conf := createConf(t)
	d := daemon.New()
	changeAppArgs(t, d, conf)

	daemonStopped := make(chan struct{})
	go func() {
		defer close(daemonStopped)
		err := d.Run()
		require.NoError(t, err, "daemon should exit with no error")
	}()
	d.WaitReady()

	outCat, stopCat, err := startCmd(t, false, "adsysctl", "-vv", "-c", conf, "service", "cat")
	require.NoError(t, err, "cat should start successfully")

	// Let cat connecting to daemon and daemon forwarding logs
	time.Sleep(time.Second)

	// Force stop it
	_, _, err = startCmd(t, true, "adsysctl", "-c", conf, "service", "stop", "-f")
	require.NoError(t, err, "force stop should be successful")

	select {
	case <-time.After(3 * time.Second):
		t.Fatal("daemon should stop quickly after forced stop")
	case <-daemonStopped:
	}
	stopCat()
	assert.NotEmpty(t, outCat(), "Cat has captured some outputs")
}

func TestServiceCat(t *testing.T) {
	// Unfortunately, we can’t easily create the cat client and other pingers in the same process:
	// as cat will print what was forwarded to it, and the daemon, other clients and such will all write
	// also, this creates multiple calls, with overriding fds and such.

	// Keep coverage by either switching the daemon or the cat client in their own process.
	// Always keep version in its own process.

	tests := map[string]struct {
		systemAnswer     string
		daemonNotStarted bool
		coverCatClient   bool
		multipleCats     bool

		wantErr bool
	}{
		"Cat other clients and daemon - cover daemon": {systemAnswer: "polkit_yes"},
		"Cat other clients and daemon - cover client": {systemAnswer: "polkit_yes", coverCatClient: true},

		"Multiple cats": {multipleCats: true, systemAnswer: "polkit_yes"},

		// Error cases
		"Error on cat denied - cover daemon":            {systemAnswer: "polkit_no", wantErr: true},
		"Error on cat denied - cover client":            {systemAnswer: "polkit_no", coverCatClient: true, wantErr: true},
		"Error on daemon not responding - cover daemon": {daemonNotStarted: true, wantErr: true},
		"Error on daemon not responding - cover client": {daemonNotStarted: true, coverCatClient: true, wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			dbusAnswer(t, tc.systemAnswer)

			conf := createConf(t)
			if !tc.daemonNotStarted && !tc.coverCatClient {
				defer runDaemon(t, conf)()
			}

			if tc.coverCatClient {
				_, stopDaemon, err := startCmd(t, false, "adsysd", "-c", conf)
				require.NoError(t, err, "daemon should start successfully")
				defer stopDaemon()
				// Let the daemon starting
				time.Sleep(5 * time.Second)
			}

			var outCat, outCat2 func() string
			var stopCat, stopCat2 func()
			if tc.coverCatClient {
				// create cat client and control it, capturing stderr for logs

				// capture log output (set to stderr, but captured when loading logrus)
				r, w, err := os.Pipe()
				require.NoError(t, err, "Setup: pipe shouldn’t fail")
				orig := logrus.StandardLogger().Out
				logrus.StandardLogger().SetOutput(w)

				c := client.New()

				var out bytes.Buffer
				done := make(chan struct{})
				go func() {
					defer close(done)
					changeAppArgs(t, c, conf, "service", "cat")
					err = c.Run()
				}()

				outCat = func() string {
					return out.String()
				}
				stopCat = func() {
					c.Quit()
					<-done
					logrus.StandardLogger().SetOutput(orig)
					w.Close()
					_, errCopy := io.Copy(&out, r)
					require.NoError(t, errCopy, "Couldn’t copy stderr to buffer")
				}
			} else {
				var err error
				if tc.multipleCats {
					outCat2, stopCat2, err = startCmd(t, false, "adsysctl", "-vv", "-c", conf, "service", "cat")
					require.NoError(t, err, "cat should start successfully")
				}

				outCat, stopCat, err = startCmd(t, false, "adsysctl", "-vv", "-c", conf, "service", "cat")
				require.NoError(t, err, "cat should start successfully")
			}

			// Let cat connecting to daemon and daemon forwarding logs
			time.Sleep(time.Second)

			// Second client we will spy logs on
			_, _, err := startCmd(t, true, "adsysctl", "-vv", "-c", conf, "version")
			if !tc.wantErr {
				require.NoError(t, err, "version should run successfully")
			}

			stopCat()

			if tc.wantErr {
				assert.NotContains(t, outCat(), "New connection from client", "no internal logs from server are forwarded")
				assert.NotContains(t, outCat(), "New request /service/Version", "no debug logs for clients are forwarded")
				return
			}

			assert.Contains(t, outCat(), "New connection from client", "internal logs from server are forwarded")
			assert.Contains(t, outCat(), "New request /service/Version", "debug logs for clients are forwarded")

			if tc.multipleCats {
				// Give time for the server to forward first Cat closing
				time.Sleep(time.Second)
				stopCat2()

				assert.Contains(t, outCat2(), "New connection from client", "internal logs from server are forwarded")
				assert.Contains(t, outCat2(), "New request /service/Cat", "debug logs for the other cat is forwarded")
				assert.Contains(t, outCat2(), "Request /service/Cat done", "the other cat is closed")
				assert.Contains(t, outCat2(), "New request /service/Version", "debug logs for clients are forwarded")
			}
		})
	}
}

func TestServiceStatus(t *testing.T) {
	admock, err := filepath.Abs(filepath.Join(rootProjectDir, "internal/testutils/admock"))
	require.NoError(t, err, "Setup: Failed to get current absolute path for ad mock")
	t.Setenv("PYTHONPATH", admock)

	hostname, err := os.Hostname()
	require.NoError(t, err, "Setup: failed to get current user")

	tests := map[string]struct {
		systemAnswer        string
		sssdConf            string
		daemonNotStarted    bool
		noCacheUsersMachine bool
		krb5ccNoCache       bool

		wantErr bool
	}{
		"Status with users and machines":          {systemAnswer: "polkit_yes"},
		"Status offline cache":                    {sssdConf: "sssd.conf-offline", systemAnswer: "polkit_yes"},
		"Status no user connected and no machine": {noCacheUsersMachine: true, systemAnswer: "polkit_yes"},
		"Status is always authorized":             {systemAnswer: "polkit_no"},
		"Status on user connected with no cache":  {krb5ccNoCache: true, systemAnswer: "polkit_yes"},
		"Status with static AD server":            {sssdConf: "sssd.conf-example.com_static-server", systemAnswer: "polkit_yes"},
		"Status with empty dynamic AD server":     {sssdConf: "sssd.conf-online_no_active_server", systemAnswer: "polkit_yes"},

		// Refresh time exception
		"No startup time leads to unknown refresh time":           {systemAnswer: "no_startup_time"},
		"Invalid startup time leads to unknown refresh time":      {systemAnswer: "invalid_startup_time"},
		"No unit refresh time leads to unknown refresh time":      {systemAnswer: "no_nextrefresh_time"},
		"Invalid unit refresh time leads to unknown refresh time": {systemAnswer: "invalid_nextrefresh_time"},

		// Ubuntu pro subscription
		"Ubuntu Pro subscription is not active": {systemAnswer: "subscription_disabled"},

		// Error cases
		"Error on daemon not responding": {daemonNotStarted: true, wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			dbusAnswer(t, tc.systemAnswer)

			adsysDir := t.TempDir()
			cachedPoliciesDir := filepath.Join(adsysDir, "cache", "policies")
			conf := createConf(t, confWithAdsysDir(adsysDir))
			if tc.sssdConf != "" {
				content, err := os.ReadFile(conf)
				require.NoError(t, err, "Setup: can’t read configuration file")
				content = bytes.Replace(content, []byte("testdata/sssd-configs/sssd.conf-example.com"),
					[]byte(fmt.Sprintf("testdata/sssd-configs/%s", tc.sssdConf)), 1)
				err = os.WriteFile(conf, content, 0600)
				require.NoError(t, err, "Setup: can’t rewrite configuration file")
			}

			// copy machine gpo rules for first update
			if !tc.noCacheUsersMachine {
				err := os.MkdirAll(cachedPoliciesDir, 0700)
				require.NoError(t, err, "Setup: couldn't create policies directory: %v", err)
				require.NoError(t,
					shutil.CopyTree(
						filepath.Join("testdata", "TestPolicyApplied", "policies", "machine"),
						filepath.Join(cachedPoliciesDir, hostname),
						&shutil.CopyTreeOptions{Symlinks: true, CopyFunction: shutil.Copy}),
					"Setup: failed to copy machine policies cache")
			}

			if !tc.daemonNotStarted {
				defer runDaemon(t, conf)()
			}

			// Create users krb5cc and GPO caches
			if !tc.noCacheUsersMachine {
				krb5UserDir := filepath.Join(adsysDir, "run", "krb5cc", "tracking")
				err := os.MkdirAll(krb5UserDir, 0750)
				require.NoError(t, err, "Setup: could not create gpo cache dir: %v", err)
				for _, user := range []string{"user1@example.com", "user2@example.com"} {
					f, err := os.Create(filepath.Join(krb5UserDir, user))
					require.NoError(t, err, "Setup: could not create krb5 cache dir for %s: %v", user, err)
					f.Close()
					f, err = os.Create(filepath.Join(cachedPoliciesDir, user))
					require.NoError(t, err, "Setup: could not create gpo cache dir for %s: %v", user, err)
					f.Close()
				}
				// TODO: change modification time? (golden)
			}
			if tc.krb5ccNoCache {
				err := os.RemoveAll(cachedPoliciesDir)
				require.NoError(t, err, "Setup: can’t delete gpo rules cache directory")
			}

			got, err := runClient(t, conf, "service", "status")
			if tc.wantErr {
				require.Error(t, err, "client should exit with an error")
				return
			}
			require.NoError(t, err, "client should exit with no error")

			// Make paths suitable for golden recording and comparison
			re := regexp.MustCompile(`/tmp/.*/`)
			got = re.ReplaceAllString(got, "/tmp/")

			re = regexp.MustCompile(`(updated on)([^\n]*)`)
			got = re.ReplaceAllString(got, "$1 DDD MON D HH:MM")
			// Hardcode time for making next refresh time independent of current timezone, but still
			// check some values (day digit, month…)
			re = regexp.MustCompile(`(Next Refresh:) .* May 2.*([^\n]*)`)
			got = re.ReplaceAllString(got, "$1 Tue May 25 14:55")

			// Compare golden files
			want := testutils.LoadWithUpdateFromGolden(t, got)
			require.Equal(t, want, got, "Expected values to match")
		})
	}
}

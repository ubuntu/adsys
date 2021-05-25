package adsys_test

import (
	"bytes"
	"errors"
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
)

func TestServiceStop(t *testing.T) {
	tests := map[string]struct {
		daemonAnswer     string
		daemonNotStarted bool
		force            bool

		wantErr bool
	}{
		"Stop daemon":           {daemonAnswer: "yes"},
		"Stop daemon denied":    {daemonAnswer: "no", wantErr: true},
		"Daemon not responding": {daemonNotStarted: true, wantErr: true},

		"Force stop doesn’t exit on error": {daemonAnswer: "yes", force: true, wantErr: false},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			systemAnswer(t, tc.daemonAnswer)

			conf := createConf(t, "")
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
	systemAnswer(t, "yes")

	conf := createConf(t, "")
	d := daemon.New()
	changeOsArgs(t, conf)

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
	// Don’t use the helper as we don’t need stdout (and cat will trigger the stdout capturer in daemon logs)
	c := client.New()
	restoreArgs := changeOsArgs(t, conf, "service", "stop")
	err = c.Run()
	restoreArgs()
	require.NoError(t, err, "client should exit with no error (graceful stop requested)")

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
	systemAnswer(t, "yes")

	conf := createConf(t, "")
	d := daemon.New()
	changeOsArgs(t, conf)

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
	// Don’t use the helper as we don’t need stdout (and cat will trigger the stdout capturer in daemon logs)
	c := client.New()
	restoreArgs := changeOsArgs(t, conf, "service", "stop", "-f")
	err = c.Run()
	restoreArgs()
	require.NoError(t, err, "client should exit with no error")

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
		"Cat other clients and daemon - cover daemon": {systemAnswer: "yes"},
		"Cat denied - cover daemon":                   {systemAnswer: "no", wantErr: true},
		"Daemon not responding - cover daemon":        {daemonNotStarted: true, wantErr: true},

		"Cat other clients and daemon - cover client": {systemAnswer: "yes", coverCatClient: true},
		"Cat denied - cover client":                   {systemAnswer: "no", coverCatClient: true, wantErr: true},
		"Daemon not responding - cover client":        {daemonNotStarted: true, coverCatClient: true, wantErr: true},

		"Multiple cats": {multipleCats: true, systemAnswer: "yes"},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			systemAnswer(t, tc.systemAnswer)

			conf := createConf(t, "")
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
			var stopCat, stopCat2 func() error
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
					changeOsArgs(t, conf, "service", "cat")
					err = c.Run()
				}()

				outCat = func() string {
					return out.String()
				}
				stopCat = func() error {
					c.Quit()
					<-done
					logrus.StandardLogger().SetOutput(orig)
					w.Close()
					_, errCopy := io.Copy(&out, r)
					require.NoError(t, errCopy, "Couldn’t copy stderr to buffer")
					return errors.New("Mimic cat killing")
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

			err = stopCat()
			require.Error(t, err, "cat has been killed")

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
				err = stopCat2()
				require.Error(t, err, "cat2 has been killed")

				assert.Contains(t, outCat2(), "New connection from client", "internal logs from server are forwarded")
				assert.Contains(t, outCat2(), "New request /service/Cat", "debug logs for the other cat is forwarded")
				assert.Contains(t, outCat2(), "Request /service/Cat done", "the other cat is closed")
				assert.Contains(t, outCat2(), "New request /service/Version", "debug logs for clients are forwarded")
			}
		})
	}
}

func TestServiceStatus(t *testing.T) {

	admock, err := filepath.Abs("../../../internal/testutils/admock")
	require.NoError(t, err, "Setup: Failed to get current absolute path for ad mock")
	os.Setenv("PYTHONPATH", admock)

	hostname, err := os.Hostname()
	require.NoError(t, err, "Setup: failed to get current user")

	tests := map[string]struct {
		systemAnswer        string
		daemonNotStarted    bool
		noCacheUsersMachine bool
		krb5ccNoCache       bool
		isOffLine           bool

		wantErr bool
	}{
		"Status with users and machines":          {systemAnswer: "yes"},
		"Status offline cache":                    {isOffLine: true, systemAnswer: "yes"},
		"Status no user connected and no machine": {noCacheUsersMachine: true, systemAnswer: "yes"},
		"Status is always authorized":             {systemAnswer: "no"},
		"Status on user connected with no cache":  {krb5ccNoCache: true, systemAnswer: "yes"},

		// Refresh time exception
		"No startup time leads to unknown refresh time":           {systemAnswer: "no_startup_time"},
		"Invalid startup time leads to unknown refresh time":      {systemAnswer: "invalid_startup_time"},
		"No unit refresh time leads to unknown refresh time":      {systemAnswer: "no_nextrefresh_time"},
		"Invalid unit refresh time leads to unknown refresh time": {systemAnswer: "invalid_nextrefresh_time"},

		"Daemon not responding": {daemonNotStarted: true, wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			systemAnswer(t, tc.systemAnswer)

			adsysDir := t.TempDir()
			gpoRulesDir := filepath.Join(adsysDir, "cache", "gpo_rules")
			conf := createConf(t, adsysDir)
			if tc.isOffLine {
				content, err := os.ReadFile(conf)
				require.NoError(t, err, "Setup: can’t read configuration file")
				content = bytes.Replace(content, []byte("ldap://adc.example.com"), []byte("ldap://NT_STATUS_HOST_UNREACHABLE"), 1)
				err = os.WriteFile(conf, content, 0644)
				require.NoError(t, err, "Setup: can’t rewrite configuration file")
			}

			// copy machine gpo rules for first update
			if !tc.noCacheUsersMachine || tc.isOffLine {
				err := os.MkdirAll(gpoRulesDir, 0700)
				require.NoError(t, err, "Setup: couldn't create gpo_rules directory: %v", err)
				err = shutil.CopyFile("testdata/PolicyApplied/gpo_rules/machine.yaml", filepath.Join(gpoRulesDir, hostname), false)
				require.NoError(t, err, "Setup: failed to copy machine gporules cache")
			}

			if !tc.daemonNotStarted {
				defer runDaemon(t, conf)()
			}

			// Update will try to update the machine and will turn the daemon offline.
			if tc.isOffLine {
				_, err := runClient(t, conf, "policy", "update", "--all")
				require.NoError(t, err, "Setup: can't turn the daemon offline with first update")
			}

			// Create users krb5cc and GPO caches
			if !tc.noCacheUsersMachine {
				krb5UserDir := filepath.Join(adsysDir, "run", "krb5cc")
				err := os.MkdirAll(krb5UserDir, 0755)
				require.NoError(t, err, "Setup: could not create gpo cache dir: %v", err)
				for _, user := range []string{"user1@example.com", "user2@example.com"} {
					f, err := os.Create(filepath.Join(krb5UserDir, user))
					require.NoError(t, err, "Setup: could not create krb5 cache dir for %s: %v", user, err)
					f.Close()
					f, err = os.Create(filepath.Join(gpoRulesDir, user))
					require.NoError(t, err, "Setup: could not create gpo cache dir for %s: %v", user, err)
					f.Close()
				}
				// TODO: change modification time? (golden)
			}
			if tc.krb5ccNoCache {
				err := os.RemoveAll(gpoRulesDir)
				require.NoError(t, err, "Setup: can’t delete gpo rules cache directory")
			}

			got, err := runClient(t, conf, "service", "status")
			if tc.wantErr {
				require.Error(t, err, "client should exit with an error")
				return
			}
			require.NoError(t, err, "client should exit with no error")

			// Make paths suitable for golden recording and comparison
			re := regexp.MustCompile(`_.*/`)
			got = re.ReplaceAllString(got, "_XXXXXX/")

			re = regexp.MustCompile(`(updated on)([^\n]*)`)
			got = re.ReplaceAllString(got, "$1 DDD MON D HH:MM")
			// Hardcode time for making next refresh time independent of current timezone, but still
			// check some values (day digit, month…)
			re = regexp.MustCompile(`(Next Refresh:) .* May 2.*([^\n]*)`)
			got = re.ReplaceAllString(got, "$1 Tue May 25 14:55")

			// Compare golden files
			goldPath := filepath.Join("testdata/PolicyStatus/golden", name)
			// Update golden file
			if update {
				t.Logf("updating golden file %s", goldPath)
				err = os.WriteFile(goldPath, []byte(got), 0644)
				require.NoError(t, err, "Cannot write golden file")
			}
			want, err := os.ReadFile(goldPath)
			require.NoError(t, err, "Cannot load policy golden file")

			require.Equal(t, string(want), got, "Status returned expected output")
		})
	}
}

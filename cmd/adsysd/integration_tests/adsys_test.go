package adsys_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/cmd/adsysd/client"
	"github.com/ubuntu/adsys/cmd/adsysd/daemon"
	"github.com/ubuntu/adsys/internal/authorizer"
	"github.com/ubuntu/adsys/internal/testutils"
	"google.golang.org/grpc"
)

const dockerSystemDaemonsImage = "ghcr.io/ubuntu/adsys/systemdaemons:0.1"

var (
	update         bool
	rootProjectDir string
)

func TestMain(m *testing.M) {
	if os.Getenv("ADSYS_SKIP_INTEGRATION_TESTS") != "" {
		fmt.Println("Integration tests skipped as requested")
		return
	}

	// get root project directory with go.mod file
	p, err := os.Getwd()
	if err != nil {
		log.Fatalf("Setup: cant't get current working directory: %v", err)
	}
	for p != "/" {
		if _, err := os.Stat(filepath.Join(p, "go.mod")); err == nil {
			rootProjectDir = p
			break
		}
		p = filepath.Dir(p)
	}
	if rootProjectDir == "" {
		log.Fatalf("Setup: can't find project root directory")
	}

	// Start 2 containers running local polkitd with our policy (one for always yes, one for always no)
	// We only start samba on non helper process
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		defer runDaemons()()
		cwd, err := os.Getwd()
		if err != nil {
			log.Fatalf("Setup: can't get current working directory: %v", err)
		}
		defer testutils.SetupSmb(1446, filepath.Join(cwd, "testdata/PolicyUpdate/AD/SYSVOL"))()
	}

	flag.BoolVar(&update, "update", false, "update golden files")
	flag.Parse()

	m.Run()

	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		testutils.MergeCoverages()
	}
}

func TestStartAndStopDaemon(t *testing.T) {
	systemAnswer(t, "polkit_yes")

	conf := createConf(t, "")
	quit := runDaemon(t, conf)
	quit()
}

func TestCommandsError(t *testing.T) {
	// No command is implemented, and so, they should all returns an error
	errorServer := adsys.UnimplementedServiceServer{}
	srv := grpc.NewServer(authorizer.WithUnixPeerCreds())
	adsys.RegisterServiceServer(srv, &errorServer)

	dir := t.TempDir()
	socket := filepath.Join(dir, "socket")
	go func() {
		lis, err := net.Listen("unix", socket)
		require.NoError(t, err, "Setup: Listen on unix socket failed")
		err = srv.Serve(lis)
		require.NoError(t, err, "Setup: Serving GRPC on unix socket failed")
	}()
	t.Cleanup(srv.Stop)
	time.Sleep(time.Second)
	confFile := filepath.Join(dir, "adsys.yaml")
	err := os.WriteFile(confFile, []byte(fmt.Sprintf(`
socket: %s`, socket)), 0600)
	require.NoError(t, err, "Setup: config file should be created")

	tests := map[string]struct {
		args []string
	}{
		"doc":                         {args: []string{"doc"}},
		"doc chapter":                 {args: []string{"doc", "chapter"}},
		"policy admx all":             {args: []string{"policy", "admx", "all"}},
		"policy applied":              {args: []string{"policy", "applied"}},
		"policy debug gpolist-script": {args: []string{"policy", "debug", "gpolist-script"}},
		"policy update":               {args: []string{"policy", "update"}},
		"service cat":                 {args: []string{"service", "cat"}},
		"service status":              {args: []string{"service", "status"}},
		"service stop":                {args: []string{"service", "stop"}},
		"version":                     {args: []string{"version"}},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			_, err = runClient(t, confFile, tc.args...)
			require.Error(t, err, "command should fail")
		})
	}
}

type timeoutOnVersionServer struct {
	adsys.UnimplementedServiceServer
	clientCancelled bool
	callbackHandled chan struct{}
}

func (server *timeoutOnVersionServer) Version(_ *adsys.Empty, s adsys.Service_VersionServer) error {
	defer close(server.callbackHandled)
	select {
	case <-s.Context().Done():
		server.clientCancelled = true
	case <-time.After(5 * time.Second):
	}

	return nil
}

func TestCommandsTimeouts(t *testing.T) {
	tests := map[string]struct {
		timeout     int
		wantTimeout bool
	}{
		"Should timeout":  {timeout: 1, wantTimeout: true},
		"0 is no timeout": {timeout: 0},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			// We only implement one command to test the client timeout functionality
			timeoutServer := timeoutOnVersionServer{callbackHandled: make(chan struct{})}
			srv := grpc.NewServer(authorizer.WithUnixPeerCreds())
			adsys.RegisterServiceServer(srv, &timeoutServer)

			dir := t.TempDir()
			socket := filepath.Join(dir, "socket")
			go func() {
				lis, err := net.Listen("unix", socket)
				require.NoError(t, err, "Setup: Listen on unix socket failed")
				err = srv.Serve(lis)
				require.NoError(t, err, "Setup: Serving GRPC on unix socket failed")
			}()
			defer srv.Stop()
			time.Sleep(time.Second)
			confFile := filepath.Join(dir, "adsys.yaml")
			err := os.WriteFile(confFile, []byte(fmt.Sprintf(`
socket: %s
client_timeout: %d`, socket, tc.timeout)), 0600)
			require.NoError(t, err, "Setup: config file should be created")

			_, err = runClient(t, confFile, "version")
			if tc.wantTimeout {
				require.Error(t, err, "command should fail due to timeout")
				<-timeoutServer.callbackHandled
				require.True(t, timeoutServer.clientCancelled, "server should have got timeout request")
			} else {
				require.NoError(t, err, "command should not fail as there is no timeout")
				<-timeoutServer.callbackHandled
				require.False(t, timeoutServer.clientCancelled, "server should have not got a timeout request")
			}
		})
	}
}

// createConf generates an adsys configuration in a temporary directory
// It will use adsysDir for socket, cache and run dir if provided.
func createConf(t *testing.T, adsysDir string) (conf string) {
	t.Helper()

	dir := adsysDir
	if dir == "" {
		dir = t.TempDir()
	}

	// Create config
	confFile := filepath.Join(dir, "adsys.yaml")
	err := os.WriteFile(confFile, []byte(fmt.Sprintf(`
# Service and client configuration
verbose: 2
socket: %s/socket

# Service only configuration
cache_dir: %s/cache
run_dir: %s/run
service_timeout: 30
ad_server: adc.example.com
ad_domain: example.com

# Those are more for tests
dconf_dir: %s/dconf
sudoers_dir: %s/sudoers.d
policykit_dir: %s/polkit-1
sss_cache_dir: %s/sss_cache
`, dir, dir, dir, dir, dir, dir, dir)), 0600)
	require.NoError(t, err, "Setup: config file should be created")

	require.NoError(t, os.MkdirAll(filepath.Join(dir, "dconf"), 0750), "Setup: should create dconf dir")
	// Don’t create empty dirs for sudo and polkit: todo: same for dconf?

	return confFile
}

// runDaemon starts the adsys daemon lifecycle.
// It returns a quit() function.
func runDaemon(t *testing.T, conf string) (quit func()) {
	t.Helper()

	var wg sync.WaitGroup
	d := daemon.New()
	changeAppArgs(t, d, conf)
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := d.Run()
		require.NoError(t, err, "daemon should exit with no error")
	}()

	d.WaitReady()
	time.Sleep(10 * time.Millisecond)

	return func() {
		done := make(chan struct{})
		go func() {
			d.Quit()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("daemon should have stopped within second")
		}

		wg.Wait()
	}
}

// runClient instantiates a client using conf from the given args.
// It returns the stdout content and error from client.
func runClient(t *testing.T, conf string, args ...string) (stdout string, err error) {
	t.Helper()

	c := client.New()
	changeAppArgs(t, c, conf, args...)

	// capture stdout
	r, w, err := os.Pipe()
	require.NoError(t, err, "Setup: pipe shouldn’t fail")
	orig := os.Stdout
	os.Stdout = w

	err = c.Run()

	// restore and collect
	os.Stdout = orig
	w.Close()
	var out bytes.Buffer
	_, errCopy := io.Copy(&out, r)
	require.NoError(t, errCopy, "Couldn’t copy stdout to buffer")

	return out.String(), err
}

type setterArgs interface {
	SetArgs([]string)
}

// changeAppArgs modifies the application Args for cobra to parse them successfully.
// Do not share the daemon or client passed to it, as cobra store it globally.
func changeAppArgs(t *testing.T, s setterArgs, conf string, args ...string) {
	t.Helper()

	newArgs := []string{"-vv"}
	if conf != "" {
		newArgs = append(newArgs, "-c", conf)
	}
	if args != nil {
		newArgs = append(newArgs, args...)
	}

	s.SetArgs(newArgs)
}

var (
	systemSockets      = make(map[string]string)
	systemAnswersModes = []string{
		"polkit_yes",
		"polkit_no",
		"no_startup_time",
		"invalid_startup_time",
		"no_nextrefresh_time",
		"invalid_nextrefresh_time",
		"subscription_disabled",
	}
)

// runDaemons is a helper to start polkit, mock systemd and a system dbus session in multile containers:
// - one giving all permissions to any actions, with a harcoded startup time and next refresh unit time.
// - one giving no permissions to every actions, with a harcoded startup time and next refresh unit time.
// - one having no startup time available.
// - one having an invalid startup time.
// - one having no refresh unit time available.
// - one having an invalid refresh unit time.
// The current branch .policy file is used.
// you can then select the correct daemon via the system dbus socket with systemAnswer().
// teardown will ensure the containers are stopped.
func runDaemons() (teardown func()) {
	r, err := rand.Int(rand.Reader, big.NewInt(999999))
	if err != nil {
		log.Fatalf("Setup: couldn't set a random name for docker container: %v", err)
	}
	containerName := fmt.Sprintf("adsys-tests-%06d", r.Int64())

	adsysActionsDir, err := filepath.Abs(filepath.Join(rootProjectDir, "internal/adsysservice/actions"))
	if err != nil {
		log.Fatalf("Setup: couldn't get absolute path for actions: %v", err)
	}

	dir, err := os.MkdirTemp("/tmp", "adsys-system-daemons.*")
	if err != nil {
		log.Fatalf("Setup: failed to create temporary directory: %v", err)
	}

	answers := make(map[string]string)
	for _, mode := range systemAnswersModes {
		answers[mode] = filepath.Join(dir, mode)
	}

	var wg sync.WaitGroup
	for answer, socketDir := range answers {
		answer := answer
		socketDir := socketDir
		wg.Add(1)

		go func() {
			defer wg.Done()

			if err := os.MkdirAll(socketDir, 0750); err != nil {
				log.Fatalf("Setup: can’t create %s socket directory: %v", answer, err)
			}

			// #nosec G204: we control the name in tests
			cmd := exec.Command("docker",
				"run", "--rm", "--pid", "host",
				"--name", containerName+answer,
				"--volume", fmt.Sprintf("%s:%s:ro", adsysActionsDir, "/usr/share/polkit-1/actions.orig"),
				"--volume", `/etc/group:/etc/group:ro`,
				"--volume", `/etc/passwd:/etc/passwd:ro`,
				"--volume", fmt.Sprintf("%s:/dbus/", socketDir),
				dockerSystemDaemonsImage,
				answer,
			)
			out, _ := cmd.CombinedOutput()
			// Docker stop -t 0 will kill it anyway the container with exit code 143
			if cmd.ProcessState.ExitCode() > 0 && cmd.ProcessState.ExitCode() != 143 {
				log.Fatalf("Error running system daemons container named %q:\n%v", answer, string(out))
			}
		}()
	}

	for a, s := range answers {
		systemSockets[a] = fmt.Sprintf("unix:path=%s/system_bus_socket", s)
	}

	// give time for polkit containers to start
	// TODO: wait for polkit containers to be ready
	time.Sleep(5 * time.Second)

	return func() {
		defer func() {
			err := os.RemoveAll(dir)
			if err != nil {
				log.Fatalf("Teardown: failed to delete temporary directory: %v", err)
			}
		}()

		for answer := range answers {
			// #nosec G204: we control the args in tests
			out, err := exec.Command("docker", "stop", "-t", "0", containerName+answer).CombinedOutput()
			if err != nil {
				log.Fatalf("Teardown: can’t stop system daemons container: %v", string(out))
			}
		}
		wg.Wait()
	}
}

// systemAnswer will flip to which polkit and systemd mock to communicate to:
// - yes for polkit always authorizing our actions, with a harcoded startup time and next refresh unit time.
// - no for polkit always denying our actions, with a harcoded startup time and next refresh unit time.
// - one having no startup time available.
// - one having an invalid startup time.
// - one having no refresh unit time available.
// - one having an invalid refresh unit time.
// Note that this modify the environment variable, and so, tests using them can’t run in parallel.
// The environment is restored when the test ends.
func systemAnswer(t *testing.T, answer string) {
	t.Helper()

	if answer == "" {
		return
	}

	var socket string
	socket, ok := systemSockets[answer]
	if !ok {
		t.Fatalf("Setup: unknown daemon answer to support: %q", answer)
	}

	testutils.Setenv(t, "DBUS_SYSTEM_BUS_ADDRESS", socket)
}

type runner interface {
	Run() error
}

func TestExecuteCommand(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	defer os.Exit(0)

	args := os.Args
	for len(args) > 0 {
		if args[0] != "--" {
			args = args[1:]
			continue
		}
		args = args[1:]
		break
	}

	// let cobra knows what we want to execute
	os.Args = args

	var app runner
	switch args[0] {
	case "adsysctl":
		app = client.New()
	case "adsysd":
		app = daemon.New()
	default:
		fmt.Fprintf(os.Stderr, "UNKNOWN command: %s", args[0])
		os.Exit(1)
	}

	if err := app.Run(); err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}
}

var testCmdName = os.Args[0]

func startCmd(t *testing.T, wait bool, args ...string) (out func() string, stop func(), err error) {
	t.Helper()

	cmdArgs := []string{"env", "GO_WANT_HELPER_PROCESS=1", testCmdName, "-test.run=TestExecuteCommand", "--"}
	cmdArgs = append(cmdArgs, args...)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	// #nosec G204: this is only for tests, under controlled args
	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)

	var b bytes.Buffer
	cmd.Stdout = &b
	cmd.Stderr = &b

	err = cmd.Start()
	if wait {
		err := cmd.Wait()
		cancel()
		return func() string { return b.String() }, func() {}, err
	}

	return func() string { return b.String() },
		func() {
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal("Failed to kill process: ", err)
			}
			_ = cmd.Wait()
			cancel()
		}, err
}

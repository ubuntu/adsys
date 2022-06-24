package adwatchd_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/cmd/adwatchd/commands"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
)

func TestMain(m *testing.M) {
	if os.Getenv("ADWATCHD_SKIP_INTEGRATION_TESTS") != "" || os.Getenv("ADSYS_SKIP_SUDO_TESTS") != "" {
		fmt.Println("Integration tests skipped as requested")
		return
	}

	// Installed service by the tests are using the test binary, with the "run" argument from service manager
	if len(os.Args) > 0 && os.Args[1] == "run" {
		app := commands.New()
		err := app.Run()
		if err != nil {
			log.Error(context.Background(), err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	m.Run()
}

func generateConfig(t *testing.T, verbosity int, dirs ...string) string {
	t.Helper()

	var dirContent string
	var verboseContent string
	for _, dir := range dirs {
		dirContent += fmt.Sprintf("  - %s\n", dir)
	}

	if verbosity > -1 {
		verboseContent = fmt.Sprintf("verbose: %d\n", verbosity)
	}

	dest := filepath.Join(t.TempDir(), "adwatchd.yaml")
	err := os.WriteFile(dest, []byte(fmt.Sprintf(`%sdirs:
%s`, verboseContent, dirContent)), 0600)
	require.NoError(t, err, "Setup: can't write configuration file")

	return dest
}

func getStatus(t *testing.T, app *commands.App) string {
	t.Helper()

	changeAppArgs(t, app, "", "service", "status")

	// capture stdout
	r, w, err := os.Pipe()
	require.NoError(t, err, "Setup: pipe shouldn't fail")
	orig := os.Stdout
	os.Stdout = w

	err = app.Run()

	// restore and collect
	os.Stdout = orig
	w.Close()
	var out bytes.Buffer
	_, errCopy := io.Copy(&out, r)
	require.NoError(t, errCopy, "Couldn't copy stdout to buffer")

	require.NoError(t, err, "Setup: couldn't get service status")

	return out.String()
}

// changeAppArgs modifies the application Args for cobra to parse them successfully.
// Do not share the daemon or client passed to it, as cobra store it globally.
func changeAppArgs(t *testing.T, app *commands.App, conf string, args ...string) {
	t.Helper()

	var newArgs []string
	if conf != "" {
		newArgs = append(newArgs, "-c", conf)
	}
	if args != nil {
		newArgs = append(newArgs, args...)
	}

	app.Reset()
	app.SetArgs(newArgs, conf)
}

// installService installs the service on the system.
func installService(t *testing.T, config string, app *commands.App) {
	t.Helper()

	t.Cleanup(func() { uninstallService(t, app) })

	changeAppArgs(t, app, config, "service", "install")
	err := app.Run()
	require.NoError(t, err, "Couldn't install service")
}

// installService uninstall the service on the system.
func uninstallService(t *testing.T, app *commands.App) {
	t.Helper()

	changeAppArgs(t, app, "", "service", "uninstall")
	err := app.Run()
	require.NoError(t, err, "Couldn't uninstall service")
}

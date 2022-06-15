package watchdtui_test

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/cmd/adwatchd/commands"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/watchdservice"
	"github.com/ubuntu/adsys/internal/watchdtui"
	"gopkg.in/yaml.v2"
)

var (
	update bool
	stdout bool
)

func TestInteractiveInput(t *testing.T) {
	t.Parallel()

	// Simulate a color terminal
	lipgloss.SetColorProfile(termenv.ANSI256)

	tests := map[string]struct {
		events        []tea.Msg
		existingPaths []string
		cfgToValidate string
		absPathInput  bool

		// Parameters for when we want to simulate a previous config file
		configOverride bool
		configDirs     []string
	}{
		"initial view": {
			events:        []tea.Msg{},
			existingPaths: []string{"foo/bar/", "foo/baz"},
		},

		// Config file input behaviors
		"config file exists": {
			events: []tea.Msg{
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/baz")},
				tea.KeyMsg{Type: tea.KeyEnter},
			},
			existingPaths: []string{"foo/baz"},
		},
		"config file is absent and input is absolute": {
			events: []tea.Msg{
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/baz")},
				tea.KeyMsg{Type: tea.KeyEnter},
			},
			absPathInput: true,
		},
		"config file is absent and input is relative": {
			events: []tea.Msg{
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/baz")},
				tea.KeyMsg{Type: tea.KeyEnter},
			},
		},
		"config file is absent and input is a dir": {
			events: []tea.Msg{
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/bar")},
				tea.KeyMsg{Type: tea.KeyEnter},
			},
			existingPaths: []string{"foo/bar/"},
		},
		"previous config file is passed in and is empty or has no directories": {
			configOverride: true,
		},
		"previous config file is passed in and contains directories which exist on the system": {
			configOverride: true,
			existingPaths:  []string{"foo/bar/", "foo/baz/"},
			configDirs:     []string{"foo/bar", "foo/baz"},
		},
		"previous config file is passed in and contains directories, not all which exist on the system": {
			configOverride: true,
			existingPaths:  []string{"foo/bar/"},
			configDirs:     []string{"foo/bar", "foo/baz"},
		},

		// Directory input behaviors
		"directory exists": {
			events: []tea.Msg{
				tea.KeyMsg{Type: tea.KeyDown},
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/bar")},
				tea.KeyMsg{Type: tea.KeyEnter}, // creates new line
				tea.KeyMsg{Type: tea.KeyEnter}, // removes new line and focuses on Submit
			},
			existingPaths: []string{"foo/bar/"},
		},
		"directory does not exist, block input": {
			events: []tea.Msg{
				tea.KeyMsg{Type: tea.KeyDown},
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/bar")},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyUp},
				tea.KeyMsg{Type: tea.KeyUp},
				tea.KeyMsg{Type: tea.KeyDown},
				tea.KeyMsg{Type: tea.KeyDown},
				tea.KeyMsg{Type: tea.KeyTab},
				tea.KeyMsg{Type: tea.KeyTab},
				tea.KeyMsg{Type: tea.KeyShiftTab},
				tea.KeyMsg{Type: tea.KeyShiftTab},
			},
		},
		"dot and double dot directory inputs are normalized": {
			events: []tea.Msg{
				tea.KeyMsg{Type: tea.KeyDown},
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/bar/./qux/../../baz")},
			},
		},
		"directory is a file, block input": {
			events: []tea.Msg{
				tea.KeyMsg{Type: tea.KeyDown},
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/bar")},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyUp},
				tea.KeyMsg{Type: tea.KeyUp},
				tea.KeyMsg{Type: tea.KeyDown},
				tea.KeyMsg{Type: tea.KeyDown},
				tea.KeyMsg{Type: tea.KeyTab},
				tea.KeyMsg{Type: tea.KeyTab},
				tea.KeyMsg{Type: tea.KeyShiftTab},
				tea.KeyMsg{Type: tea.KeyShiftTab},
			},
			existingPaths: []string{"foo/bar"},
		},
		"multiple existing directories, can cycle between the inputs": {
			events: []tea.Msg{
				tea.KeyMsg{Type: tea.KeyDown},
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/bar")},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/baz")},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/qux")},
				tea.KeyMsg{Type: tea.KeyUp},
				tea.KeyMsg{Type: tea.KeyUp},        // focus on first entry
				tea.KeyMsg{Type: tea.KeyBackspace}, // delete last char to make it invalid
				tea.KeyMsg{Type: tea.KeyDown},      // attempt to move
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")}, // fix entry
				tea.KeyMsg{Type: tea.KeyTab},
				tea.KeyMsg{Type: tea.KeyTab},  // back to the last entry
				tea.KeyMsg{Type: tea.KeyDown}, // focus on Submit
			},
			existingPaths: []string{"foo/bar/", "foo/baz/", "foo/qux/"},
		},
		"multiple existing directories, can delete them": {
			events: []tea.Msg{
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/bar")},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/baz")},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo")},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyBackspace}, // delete current input, back to foo
				tea.KeyMsg{Type: tea.KeyBackspace},
				tea.KeyMsg{Type: tea.KeyBackspace},
				tea.KeyMsg{Type: tea.KeyBackspace},
				tea.KeyMsg{Type: tea.KeyEnter}, // delete current empty input
			},
			existingPaths: []string{"foo/bar/", "foo/baz/"},
		},
		"no directories, focus on dir input": {
			events: []tea.Msg{
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyEnter}, // cannot move further with no directories
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyEnter},
			},
		},

		// Submit behaviors
		"submit with default config": {
			events: []tea.Msg{
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/bar")},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/baz")},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyEnter},
			},
			existingPaths: []string{"foo/bar/", "foo/baz/"},
			cfgToValidate: "adwatchd.yml",
		},
		"submit with fresh config in current directory": {
			events: []tea.Msg{
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("my_config.yml")},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/bar")},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/baz")},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyEnter},
			},
			existingPaths: []string{"foo/bar/", "foo/baz/"},
			cfgToValidate: "my_config.yml",
		},
		"submit with fresh config in nested directory": {
			events: []tea.Msg{
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("aaa/bbb/ccc/my_config.yml")},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/bar")},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/baz")},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyEnter},
			},
			existingPaths: []string{"foo/bar/", "foo/baz/"},
			cfgToValidate: "aaa/bbb/ccc/my_config.yml",
		},
		"submit with duplicate directories": {
			events: []tea.Msg{
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/bar")},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/bar/../")},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/baz")},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/baz")},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/baz/abc/../")},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyEnter},
			},
			existingPaths: []string{"foo/bar/", "foo/baz/"},
			cfgToValidate: "adwatchd.yml",
		},
		"submit with directory as config input": {
			events: []tea.Msg{
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/bar")},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/baz")},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyEnter},
			},
			existingPaths: []string{"foo/bar/", "foo/baz/"},
			cfgToValidate: "foo/bar/adwatchd.yml",
		},
		"submit with dot directories is normalized": {
			events: []tea.Msg{
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("./foo/./bar/./")},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(".")}, // #ABSPATH#
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyEnter},
			},
			existingPaths: []string{"foo/bar/"},
			cfgToValidate: "adwatchd.yml",
		},
		"submit with double dot directories is normalized": {
			events: []tea.Msg{
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/baz/qux/asd/../..")}, // baz
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyEnter},
			},
			existingPaths: []string{"foo/baz/"},
			cfgToValidate: "adwatchd.yml",
		},

		// Other navigation behaviors
		"other navigation tests": {
			events: []tea.Msg{
				tea.KeyMsg{Type: tea.KeyUp},        // no up or shift+tab on config
				tea.KeyMsg{Type: tea.KeyShiftTab},  // no up or shift+tab on config
				tea.KeyMsg{Type: tea.KeyBackspace}, // no custom backspace on config
				tea.KeyMsg{Type: tea.KeyDown},
				tea.KeyMsg{Type: tea.KeyBackspace}, // backspace on first input cycles back to config
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("foo/bar")},
				tea.KeyMsg{Type: tea.KeyEnter},
				tea.KeyMsg{Type: tea.KeyEnter},     // focus on Submit
				tea.KeyMsg{Type: tea.KeyBackspace}, // backspace on Submit
				tea.KeyMsg{Type: tea.KeyEnter},     // back on Submit
				tea.KeyMsg{Type: tea.KeyDown},      // no down or tab on Submit
				tea.KeyMsg{Type: tea.KeyTab},
			},
			existingPaths: []string{"foo/bar/"},
		},
	}
	for name, tc := range tests {
		tc := tc
		goldDir, _ := filepath.Abs(filepath.Join("testdata", "golden"))
		t.Run(name, func(t *testing.T) {
			var err error

			goldPath := filepath.Join(goldDir, strings.Replace(name, " ", "_", -1))

			tmpdir := chdirToTempdir(t)

			// Create existing directories/files
			for _, path := range tc.existingPaths {
				if strings.HasSuffix(path, "/") {
					err = os.MkdirAll(path, 0755)
					require.NoError(t, err, "can't create directories")
				} else {
					err = os.MkdirAll(filepath.Dir(path), 0755)
					require.NoError(t, err, "can't create directory for file")

					err = os.WriteFile(path, []byte("some content"), 0644)
					require.NoError(t, err, "could not write sample file")
				}
			}

			// Create previous/existing config file if needed
			if len(tc.configDirs) > 0 {
				data, err := yaml.Marshal(&watchdtui.AppConfig{Dirs: tc.configDirs})
				require.NoError(t, err, "could not marshal config")
				err = os.WriteFile("adwatchd.yml", data, 0644)
				require.NoError(t, err, "could not write previous config")
			}

			m, _ := watchdtui.InitialModelForTests(!tc.configOverride).Update(nil)

			for _, e := range tc.events {
				keyMsg, ok := e.(tea.KeyMsg)
				require.True(t, ok, "expected event to be a KeyMsg")

				// Did we request an absolute path? If so, we need to merge the
				// runes with the current working directory.
				if tc.absPathInput && keyMsg.Type == tea.KeyRunes {
					e = tea.KeyMsg{
						Type:  tea.KeyRunes,
						Runes: []rune(filepath.Join(tmpdir, string(keyMsg.Runes))),
					}
				}

				m = updateModel(t, m, e)
			}
			out := m.View()
			if stdout {
				fmt.Println(out)
			}

			// Update golden file
			if update {
				t.Logf("updating golden file %s", goldPath)
				err = os.WriteFile(goldPath, []byte(parseOutput(t, out)), 0600)
				require.NoError(t, err, "Cannot write golden file")
			}
			want, err := os.ReadFile(goldPath)
			require.NoError(t, err, "Cannot load golden file")

			if tc.cfgToValidate != "" {
				goldCfgPath := filepath.Join(goldDir, strings.Replace(name, " ", "_", -1)+".yml")
				outCfg, err := os.ReadFile(tc.cfgToValidate)
				require.NoError(t, err, "Cannot load test config file")

				if update {
					err = os.WriteFile(goldCfgPath, []byte(parseOutput(t, string(outCfg))), 0600)
					require.NoError(t, err, "Cannot write golden config file")
				}

				wantCfg, err := os.ReadFile(goldCfgPath)
				require.NoError(t, err, "Cannot load golden config file")

				require.Equal(t, string(wantCfg), parseOutput(t, string(outCfg)), "Configs don't match")
			}

			require.Equal(t, string(want), parseOutput(t, m.View()), "Didn't get expected output")
		})
	}
}

func TestInteractiveInstall(t *testing.T) {
	if os.Getenv("ADWATCHD_RUN_INTEGRATION_TESTS") == "" {
		t.Skip("Integration tests skipped as requested")
	}

	svc, err := watchdservice.New(context.Background())
	require.NoError(t, err, "Cannot initialize watchd service")

	t.Cleanup(func() {
		err = svc.Uninstall(context.Background())
		require.NoError(t, err, "Cannot uninstall watchd service")
	})

	_ = chdirToTempdir(t)

	// Create existing directories/files
	err = os.MkdirAll("foo/bar", 0755)
	require.NoError(t, err, "can't create directories")
	err = os.MkdirAll("foo/baz", 0755)
	require.NoError(t, err, "can't create directories")

	m, _ := watchdtui.InitialModel().Update(nil)

	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyEnter}) // use default config

	// add directories
	for _, dir := range []string{"foo/bar", "foo/baz"} {
		m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(dir)})
		m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	}

	// submit
	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	m = updateModel(t, m, tea.KeyMsg{Type: tea.KeyEnter})

	out := m.View()
	goldOutput := "Service adwatchd was successfully installed and is now running.\n"
	require.Equal(t, goldOutput, out, "Didn't get expected output")

	status, err := svc.Status(context.Background())
	require.NoError(t, err, "Cannot get status")
	require.Contains(t, status, "running", "Expected service to be running")
}

// updateModel calls Update() on the model and executes returned commands.
// It will reexecute Update() until there are no more returned commands.
func updateModel(t *testing.T, m tea.Model, msg tea.Msg) tea.Model {
	t.Helper()

	m, cmd := m.Update(msg)
	if cmd == nil {
		return m
	}

	messageCandidates := cmd()

	batchMsgType := reflect.TypeOf(tea.Batch(func() tea.Msg { return tea.Msg(struct{}{}) })())

	// executes all messages on batched messages, which is a slice underlying it.
	if reflect.TypeOf(messageCandidates) == batchMsgType {
		if reflect.TypeOf(messageCandidates).Kind() != reflect.Slice {
			t.Fatalf("expected batched messages to be a slice but it's not: %v", reflect.TypeOf(messageCandidates).Kind())
		}

		v := reflect.ValueOf(messageCandidates)
		for i := 0; i < v.Len(); i++ {
			messages := v.Index(i).Call(nil)
			// Call update on all returned messages, which can itself reenter Update()
			for _, msgValue := range messages {
				// if this is a Tick message, ignore it (to avoid endless loop as we will always have the next tick available)
				// and our function is reentrant, not a queue of message. Thus, install is never called.
				if _, ok := msgValue.Interface().(spinner.TickMsg); ok {
					continue
				}

				msg, ok := msgValue.Interface().(tea.Msg)
				if !ok {
					t.Fatalf("expected message to be a tea.Msg, but got: %T", msg)
				}
				m = updateModel(t, m, msg)
			}
		}
		return m
	}

	// We only got one message, call Update() on it
	return updateModel(t, m, messageCandidates)
}

func chdirToTempdir(t *testing.T) string {
	t.Helper()

	orig, err := os.Getwd()
	require.NoError(t, err, "Setup: can't get current directory")

	dir := t.TempDir()
	err = os.Chdir(dir)
	require.NoError(t, err, "Setup: can't change current directory")
	t.Cleanup(func() {
		err := os.Chdir(orig)
		require.NoError(t, err, "Teardown: can't restore current directory")
	})
	return dir
}

// parseOutput normalizes the output of the view function in order to ensure
// tests work on both Linux and Windows.
func parseOutput(t *testing.T, out string) string {
	t.Helper()

	cwd, err := os.Getwd()
	require.NoError(t, err, "can't get current directory")

	cwd = filepath.ToSlash(cwd)
	// Normalize backslashes to slashes
	out = strings.Replace(out, "\\", "/", -1)

	// Replace cwd with a deterministic placeholder
	out = strings.Replace(out, cwd, "#ABSPATH#", -1)
	return out
}

func TestMain(m *testing.M) {
	// Running real command mock from service manager
	if len(os.Args) > 0 && os.Args[1] == "run" {
		app := commands.New()
		err := app.Run()
		if err != nil {
			log.Error(context.Background(), err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	flag.BoolVar(&update, "update", false, "update golden files")
	flag.BoolVar(&stdout, "stdout", false, "print output to stdout for debugging purposes")
	flag.Parse()

	m.Run()
}

package apparmor_test

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/termie/go-shutil"
	"github.com/ubuntu/adsys/internal/policies/apparmor"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/testutils"
)

var update bool

func TestApplyPolicy(t *testing.T) {
	t.Parallel()

	defaultMachineProfile := []entry.Entry{{Key: "apparmor-machine", Value: "usr.bin.foo"}}

	tests := map[string]struct {
		entries []entry.Entry
		user    bool

		noParserOutput          bool
		saveAssetsError         bool
		removeUnusedAssetsError bool
		apparmorParserError     bool
		destAlreadyExists       string
		readOnlyApparmorDir     string
		noApparmorParser        bool

		wantErr bool
	}{
		// computer cases
		"computer, one profile":              {entries: defaultMachineProfile},
		"computer, multiple profiles,":       {entries: []entry.Entry{{Key: "apparmor-machine", Value: "usr.bin.foo\nusr.bin.bar\nnested/usr.bin.baz"}}},
		"computer, duplicated profiles":      {entries: []entry.Entry{{Key: "apparmor-machine", Value: "usr.bin.foo\nusr.bin.foo"}}},
		"computer, blank line profiles":      {entries: []entry.Entry{{Key: "apparmor-machine", Value: "usr.bin.foo\n\nusr.bin.bar\n"}}},
		"computer, profiles with whitespace": {entries: []entry.Entry{{Key: "apparmor-machine", Value: " usr.bin.foo\n\n usr.bin.bar   \nnested/usr.bin.baz "}}},
		"computer, whitespace-only value":    {entries: []entry.Entry{{Key: "apparmor-machine", Value: "       "}}, noParserOutput: true},
		"computer, only blank profiles":      {entries: []entry.Entry{{Key: "apparmor-machine", Value: "\n\n\n"}}, noParserOutput: true},
		"existing .old directory is removed": {entries: defaultMachineProfile, destAlreadyExists: "machine.old", noParserOutput: true},
		"existing .new directory is removed": {entries: defaultMachineProfile, destAlreadyExists: "machine.new", noParserOutput: true},

		// shared cases
		"no profiles, existing rules are removed": {destAlreadyExists: "machine"},
		"no profiles, apparmor directory absent":  {noParserOutput: true},
		"unexpected entry key":                    {entries: []entry.Entry{{Key: "apparmor-foo", Value: "usr.bin.foo"}}, noParserOutput: true},

		// user cases
		"user, one profile": {entries: []entry.Entry{{Key: "apparmor-user", Value: "usr.bin.foo"}}, user: true, noParserOutput: true},

		// other edge cases
		"no apparmor_parser and no entries": {noApparmorParser: true, noParserOutput: true},
		"no apparmor_parser and entries":    {entries: defaultMachineProfile, noApparmorParser: true, noParserOutput: true, wantErr: true},

		// error cases
		"error on parsing profiles failing":              {entries: defaultMachineProfile, apparmorParserError: true, wantErr: true},
		"error on unloading profiles failing":            {destAlreadyExists: "machine", apparmorParserError: true, wantErr: true},
		"error on save assets dumping failing":           {entries: defaultMachineProfile, noParserOutput: true, saveAssetsError: true, wantErr: true},
		"error on removing unused assets after dump":     {entries: defaultMachineProfile, noParserOutput: true, removeUnusedAssetsError: true, wantErr: true},
		"error on profile being a directory":             {entries: []entry.Entry{{Key: "apparmor-machine", Value: "nested/"}}, noParserOutput: true, wantErr: true},
		"error on absent profile":                        {entries: []entry.Entry{{Key: "apparmor-machine", Value: "usr.bin.nonexistent"}}, noParserOutput: true, wantErr: true},
		"error on file as a directory":                   {entries: []entry.Entry{{Key: "apparmor-machine", Value: "usr.bin.foo/notadir"}}, noParserOutput: true, wantErr: true},
		"error on read-only root directory, no entries":  {readOnlyApparmorDir: ".", noParserOutput: true, wantErr: true},
		"error on read-only root directory with entries": {entries: defaultMachineProfile, readOnlyApparmorDir: ".", noParserOutput: true, wantErr: true},
		"error on read-only machine directory":           {entries: defaultMachineProfile, destAlreadyExists: "machine", readOnlyApparmorDir: "machine", noParserOutput: true, wantErr: true},
		"error on read-only .old directory":              {entries: defaultMachineProfile, destAlreadyExists: "machine.old", readOnlyApparmorDir: "machine.old", noParserOutput: true, wantErr: true},
		"error on read-only .new directory":              {entries: defaultMachineProfile, destAlreadyExists: "machine.new", readOnlyApparmorDir: "machine.new", noParserOutput: true, wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			apparmorDir := t.TempDir()
			parserCmdOutputFile := filepath.Join(t.TempDir(), "parser-output")
			apparmorParserCmd := mockApparmorParserCmd(t, parserCmdOutputFile)
			if tc.noApparmorParser {
				apparmorParserCmd = []string{"this-definitely-does-not-exist"}
			}
			if tc.apparmorParserError {
				apparmorParserCmd = append(apparmorParserCmd, "-Exit1-")
			}

			object := "machine"
			if tc.user {
				object = "users"
			}

			if tc.destAlreadyExists != "" {
				require.NoError(t, os.RemoveAll(apparmorDir), "Setup: can't remove apparmor dir before filing it")
				require.NoError(t,
					shutil.CopyTree(
						filepath.Join("testdata", "apparmor_dir", object), filepath.Join(apparmorDir, tc.destAlreadyExists),
						&shutil.CopyTreeOptions{Symlinks: true, CopyFunction: shutil.Copy}),
					"Setup: can't create initial apparmor dir profiles content")
				fmt.Println(filepath.Join(apparmorDir, tc.destAlreadyExists))
			}
			if tc.readOnlyApparmorDir != "" {
				testutils.MakeReadOnly(t, filepath.Join(apparmorDir, tc.readOnlyApparmorDir))
			}
			mockAssetsDumper := testutils.MockAssetsDumper{Err: tc.saveAssetsError, ReadOnlyErr: tc.removeUnusedAssetsError, Path: "apparmor/", T: t}

			m := apparmor.New(apparmorDir, apparmor.WithApparmorParserCmd(apparmorParserCmd))
			err := m.ApplyPolicy(context.Background(), "ubuntu", !tc.user, tc.entries, mockAssetsDumper.SaveAssetsTo)
			if tc.wantErr {
				// We don't return here as we want to check that the apparmor
				// dir is in the expected state even in error cases
				require.Error(t, err, "ApplyPolicy should have failed but didn't")
			} else {
				require.NoError(t, err, "ApplyPolicy failed but shouldn't have")
			}

			// Restore permissions to be able to correctly compare trees
			if tc.readOnlyApparmorDir != "" {
				// nolint:gosec //false positive, this is a directory
				err = os.Chmod(filepath.Join(apparmorDir, tc.readOnlyApparmorDir), 0700)
				require.NoError(t, err, "Setup: can't chmod apparmor dir")
			}

			// Restore permissions to the dumped apparmor directory
			if tc.removeUnusedAssetsError {
				err = filepath.WalkDir(filepath.Join(apparmorDir), func(path string, d fs.DirEntry, err error) error {
					require.NoError(t, err, "Setup: can't walk dumped apparmor dir")
					if d.IsDir() {
						// nolint:gosec //false positive, this is a directory
						err = os.Chmod(path, 0700)
					} else {
						err = os.Chmod(path, 0600)
					}
					require.NoError(t, err, "Setup: can't chmod path")
					return nil
				})
				require.NoError(t, err, "Setup: can't restore permissions of dumped files")
			}
			testutils.CompareTreesWithFiltering(t, apparmorDir, filepath.Join("testdata", "golden", testutils.NormalizeGoldenName(t, t.Name()), "etc", "apparmor.d", "adsys"), update)

			// Return early if we don't want to check apparmor_parser output for
			// whatever reason (e.g. command did not execute, returned an error before etc.)
			if tc.noParserOutput {
				return
			}

			// Check that apparmor_parser was called with the expected arguments
			goldPath := filepath.Join("testdata", "golden", testutils.NormalizeGoldenName(t, t.Name()), fmt.Sprintf("parser_output-%s", userOrMachine(tc.user)))
			got, err := os.ReadFile(parserCmdOutputFile)
			require.NoError(t, err, "Setup: Can't read parser output file")
			got = []byte(normalizeOutput(t, string(got), apparmorDir))
			if update {
				err = os.WriteFile(goldPath, got, 0600)
				require.NoError(t, err, "Setup: Can't write golden file")
			}
			want, err := os.ReadFile(goldPath)
			require.NoError(t, err, "Setup: Can't read golden file")
			require.Equal(t, string(want), string(got), "Apparmor parser command output doesn't match")
		})
	}
}

func appendToFile(t *testing.T, path string, data []byte) {
	t.Helper()

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	require.NoError(t, err, "Setup: Can't open file for appending")
	defer f.Close()

	_, err = f.Write(data)
	require.NoError(t, err, "Setup: Can't write to file")
}

func mockApparmorParserCmd(t *testing.T, parserOutputFile string, args ...string) []string {
	t.Helper()

	cmdArgs := []string{"env", "GO_WANT_HELPER_PROCESS=1", os.Args[0], "-test.run=TestMockApparmorParser", "--", parserOutputFile}
	cmdArgs = append(cmdArgs, args...)
	return cmdArgs
}

func TestMockApparmorParser(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	defer os.Exit(0)

	var outputFile string
	args := os.Args
	for len(args) > 0 {
		if args[0] != "--" {
			args = args[1:]
			continue
		}
		// First arg after -- is the output file to write to
		outputFile = args[1]
		args = args[2:]
		break
	}
	// Dump the newline-separated args to the output file, appending if needed
	// in order to track multiple apparmor_parser invocations
	appendToFile(t, outputFile, []byte(strings.Join(args, "\n")+"\n"))

	if args[0] == "-Exit1-" {
		fmt.Println("EXIT 1 requested in mock")
		os.Exit(1)
	}
}

func normalizeOutput(t *testing.T, out string, tmpPath string) string {
	t.Helper()

	return strings.ReplaceAll(out, tmpPath, "#TMPDIR#")
}

func userOrMachine(user bool) string {
	if user {
		return "user"
	}
	return "machine"
}

func TestMain(m *testing.M) {
	flag.BoolVar(&update, "update", false, "update golden files")
	flag.Parse()

	m.Run()
}

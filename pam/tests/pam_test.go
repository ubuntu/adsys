package pamtest

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var pamSourceDir = func() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("cannot determine PAM source directory")
	}
	return filepath.Dir(filepath.Dir(file))
}()

func TestPAMOpenSessionDconfProfile(t *testing.T) {
	gcc := requirePAMTestToolchain(t)
	t.Parallel()

	tests := []pamProfileTestCase{
		{
			name:             "short name uses the daemon-normalized target",
			username:         "Alice",
			normalizedTarget: "alice@example.com",
			createProfile:    true,
			hasMachineCache:  true,
			wantProfile:      "alice@example.com",
			wantSuccess:      true,
		},
		{
			name:             "effective daemon SSSD config supplies the domain",
			username:         "Alice",
			normalizedTarget: "alice@daemon-domain.example",
			createProfile:    true,
			hasMachineCache:  true,
			wantProfile:      "alice@daemon-domain.example",
			wantSuccess:      true,
		},
		{
			name:             "qualified name uses daemon normalization",
			username:         "Alice@Example.COM",
			normalizedTarget: "alice@example.com",
			createProfile:    true,
			hasMachineCache:  true,
			wantProfile:      "alice@example.com",
			wantSuccess:      true,
		},
		{
			name:             "qualified Unicode name uses daemon normalization",
			username:         "Älice@Example",
			normalizedTarget: "älice@example",
			createProfile:    true,
			hasMachineCache:  true,
			wantProfile:      "älice@example",
			wantSuccess:      true,
		},
		{
			name:             "domain slash name uses daemon normalization",
			username:         `EXAMPLE\Alice`,
			normalizedTarget: "alice@example",
			createProfile:    true,
			hasMachineCache:  true,
			wantProfile:      "alice@example",
			wantSuccess:      true,
		},
		{
			name:             "domain slash Unicode name uses daemon normalization",
			username:         `EXAMPLE\Älice`,
			normalizedTarget: "älice@example",
			createProfile:    true,
			hasMachineCache:  true,
			wantProfile:      "älice@example",
			wantSuccess:      true,
		},
		{
			name:            "missing profile leaves the environment unset",
			username:        "alice",
			hasMachineCache: true,
			wantProfile:     "<unset>",
			wantSuccess:     true,
		},
		{
			name:            "failed user update leaves the environment unset",
			username:        "alice",
			createProfile:   true,
			hasMachineCache: true,
			failUserUpdate:  true,
			wantProfile:     "<unset>",
		},
		{
			name:             "path-like name is not exported",
			username:         "Alice/unsafe",
			normalizedTarget: "alice/unsafe",
			hasMachineCache:  true,
			wantProfile:      "<unset>",
			wantSuccess:      true,
		},
		{
			name:             "dot name is not exported",
			username:         ".",
			normalizedTarget: ".",
			hasMachineCache:  true,
			wantProfile:      "<unset>",
			wantSuccess:      true,
		},
		{
			name:             "dot-dot name is not exported",
			username:         "..",
			normalizedTarget: "..",
			hasMachineCache:  true,
			wantProfile:      "<unset>",
			wantSuccess:      true,
		},
		{
			name:                   "directory is not accepted as a profile",
			username:               "alice",
			normalizedTarget:       "alice",
			hasMachineCache:        true,
			createProfileDirectory: true,
			wantProfile:            "<unset>",
			wantSuccess:            true,
		},
		{
			name:            "existing bare profile is supported",
			username:        "Alice",
			createProfile:   true,
			hasMachineCache: true,
			wantProfile:     "alice",
			wantSuccess:     true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runPAMProfileTest(t, gcc, test)
		})
	}
}

type pamProfileTestCase struct {
	name                   string
	username               string
	normalizedTarget       string
	createProfile          bool
	createProfileDirectory bool
	hasMachineCache        bool
	failUserUpdate         bool
	wantProfile            string
	wantSuccess            bool
}

func runPAMProfileTest(t *testing.T, gcc string, test pamProfileTestCase) {
	t.Helper()

	testDir := t.TempDir()

	profileDir := filepath.Join(testDir, "dconf", "profile")
	policiesDir := filepath.Join(testDir, "policies")
	adsysctlPath := filepath.Join(testDir, "fake-adsysctl")
	callsPath := filepath.Join(testDir, "calls")
	profileName := test.wantProfile
	if profileName == "<unset>" {
		profileName = "unused-profile"
		if test.createProfileDirectory {
			profileName = "alice"
		}
	}
	profilePath := filepath.Join(profileDir, profileName)
	normalizedTarget := test.normalizedTarget
	if normalizedTarget == "" {
		normalizedTarget = test.wantProfile
		if normalizedTarget == "<unset>" {
			normalizedTarget = "unused-profile"
		}
	}

	hostname, err := os.Hostname()
	require.NoError(t, err)
	machineCachePath := filepath.Join(policiesDir, hostname)
	if test.hasMachineCache {
		require.NoError(t, os.MkdirAll(machineCachePath, 0700))
	}

	if test.createProfileDirectory {
		require.NoError(t, os.MkdirAll(profilePath, 0700))
	}

	script := `#!/bin/sh
printf '%s' "$1" >> "$ADSYS_TEST_CALLS"
shift
for arg do
    printf '\t%s' "$arg" >> "$ADSYS_TEST_CALLS"
done
printf '\n' >> "$ADSYS_TEST_CALLS"

if [ "$1" = "-m" ]; then
    mkdir -p "$ADSYS_TEST_MACHINE_CACHE" || exit 70
    exit 0
fi

if [ "$ADSYS_TEST_FAIL_USER" = "1" ]; then
    exit 17
fi

if [ "$ADSYS_TEST_CREATE_PROFILE" = "1" ]; then
    mkdir -p "$ADSYS_TEST_PROFILE_DIR" || exit 71
    : > "$ADSYS_TEST_PROFILE" || exit 72
fi
case " $* " in
    *" --print-normalized-target "*) printf '%s\n' "$ADSYS_TEST_NORMALIZED_TARGET" ;;
esac
exit 0
`
	//nolint:gosec // G306 - The fake adsysctl must be executable by execv.
	require.NoError(t, os.WriteFile(adsysctlPath, []byte(script), 0700))

	harness := buildPAMHarness(t, gcc, filepath.Join(policiesDir, "%s"), profileDir, adsysctlPath)
	ccachePath := filepath.Join(testDir, "ccache")
	//nolint:gosec // G204 - The harness is built in a test directory and takes a table-controlled username.
	cmd := exec.Command(harness, test.username)
	cmd.Env = append(os.Environ(),
		"ADSYS_TEST_KRB5CCNAME=KRB5CCNAME=FILE:"+ccachePath,
		"ADSYS_TEST_CALLS="+callsPath,
		"ADSYS_TEST_MACHINE_CACHE="+machineCachePath,
		"ADSYS_TEST_CREATE_PROFILE="+boolToEnv(test.createProfile),
		"ADSYS_TEST_FAIL_USER="+boolToEnv(test.failUserUpdate),
		"ADSYS_TEST_PROFILE="+profilePath,
		"ADSYS_TEST_PROFILE_DIR="+profileDir,
		"ADSYS_TEST_NORMALIZED_TARGET="+normalizedTarget,
	)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "running PAM harness: %s", output)

	var pamReturn int
	var dconfProfile string
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		switch {
		case strings.HasPrefix(line, "pam_return="):
			pamReturn, err = strconv.Atoi(strings.TrimPrefix(line, "pam_return="))
			require.NoError(t, err, "parsing PAM return code from %q", line)
		case strings.HasPrefix(line, "dconf_profile="):
			dconfProfile = strings.TrimPrefix(line, "dconf_profile=")
		}
	}
	if test.wantSuccess {
		require.Equal(t, 0, pamReturn, "harness output: %s", output)
	} else {
		require.NotZero(t, pamReturn, "harness output: %s", output)
	}
	require.Equal(t, test.wantProfile, dconfProfile, "harness output: %s", output)

	callsContent, err := os.ReadFile(callsPath)
	require.NoError(t, err)
	var calls [][]string
	for _, line := range strings.Split(strings.TrimSpace(string(callsContent)), "\n") {
		if line == "" {
			continue
		}
		calls = append(calls, strings.Split(line, "\t"))
	}

	wantCalls := make([][]string, 0, 2)
	if !test.hasMachineCache {
		wantCalls = append(wantCalls, []string{"update", "-m"})
	}
	wantCalls = append(wantCalls, []string{"update", "--print-normalized-target", test.username, ccachePath})
	require.Equal(t, wantCalls, calls, "adsysctl call order")
}

func buildPAMHarness(t *testing.T, gcc, policiesDir, profileDir, adsysctlPath string) string {
	t.Helper()

	binary := filepath.Join(t.TempDir(), "pam-adsys-harness")
	args := []string{
		"-Wall",
		"-Wextra",
		"-Wno-unused-parameter",
		"-Werror",
		"-DADSYS_POLICIES_DIR=" + strconv.Quote(policiesDir),
		"-DADSYS_DCONF_PROFILE_DIR=" + strconv.Quote(profileDir),
		"-DADSYSCTL_PATH=" + strconv.Quote(adsysctlPath),
		filepath.Join(pamSourceDir, "testdata", "pam_adsys_harness.c"),
		filepath.Join(pamSourceDir, "pam_adsys.c"),
		"-lpam",
		"-o",
		binary,
	}
	//nolint:gosec // G204 - gcc comes from PATH and all compilation arguments are controlled by the test.
	cmd := exec.Command(gcc, args...)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "compiling PAM harness: %s", output)
	return binary
}

func requirePAMTestToolchain(t *testing.T) string {
	t.Helper()

	gcc, err := exec.LookPath("gcc")
	if err != nil {
		t.Skip("skipping PAM C harness: gcc is unavailable")
	}

	//nolint:gosec // G204 - gcc is resolved from PATH before checking development headers.
	preflight := exec.Command(gcc, "-fsyntax-only", "-x", "c", "-")
	preflight.Stdin = strings.NewReader(`#include <security/_pam_macros.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>
int main(void) { return 0; }
`)
	if output, err := preflight.CombinedOutput(); err != nil {
		if strings.Contains(string(output), "No such file or directory") && strings.Contains(string(output), "security/") {
			t.Skipf("skipping PAM C harness: PAM development headers are unavailable: %s", output)
		}
		t.Fatalf("checking PAM development headers: %v: %s", err, output)
	}
	return gcc
}

func boolToEnv(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

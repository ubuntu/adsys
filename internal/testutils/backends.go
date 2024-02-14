package testutils

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/ad/backends"
)

// FormatBackendCalls takes a backend and returns a string containing a pretty
// representation of all calls to the exported functions of the interface.
func FormatBackendCalls(t *testing.T, backend backends.Backend) string {
	t.Helper()

	var got bytes.Buffer
	got.WriteString(fmt.Sprintf("* Domain(): %s\n", backend.Domain()))

	serverFQDN, err := backend.ServerFQDN(context.Background())
	serverLine := fmt.Sprintf("* ServerFQDN(): %s\n", serverFQDN)
	if err != nil {
		serverLine = fmt.Sprintf("* ServerFQDN ERROR(): %s\n", err)
	}
	got.WriteString(serverLine)

	isOnline, err := backend.IsOnline()
	isOnlineLine := fmt.Sprintf("* IsOnline(): %t\n", isOnline)
	if err != nil {
		isOnlineLine = fmt.Sprintf("* IsOnline ERROR(): %s\n", err)
	}
	got.WriteString(isOnlineLine)

	hostKrb5CCName, err := backend.HostKrb5CCName()
	hostKrb5CCNameLine := fmt.Sprintf("* HostKrb5CCName(): %s\n", hostKrb5CCName)
	if err != nil {
		hostKrb5CCNameLine = fmt.Sprintf("* HostKrb5CCName ERROR(): %s\n", err)
	}
	got.WriteString(hostKrb5CCNameLine)

	got.WriteString(fmt.Sprintf("* DefaultDomainSuffix(): %s\n", backend.DefaultDomainSuffix()))
	got.WriteString(fmt.Sprintf("* Config():\n%s\n", backend.Config()))

	return got.String()
}

// BuildWinbindMock takes the path to the location of the winbind internal
// package and builds the libwbclient mock for use with package or integration
// tests.
func BuildWinbindMock(t *testing.T, goPkgPath string) string {
	t.Helper()

	cmd := exec.Command("pkg-config", "--cflags-only-I", "wbclient")
	cflags, err := cmd.Output()
	require.NoError(t, err, "libwbclient-dev is not installed on disk, either skip these tests or install the required package")

	// Build mock libwbclient
	tmpdir := t.TempDir()
	libPath := filepath.Join(tmpdir, "libwbclient.so.0")
	args := strings.Fields(string(cflags))
	args = append(args, "-fPIC", "-shared", filepath.Join(goPkgPath, "mock/libwbclient_mock.c"), "-o", libPath)
	// #nosec G204: this is only for tests, under controlled args
	out, err := exec.Command("gcc", args...).CombinedOutput()
	require.NoError(t, err, "failed to build mock libwbclient: ", string(out))

	return libPath
}

// BuildKrb5Mock takes the path to the location of the ad internal package and
// builds the libkrb5 mock for use with package or integration tests.
func BuildKrb5Mock(t *testing.T, goPkgPath string) string {
	t.Helper()

	filesToCompile := []string{filepath.Join(goPkgPath, "mock", "libkrb5_mock.c")}

	// We only compile the krb5_init_context mock for package tests, as on
	// integration tests it interferes with the real krb5 library in samba.
	if goPkgPath == "." {
		filesToCompile = append(filesToCompile, filepath.Join(goPkgPath, "mock", "libkrb5_package_tests_mock.c"))
	}

	// Build mock libkrb5
	tmpdir := t.TempDir()
	libPath := filepath.Join(tmpdir, "libkrb5.so")
	args := []string{"-fPIC", "-shared"}
	args = append(args, filesToCompile...)
	args = append(args, "-o", libPath)
	// #nosec G204: this is only for tests, under controlled args
	out, err := exec.Command("gcc", args...).CombinedOutput()
	require.NoError(t, err, "failed to build mock libkrb5: ", string(out))

	return libPath
}

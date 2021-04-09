package adsys_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/config"
)

func TestPolicyAdmx(t *testing.T) {
	tests := map[string]struct {
		arg              string
		distroOption     string
		polkitAnswer     string
		daemonNotStarted bool

		wantErr bool
	}{
		"LTS only content":               {arg: "lts-only", polkitAnswer: "yes"},
		"All supported releases content": {arg: "all", polkitAnswer: "yes"},

		"Accept distro option": {arg: "lts-only", distroOption: "Ubuntu", polkitAnswer: "yes"},

		"Need one valid argument": {polkitAnswer: "yes", wantErr: true},

		"Admx generation denied":    {arg: "lts-only", polkitAnswer: "no"},
		"Fail on non stored distro": {arg: "lts-only", distroOption: "Tartanpion", polkitAnswer: "yes", wantErr: true},
		"Fail on invalid arg":       {arg: "something", polkitAnswer: "yes", wantErr: true},
		"Daemon not responding":     {arg: "lts-only", daemonNotStarted: true, wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			defer polkitAnswer(t, tc.polkitAnswer)()

			conf, quit := runDaemon(t, !tc.daemonNotStarted)
			defer quit()
			args := []string{"policy", "admx"}
			if tc.arg != "" {
				args = append(args, tc.arg)
			}
			distro := config.DistroID
			if tc.distroOption != "" {
				args = append(args, "--distro", tc.distroOption)
				distro = tc.distroOption
			}
			dest := t.TempDir()
			defer chdir(t, dest)()
			_, err := runClient(t, conf, args...)
			if tc.wantErr {
				require.Error(t, err, "client should exit with an error")
				return
			}
			require.NoError(t, err, "client should exit with no error")

			// Ensure files exists
			_, err = os.Stat(filepath.Join(dest, fmt.Sprintf("%s.admx", distro)))
			require.NoError(t, err, "admx file exists for this distro")
			_, err = os.Stat(filepath.Join(dest, fmt.Sprintf("%s.adml", distro)))
			require.NoError(t, err, "adml file exists for this distro")
		})
	}
}

func chdir(t *testing.T, dir string) func() {
	t.Helper()

	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("Setup: Can’t get current directory: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Setup: Can’t change current directory: %v", err)
	}
	return func() {
		if err := os.Chdir(orig); err != nil {
			t.Fatalf("Teardown: Can’t restore current directory: %v", err)
		}
	}
}

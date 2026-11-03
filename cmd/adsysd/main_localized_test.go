//go:build !withmo || windows

// The help is only translated here when the catalogs are embedded (see
// po/embedder.go): withmo builds, such as the Debian package, read them from
// the installed locale directory instead.

package main

import (
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/cmd/adsysd/client"
	"github.com/ubuntu/adsys/cmd/adsysd/daemon"
)

func TestMainAppLocalizedHelp(t *testing.T) {
	if os.Getenv("ADSYS_CALL_MAIN") != "" {
		os.Args = []string{os.Getenv("ADSYS_MAIN_ARGV0"), "--help"}
		main()
		return
	}

	tests := map[string]struct {
		argv0 string

		wantHelp string
	}{
		"Client help is localized": {argv0: client.CmdName, wantHelp: "Outil en ligne de commande de la suite d'intégration avec Active Directory."},
		"Daemon help is localized": {argv0: daemon.CmdName, wantHelp: "Démon de la suite d'intégration avec Active Directory."},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// #nosec G204,G702: this is only for tests, under controlled args
			cmd := exec.Command(os.Args[0], "-test.run=TestMainAppLocalizedHelp")
			cmd.Env = append(os.Environ(), "ADSYS_CALL_MAIN=1", "ADSYS_MAIN_ARGV0="+tc.argv0, "LANGUAGE=fr")
			out, err := cmd.CombinedOutput()
			require.NoError(t, err, "Main should not return an error: %s", out)
			require.Contains(t, string(out), tc.wantHelp, "Help should be printed in the language selected by the environment")
		})
	}
}

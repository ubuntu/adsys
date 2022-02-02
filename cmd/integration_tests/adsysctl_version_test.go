package adsys_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersion(t *testing.T) {
	tests := map[string]struct {
		systemAnswer     string
		daemonNotStarted bool

		wantErr bool
	}{
		"Get client version":           {systemAnswer: "polkit_yes"},
		"Version is always authorized": {systemAnswer: "polkit_no"},
		"Daemon not responding":        {daemonNotStarted: true, wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			systemAnswer(t, tc.systemAnswer)

			conf := createConf(t, "")
			if !tc.daemonNotStarted {
				defer runDaemon(t, conf)()
			}

			out, err := runClient(t, conf, "version")
			if tc.wantErr {
				require.Error(t, err, "client should exit with an error")
				// Client version is still printed
				assert.True(t, strings.HasPrefix(out, "adsysctl\t"), "Start printing client name")
				version := strings.TrimSpace(strings.TrimPrefix(out, "adsysctl\t"))
				assert.NotEmpty(t, version, "Version is printed")
				assert.NotContains(t, out, "adsysd\t", "No adsysd version is found")
				return
			}

			require.NoError(t, err, "client should exit with no error")
			lines := strings.Split(out, "\n")
			for i, content := range []string{"adsysctl", "adsysd"} {
				assert.True(t, strings.HasPrefix(lines[i], content+"\t"), "Start printing element name")
				version := strings.TrimSpace(strings.TrimPrefix(lines[i], content+"\t"))
				assert.NotEmpty(t, version, "Version is printed")
			}
		})
	}
}

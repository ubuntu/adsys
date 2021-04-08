package adsys_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStop(t *testing.T) {
	tests := map[string]struct {
		polkitAnswer     string
		daemonNotStarted bool
		force            bool

		wantErr bool
	}{
		"Stop daemon":           {polkitAnswer: "yes"},
		"Stop daemon denied":    {polkitAnswer: "no", wantErr: true},
		"Daemon not responding": {daemonNotStarted: true, wantErr: true},

		"Force stop doesn’t exit on error": {polkitAnswer: "yes", force: true, wantErr: false},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			defer polkitAnswer(t, tc.polkitAnswer)()

			conf, quit := runDaemon(t, !tc.daemonNotStarted)
			defer quit()

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

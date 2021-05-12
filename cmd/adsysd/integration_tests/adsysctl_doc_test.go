package adsys_test

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/doc"
)

func TestDocChapter(t *testing.T) {
	orig := os.Getenv("GLAMOUR_STYLE")
	err := os.Setenv("GLAMOUR_STYLE", "notty")
	require.NoError(t, err, "Setup: can’t set GLAMOUR_STYLE env variable")
	defer func() {
		err := os.Setenv("GLAMOUR_STYLE", orig)
		require.NoError(t, err, "Teardown: can’t restore GLAMOUR_STYLE env variable")
	}()

	tests := map[string]struct {
		chapter          string
		raw              bool
		polkitAnswer     string
		daemonNotStarted bool

		wantErr bool
	}{
		"Get documentation chapter": {chapter: "intro"},
		"Get raw documentation":     {chapter: "intro", raw: true},

		// Tried to match filename
		"Get documentation chapter with prefix":    {chapter: "1-intro"},
		"Get documentation chapter with full name": {chapter: "1-intro.md"},

		"Get documentation is always authorized": {polkitAnswer: "no", chapter: "intro"},

		// Error cases
		"Daemon not responding": {daemonNotStarted: true, wantErr: true},
		"Nonexistent chapter":   {chapter: "nonexistent-chapter", wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			if tc.polkitAnswer == "" {
				tc.polkitAnswer = "yes"
			}
			polkitAnswer(t, tc.polkitAnswer)

			conf := createConf(t, "")
			if !tc.daemonNotStarted {
				defer runDaemon(t, conf)()
			}

			args := []string{"doc", tc.chapter}
			if tc.raw {
				args = append(args, "-r")
			}
			out, err := runClient(t, conf, args...)
			if tc.wantErr {
				require.Error(t, err, "client should exit with an error")
				return
			}

			require.NoError(t, err, "client should exit with no error")
			require.NotEmpty(t, out, "some documentation is printed")
			if tc.raw {
				assert.False(t, strings.HasPrefix(out, "\n  "), "markdown should not be rendered")
			} else {
				assert.True(t, strings.HasPrefix(out, "\n  "), "markdown should be rendered")
			}
		})
	}
}

func TestDocList(t *testing.T) {
	orig := os.Getenv("GLAMOUR_STYLE")
	err := os.Setenv("GLAMOUR_STYLE", "notty")
	require.NoError(t, err, "Setup: can’t set GLAMOUR_STYLE env variable")
	defer func() {
		err := os.Setenv("GLAMOUR_STYLE", orig)
		require.NoError(t, err, "Teardown: can’t restore GLAMOUR_STYLE env variable")
	}()

	tests := map[string]struct {
		raw              bool
		polkitAnswer     string
		daemonNotStarted bool

		wantErr bool
	}{
		"List every documentation chapter":        {},
		"Raw list of everu documentation chapter": {raw: true},

		"List documentation is always authorized": {polkitAnswer: "no"},

		// Error cases
		"Daemon not responding": {daemonNotStarted: true, wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			if tc.polkitAnswer == "" {
				tc.polkitAnswer = "yes"
			}
			polkitAnswer(t, tc.polkitAnswer)

			conf := createConf(t, "")
			if !tc.daemonNotStarted {
				defer runDaemon(t, conf)()
			}

			args := []string{"doc"}
			if tc.raw {
				args = append(args, "-r")
			}
			out, err := runClient(t, conf, args...)
			if tc.wantErr {
				require.Error(t, err, "client should exit with an error")
				return
			}

			require.NoError(t, err, "client should exit with no error")
			require.NotEmpty(t, out, "some list is printed")

			// Ensure all chapters are listed
			fs, err := doc.Dir.ReadDir(".")
			require.NoError(t, err, "can’t list documentation directory")
			for _, f := range fs {
				// Assume we respect the <prefix>-chaptername.md schema
				n := strings.TrimSuffix(strings.SplitN(f.Name(), "-", 2)[1], ".md")
				assert.Contains(t, out, n, "Chapter is listed")
			}

			if tc.raw {
				assert.False(t, strings.HasPrefix(out, "\n  "), "markdown should not be rendered")
			} else {
				assert.True(t, strings.HasPrefix(out, "\n  "), "markdown should be rendered")
			}
		})
	}
}

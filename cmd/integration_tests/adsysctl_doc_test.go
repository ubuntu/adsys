package adsys_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/doc"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestDocChapter(t *testing.T) {
	testutils.Setenv(t, "GLAMOUR_STYLE", "notty")

	fullName, strippedExt, baseName := getTestChapter(t, "02.")

	tests := map[string]struct {
		chapter          string
		format           string
		withDest         bool
		modifyCase       bool
		systemAnswer     string
		daemonNotStarted bool

		wantErr bool
	}{
		"Get documentation chapter": {chapter: baseName},
		"Get raw documentation":     {chapter: baseName, format: "raw"},
		"Get html documentation":    {chapter: baseName, format: "html"},

		"Write all documentation":            {withDest: true},
		"Write one documentation":            {chapter: baseName, withDest: true},
		"Write documentation in raw format":  {chapter: baseName, format: "raw", withDest: true},
		"Write documentation in html format": {chapter: baseName, format: "html", withDest: true},

		// Tried to match filename
		"Get documentation chapter with prefix":            {chapter: strippedExt},
		"Get documentation chapter with full name":         {chapter: fullName},
		"Get documentation chapter with non matching case": {chapter: baseName, modifyCase: true},

		"Get documentation is always authorized": {systemAnswer: "polkit_no", chapter: baseName},

		// Error cases
		"Daemon not responding":                        {daemonNotStarted: true, wantErr: true},
		"Nonexistent chapter":                          {chapter: "nonexistent-chapter", wantErr: true},
		"Error on exact name matching with wrong case": {chapter: fullName, modifyCase: true, wantErr: true},
		"Error on documentation in unknown format":     {format: "unknown format", wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			if tc.systemAnswer == "" {
				tc.systemAnswer = "polkit_yes"
			}
			systemAnswer(t, tc.systemAnswer)

			if tc.modifyCase {
				tc.chapter = strings.ToUpper(tc.chapter)
				if strings.HasSuffix(tc.chapter, ".MD") {
					tc.chapter = strings.TrimSuffix(tc.chapter, ".MD") + ".md"
				}
			}

			conf := createConf(t, "")
			if !tc.daemonNotStarted {
				defer runDaemon(t, conf)()
			}

			args := []string{"doc"}
			if tc.chapter != "" {
				args = append(args, tc.chapter)
			}
			if tc.format != "" {
				args = append(args, "--format", tc.format)
			}
			var dest string
			if tc.withDest {
				dest = t.TempDir()
				err := os.RemoveAll(dest)
				require.NoError(t, err, "Setup: can’t delete destination directory")
				args = append(args, "--dest", dest)
			}
			out, err := runClient(t, conf, args...)
			if tc.wantErr {
				require.Error(t, err, "client should exit with an error")
				return
			}

			require.NoError(t, err, "client should exit with no error")

			// Printing on stdout
			if !tc.withDest {
				require.NotEmpty(t, out, "some documentation is printed")
				// Images urls are translated to online version
				assert.NotContains(t, out, "(images/", "No local images are referenced")

				switch tc.format {
				case "markdown":
					assert.True(t, strings.HasPrefix(out, "\n  "), "markdown should be rendered")
					assert.Contains(t, out, "###", "markdown should be printed")
				case "html":
					assert.Contains(t, out, "<html>", "html should be printed")
				case "raw":
					assert.False(t, strings.HasPrefix(out, "\n  "), "markdown should not be rendered")
				}
				return
			}

			// Documentation written on disk
			fs, err := os.ReadDir(dest)
			require.NoError(t, err, "Destination directory exists")
			if tc.chapter == "" {
				require.True(t, len(fs) > 1, "Multiple files are created when requesting the whole documentation")
			}
			for _, f := range fs {
				content, err := os.ReadFile(filepath.Join(dest, f.Name()))
				require.NoError(t, err, "Can't read destination file")

				out = string(content)
				var ext string
				switch tc.format {
				case "markdown":
					ext = ".md"
					assert.True(t, strings.HasPrefix(out, "\n  "), "markdown should be rendered")
					assert.Contains(t, out, "###", "markdown should be printed")
				case "html":
					ext = ".html"
					assert.Contains(t, out, "<html>", "html should be printed")
				case "raw":
					assert.False(t, strings.HasPrefix(out, "\n  "), "markdown should not be rendered")
				}
				require.True(t, strings.HasSuffix(f.Name(), ext), "File %q has expected suffix: %q", f.Name(), ext)
			}
		})
	}
}

func TestDocList(t *testing.T) {
	testutils.Setenv(t, "GLAMOUR_STYLE", "notty")

	tests := map[string]struct {
		raw              bool
		systemAnswer     string
		daemonNotStarted bool

		wantErr bool
	}{
		"List every documentation chapter":        {},
		"Raw list of everu documentation chapter": {raw: true},

		"List documentation is always authorized": {systemAnswer: "polkit_no"},

		// Error cases
		"Daemon not responding": {daemonNotStarted: true, wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			if tc.systemAnswer == "" {
				tc.systemAnswer = "polkit_yes"
			}
			systemAnswer(t, tc.systemAnswer)

			conf := createConf(t, "")
			if !tc.daemonNotStarted {
				defer runDaemon(t, conf)()
			}

			args := []string{"doc"}
			if tc.raw {
				args = append(args, "--format", "raw")
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

// Returns the names(s) of the chapter used for testing corresponding to chapterPrefix,
// so tests do not break if chapters are renamed.
func getTestChapter(t *testing.T, chapterPrefix string) (fullName string, strippedExt string, baseName string) {
	t.Helper()

	fs, err := doc.Dir.ReadDir(".")
	if err != nil {
		t.Fatalf(i18n.G("could not list documentation directory: %v"), err)
	}

	// Sort all file names while they have their prefix
	var name string
	for _, f := range fs {
		if !strings.HasPrefix(f.Name(), chapterPrefix) {
			continue
		}
		name = f.Name()
	}

	if name == "" {
		t.Fatalf(i18n.G("could not find chapter starting with %s"), chapterPrefix)
	}

	return name, strings.TrimSuffix(name, ".md"), strings.TrimPrefix(strings.TrimSuffix(name, ".md"), chapterPrefix+"-")
}

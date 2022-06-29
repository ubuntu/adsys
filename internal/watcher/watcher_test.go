package watcher_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kardianos/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/config"
	"github.com/ubuntu/adsys/internal/testutils"
	"github.com/ubuntu/adsys/internal/watcher"
	"gopkg.in/ini.v1"
)

func TestWatchDirectory(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		filesToUpdate []string
		filesToRename []string
		filesToRemove []string
		existingDirs  []string

		wantErrNew   bool
		wantErrStart bool
		wantErrBump  bool

		wantVersions []int
	}{
		// without GPT.ini
		"New file, no gpt.ini":  {filesToUpdate: []string{"no_gpt/new"}, existingDirs: []string{"no_gpt"}, wantVersions: []int{1}},
		"No update, no gpt.ini": {existingDirs: []string{"no_gpt"}, wantVersions: []int{0}},

		// with GPT.ini
		"Update with existing gpt.ini": {filesToUpdate: []string{"one_file/new"}, existingDirs: []string{"one_file"}, wantVersions: []int{4}},
		"No update, existing gpt.ini":  {existingDirs: []string{"one_file"}, wantVersions: []int{3}},
		"Update existing file":         {filesToUpdate: []string{"one_file/alreadyexists"}, existingDirs: []string{"one_file"}, wantVersions: []int{4}},
		"Updating gpt.ini is a no-op":  {filesToUpdate: []string{"one_file/GPT.INI"}, existingDirs: []string{"one_file"}, wantVersions: []int{3}},

		// remove / rename
		"Remove root directory": {filesToRemove: []string{"one_file"}, existingDirs: []string{"one_file"}},
		"Remove file":           {filesToRemove: []string{"one_file/alreadyexists"}, existingDirs: []string{"one_file"}, wantVersions: []int{4}},
		"Rename file":           {filesToRename: []string{"one_file/alreadyexists"}, existingDirs: []string{"one_file"}, wantVersions: []int{4}},
		"Rename file and update": {
			filesToRename: []string{"one_file/alreadyexists"}, filesToUpdate: []string{"one_file/alreadyexists.bak"},
			existingDirs: []string{"one_file"}, wantVersions: []int{4}},

		// subdirectories
		"New file, subdir": {
			filesToUpdate: []string{"withsubdir/alreadyexistsDir/new"},
			existingDirs:  []string{"withsubdir"},
			wantVersions:  []int{3}},
		"Existing file, subdir": {
			filesToUpdate: []string{"withsubdir/alreadyexistsDir/alreadyexists"},
			existingDirs:  []string{"withsubdir"},
			wantVersions:  []int{3}},
		"New subdir": {
			filesToUpdate: []string{"withsubdir/dir/file"},
			existingDirs:  []string{"withsubdir"},
			wantVersions:  []int{3}},
		"Nested new subdirs": {
			filesToUpdate: []string{"withsubdir/otherdir/subdir/file"},
			existingDirs:  []string{"withsubdir"},
			wantVersions:  []int{3}},
		"Multiple nested subdirectories": {
			filesToUpdate: []string{"withsubdir/new", "withsubdir/alreadyexistsDir/alreadyexists"},
			existingDirs:  []string{"withsubdir", "withsubdir/alreadyexistsDir"},
			wantVersions:  []int{3, 3}},
		"Multiple nested subdirectories, only update nested file": {
			filesToUpdate: []string{"withsubdir/alreadyexistsDir/alreadyexists"},
			existingDirs:  []string{"withsubdir/alreadyexistsDir", "withsubdir"},
			wantVersions:  []int{3, 2}},
		"New subdir without file": {
			filesToUpdate: []string{"withsubdir/newsubdir/"},
			existingDirs:  []string{"withsubdir"},
			wantVersions:  []int{3}},
		"Combined case": {
			filesToUpdate: []string{
				"withsubdir/alreadyexists", "withsubdir/new", "withsubdir/dir/file",
				"withsubdir/alreadyexistsDir/alreadyexists", "withsubdir/alreadyexistsDir/new",
				"withsubdir/otherdir/subdir/file", "withsubdir/newdir/"},
			existingDirs: []string{"withsubdir"},
			wantVersions: []int{3}},

		// multiple directories
		"Multiple directories, only one is updated": {
			filesToUpdate: []string{"withsubdir/alreadyexists"},
			existingDirs:  []string{"one_file", "withsubdir"},
			wantVersions:  []int{3, 3},
		},
		"Multiple directories with different versions, all updated": {
			filesToUpdate: []string{"one_file/alreadyexists", "withsubdir/alreadyexists"},
			existingDirs:  []string{"one_file", "withsubdir"},
			wantVersions:  []int{4, 3},
		},

		// Error cases
		"Error on non existing directory":     {existingDirs: []string{"doesnotexist"}, wantErrStart: true},
		"Error on listing no directory":       {wantErrNew: true},
		"Error on updating malformed GPT.ini": {filesToUpdate: []string{"malformed/new"}, existingDirs: []string{"malformed"}, wantErrBump: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			temp := t.TempDir()
			var dirs []string
			for _, dir := range tc.existingDirs {
				if dir != "doesnotexist" {
					// Decouple configured dirs from copied dirs by only copying the root directory.
					// This supports nested subdirectories in existingDirs.
					rootDir, _, _ := strings.Cut(dir, "/")
					if _, err := os.Stat(filepath.Join(temp, rootDir)); os.IsNotExist(err) {
						testutils.Copy(t, filepath.Join("testdata", rootDir), filepath.Join(temp, rootDir))
					}
				}
				dirs = append(dirs, filepath.Join(temp, dir))
			}

			// Instantiate the object
			w, err := watcher.New(context.Background(), dirs)
			if tc.wantErrNew {
				require.Error(t, err, "New should have failed but hasn't")
				return
			}
			require.NoError(t, err, "Can't create watcher")

			// Start it
			err = w.Start(mockService{})
			if tc.wantErrStart {
				require.Error(t, err, "Start should have failed but hasn't")
				return
			}
			require.NoError(t, err, "Can't start watcher")
			defer w.Stop(mockService{})

			// Remove some files and directories
			for _, path := range tc.filesToRemove {
				err := os.RemoveAll(filepath.Join(temp, path))
				require.NoError(t, err, "Can't remove file")
			}

			// Rename some files and directories
			for _, path := range tc.filesToRename {
				err := os.Rename(filepath.Join(temp, path), filepath.Join(temp, path+".bak"))
				require.NoError(t, err, "Can't rename file")
			}

			// Update some files
			for _, path := range tc.filesToUpdate {
				// update the file if it exists
				if _, err := os.Stat(filepath.Join(temp, path)); err == nil {
					d := []byte("new content")
					if strings.HasSuffix(path, "GPT.INI") {
						data, err := os.ReadFile(filepath.Join(temp, path))
						require.NoError(t, err, "Can't read file")
						d = append(data, []byte("\n;comment string")...)
					}
					err := os.WriteFile(filepath.Join(temp, path), d, 0600)
					require.NoError(t, err, "Can't update file")
					continue
				}

				testutils.CreatePath(t, filepath.Join(temp, path))
			}

			testutils.WaitForWrites(t)

			// Stop the watcher
			err = w.Stop(mockService{})
			require.NoError(t, err, "Can't stop watcher")

			// compare GPT.ini version
			testutils.WaitForWrites(t)

			if len(tc.wantVersions) > 0 {
				for i, dir := range tc.existingDirs {
					if tc.wantErrBump {
						requireGPTVersionError(t, filepath.Join(temp, dir))
						return
					}
					assertGPTVersionEquals(t, filepath.Join(temp, dir), tc.wantVersions[i])
				}
			}
		})
	}
}

func TestRefreshGracePeriod(t *testing.T) {
	t.Parallel()

	dir := "withsubdir"
	temp := t.TempDir()
	dest := filepath.Join(temp, dir)
	testutils.Copy(t, filepath.Join("testdata", dir), dest)

	// Instantiate the object
	w, err := watcher.New(context.Background(), []string{dest}, watcher.WithRefreshDuration(time.Second))
	require.NoError(t, err, "Setup: Can't create watcher")

	// Start it
	err = w.Start(mockService{})
	require.NoError(t, err, "Setup: Can't start watcher")
	defer w.Stop(mockService{})

	// Modify first file
	err = os.WriteFile(filepath.Join(temp, dir, "alreadyexists"), []byte("new content"), 0600)
	require.NoError(t, err, "Setup: Can't update file")

	testutils.WaitForWrites(t)

	// Wait for half of the grace period
	time.Sleep(w.RefreshDuration() / 2)

	// GPT.ini version was not changed
	assertGPTVersionEquals(t, dest, 2)

	// Modify second file
	err = os.WriteFile(filepath.Join(temp, dir, "alreadyexistsDir", "alreadyexists"), []byte("new content"), 0600)
	require.NoError(t, err, "Setup: Can't update file")

	testutils.WaitForWrites(t)

	// Wait for 3/4 of the grace period (to be sure that we waited for more than one whole grace period in total).
	time.Sleep(time.Duration(float64(w.RefreshDuration()) * 0.75))

	// GPT.ini version was still not changed
	assertGPTVersionEquals(t, dest, 2)

	// Wait for another 1/2 of the grace period (to be sure that we waited for more than one whole grace period in total).
	time.Sleep(w.RefreshDuration() / 2)

	// GPT.ini version was updated
	assertGPTVersionEquals(t, dest, 3)
}

func TestUpdateDirs(t *testing.T) {
	t.Parallel()

	temp := t.TempDir()
	destKeep := filepath.Join(temp, "keep")
	destRemove := filepath.Join(temp, "remove")
	destAdd := filepath.Join(temp, "add")

	testutils.Copy(t, filepath.Join("testdata", "withsubdir"), destKeep)
	testutils.Copy(t, filepath.Join("testdata", "withsubdir"), destRemove)
	testutils.Copy(t, filepath.Join("testdata", "withsubdir"), destAdd)
	testutils.WaitForWrites(t, destKeep, destRemove, destAdd)

	// Instantiate the object
	w, err := watcher.New(context.Background(), []string{destRemove, destKeep})
	require.NoError(t, err, "Setup: Can't create watcher")

	// Start it
	err = w.Start(mockService{})
	require.NoError(t, err, "Setup: Can't start watcher")
	defer w.Stop(mockService{})

	// Check GPT versions on the 3 dirs
	assertGPTVersionEquals(t, destKeep, 2)
	assertGPTVersionEquals(t, destRemove, 2)
	assertGPTVersionEquals(t, destAdd, 2)

	// Modify one of the folder to check that it will be updated when changing dir
	updateFiles(t, []string{filepath.Join(destRemove, "alreadyexists")})

	// Change directories to watch
	err = w.UpdateDirs(context.Background(), []string{destKeep, destAdd})
	require.NoError(t, err, "Can't update watched dirs")

	// GPT.ini version was updated on the removed directory
	testutils.WaitForWrites(t)
	assertGPTVersionEquals(t, destRemove, 3)
	assertGPTVersionEquals(t, destKeep, 2)
	assertGPTVersionEquals(t, destAdd, 2)

	// Modify files in all directories
	updateFiles(t, []string{
		filepath.Join(destKeep, "alreadyexists"),
		filepath.Join(destRemove, "alreadyexists"),
		filepath.Join(destAdd, "alreadyexists")})

	// Stop the watcher
	err = w.Stop(mockService{})
	require.NoError(t, err, "Can't stop watcher")

	// compare GPT.ini version: only keep and add should be updated
	testutils.WaitForWrites(t)
	assertGPTVersionEquals(t, destKeep, 3)
	assertGPTVersionEquals(t, destAdd, 3)
	assertGPTVersionEquals(t, destRemove, 3) // remove was already 3
}

func TestUpdateDirsFailing(t *testing.T) {
	t.Parallel()

	// If UpdateDirs is failing, we are still watching the old directories.

	temp := t.TempDir()
	destKeep := filepath.Join(temp, "keep")
	destRemove := filepath.Join(temp, "remove")

	testutils.Copy(t, filepath.Join("testdata", "withsubdir"), destKeep)
	testutils.Copy(t, filepath.Join("testdata", "withsubdir"), destRemove)

	// Instantiate the object
	w, err := watcher.New(context.Background(), []string{destRemove, destKeep})
	require.NoError(t, err, "Setup: Can't create watcher")

	// Start it
	err = w.Start(mockService{})
	require.NoError(t, err, "Setup: Can't start watcher")
	defer w.Stop(mockService{})

	// Check GPT versions on the 2 dirs
	assertGPTVersionEquals(t, destKeep, 2)
	assertGPTVersionEquals(t, destRemove, 2)

	// Give some unexisting directories to watch
	err = w.UpdateDirs(context.Background(), []string{destKeep, "unexisting"})
	require.Error(t, err, "UpdateDirs should have failed but didn't")

	// Modify files in previous watched directories
	updateFiles(t, []string{
		filepath.Join(destKeep, "alreadyexists"),
		filepath.Join(destRemove, "alreadyexists")})

	// Stop the watcher
	err = w.Stop(mockService{})
	require.NoError(t, err, "Can't stop watcher")

	// compare GPT.ini version: only keep and add should be updated
	testutils.WaitForWrites(t)
	assertGPTVersionEquals(t, destKeep, 3)
	assertGPTVersionEquals(t, destRemove, 3)
}

func TestUpdateDirsWithEmptyDirSlice(t *testing.T) {
	t.Parallel()

	temp := t.TempDir()
	dirToWatch := filepath.Join(temp, "watchdir")
	testutils.Copy(t, filepath.Join("testdata", "withsubdir"), dirToWatch)

	// Instantiate the object
	w, err := watcher.New(context.Background(), []string{dirToWatch})
	require.NoError(t, err, "Setup: Can't create watcher")

	// Start it
	err = w.Start(mockService{})
	require.NoError(t, err, "Setup: Can't start watcher")
	defer w.Stop(mockService{})

	// Update the watched directories with an empty slice
	err = w.UpdateDirs(context.Background(), []string{})
	require.ErrorContains(t, err, "need at least one directory to watch", "Updating directories should have failed")
}

func TestUpdateDirsOnStoppedWatcher(t *testing.T) {
	t.Parallel()

	temp := t.TempDir()
	prevDir := filepath.Join(temp, "prevdir")
	curDir := filepath.Join(temp, "curdir")
	testutils.Copy(t, filepath.Join("testdata", "withsubdir"), prevDir)
	testutils.Copy(t, filepath.Join("testdata", "withsubdir"), curDir)

	// Instantiate the object
	w, err := watcher.New(context.Background(), []string{prevDir})
	require.NoError(t, err, "Setup: Can't create watcher")

	// Check initial GPT version on the new directory
	assertGPTVersionEquals(t, curDir, 2)

	// Update the stopped watcher with the new directory
	err = w.UpdateDirs(context.Background(), []string{curDir})
	require.NoError(t, err, "UpdateDirs should have succeeded")
	defer w.Stop(mockService{})

	// Update something in the new directory to confirm it's watched
	updateFiles(t, []string{filepath.Join(curDir, "alreadyexists")})

	// Stop the watcher
	err = w.Stop(mockService{})
	require.NoError(t, err, "Can't stop watcher")

	// Check updated GPT version on the new directory
	testutils.WaitForWrites(t)
	assertGPTVersionEquals(t, curDir, 3)
}

func TestStopWithoutStart(t *testing.T) {
	t.Parallel()

	temp := t.TempDir()
	w, err := watcher.New(context.Background(), []string{temp})
	require.NoError(t, err, "Can't create watcher")

	var s service.Service = mockService{}

	err = w.Stop(s)
	require.Error(t, err, "Stop should have failed but hasn't")
}

func assertGPTVersionEquals(t *testing.T, path string, version int) {
	t.Helper()

	gptfile := filepath.Join(path, "GPT.INI")

	var gptFileExists bool
	if _, err := os.Stat(gptfile); err == nil {
		gptFileExists = true
	}

	if version == 0 {
		require.False(t, gptFileExists, "GPT.ini should not exist")
		return
	}
	require.True(t, gptFileExists, "GPT.ini not created")

	cfg, err := ini.Load(gptfile)
	require.NoError(t, err, "Can't load GPT.ini")

	v, err := cfg.Section("General").Key("Version").Int()
	require.NoError(t, err, "Can't get GPT.ini version as an integer")

	assert.Equal(t, version, v, "GPT.ini version is not equal to the expected one")
}

func requireGPTVersionError(t *testing.T, path string) {
	t.Helper()

	gptfile := filepath.Join(path, "GPT.INI")

	var gptFileExists bool
	if _, err := os.Stat(gptfile); err == nil {
		gptFileExists = true
	}
	require.True(t, gptFileExists, "GPT.ini not created")

	cfg, err := ini.Load(gptfile)
	require.NoError(t, err, "Can't load GPT.ini")

	_, err = cfg.Section("General").Key("Version").Int()
	require.Error(t, err, "Version should be invalid")
}

func updateFiles(t *testing.T, files []string) {
	t.Helper()

	for _, file := range files {
		err := os.WriteFile(file, []byte("new content"), 0600)
		require.NoError(t, err, "Can't write to file")
	}
	testutils.WaitForWrites(t)
}

type mockService struct{}

func (mockService) Run() error       { return nil }
func (mockService) Start() error     { return nil }
func (mockService) Stop() error      { return nil }
func (mockService) Restart() error   { return nil }
func (mockService) Install() error   { return nil }
func (mockService) Uninstall() error { return nil }
func (mockService) Logger(errs chan<- error) (service.Logger, error) {
	return service.ConsoleLogger, nil
}
func (mockService) SystemLogger(errs chan<- error) (service.Logger, error) {
	return service.ConsoleLogger, nil
}
func (mockService) String() string                  { return "" }
func (mockService) Platform() string                { return "" }
func (mockService) Status() (service.Status, error) { return 0, nil }

func TestMain(m *testing.M) {
	config.SetVerboseMode(2)
	m.Run()
}

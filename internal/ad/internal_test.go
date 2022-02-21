package ad

import (
	"context"
	// #nosec: G501: we are using it only for comparing directory tree content in tests.
	"crypto/md5"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/termie/go-shutil"
	"github.com/ubuntu/adsys/internal/consts"
	"github.com/ubuntu/adsys/internal/testutils"
)

var Update bool

func TestFetch(t *testing.T) {
	t.Parallel() // libsmbclient overrides SIGCHILD, but we have one global lock

	bus := testutils.NewDbusConn(t)

	tests := map[string]struct {
		adDomain               string
		gpos                   []string
		assetsURL              string
		concurrentGposDownload []string
		existing               map[string]string
		makeReadOnlyOnSource   []string

		want                map[string]string
		wantAssetsRefreshed bool
		wantErr             bool
	}{
		"one new gpo": {
			gpos: []string{"gpo1"},
			want: map[string]string{"Policies/gpo1": "Policies/gpo1"},
		},
		"two new gpos": {
			gpos: []string{"gpo1", "gpo2"},
			want: map[string]string{
				"Policies/gpo1": "Policies/gpo1",
				"Policies/gpo2": "Policies/gpo2",
			},
		},

		"gpo already up to date": {
			gpos:     []string{"gpo1"},
			existing: map[string]string{"Policies/gpo1": "Policies/gpo1"},
			want:     map[string]string{"Policies/gpo1": "Policies/gpo1"},
		},
		"two gpos, one already up to date, one new": {
			gpos:     []string{"gpo1", "gpo2"},
			existing: map[string]string{"Policies/gpo1": "Policies/gpo1"},
			want: map[string]string{
				"Policies/gpo1": "Policies/gpo1",
				"Policies/gpo2": "Policies/gpo2",
			},
		},

		"gpo is refreshed": {
			gpos:     []string{"gpo1"},
			existing: map[string]string{"Policies/gpo1": "Policies/old_version"},
			want:     map[string]string{"Policies/gpo1": "Policies/gpo1"},
		},
		"two gpos, one already up to date, one should be refreshed": {
			gpos: []string{"gpo1", "gpo2"},
			existing: map[string]string{
				"Policies/gpo2": "Policies/gpo2",
				"Policies/gpo1": "Policies/old_version",
			},
			want: map[string]string{
				"Policies/gpo1": "Policies/gpo1",
				"Policies/gpo2": "Policies/gpo2",
			},
		},
		"two gpos, one should be refreshed, one new": {
			gpos:     []string{"gpo1", "gpo2"},
			existing: map[string]string{"Policies/gpo1": "Policies/old_version"},
			want: map[string]string{
				"Policies/gpo1": "Policies/gpo1",
				"Policies/gpo2": "Policies/gpo2",
			},
		},

		"local gpo is more recent than AD one": {
			gpos:     []string{"gpo2"},
			existing: map[string]string{"Policies/gpo2": "Policies/new_version"},
			want:     map[string]string{"Policies/gpo2": "Policies/new_version"},
		},
		"two gpos, one more recent, one up to date": {
			gpos: []string{"gpo2", "gpo1"},
			existing: map[string]string{
				"Policies/gpo2": "Policies/new_version",
				"Policies/gpo1": "Policies/gpo1",
			},
			want: map[string]string{
				"Policies/gpo2": "Policies/new_version",
				"Policies/gpo1": "Policies/gpo1",
			},
		},
		"two gpos, one more recent, one should be refreshed": {
			gpos: []string{"gpo2", "gpo1"},
			existing: map[string]string{
				"Policies/gpo2": "Policies/new_version",
				"Policies/gpo1": "Policies/old_version",
			},
			want: map[string]string{
				"Policies/gpo2": "Policies/new_version",
				"Policies/gpo1": "Policies/gpo1",
			},
		},
		"two gpos, one more recent, one new": {
			gpos:     []string{"gpo2", "gpo1"},
			existing: map[string]string{"Policies/gpo2": "Policies/new_version"},
			want: map[string]string{
				"Policies/gpo2": "Policies/new_version",
				"Policies/gpo1": "Policies/gpo1",
			},
		},

		"keep existing gpos intact": {
			gpos: []string{"gpo1"},
			existing: map[string]string{
				"Policies/gpo1": "Policies/gpo1",
				"Policies/gpo2": "Policies/gpo2",
			},
			want: map[string]string{
				"Policies/gpo1": "Policies/gpo1",
				"Policies/gpo2": "Policies/gpo2",
			},
		},

		"Local gpo redownloaded on missing GPT.INI": {
			gpos:     []string{"gpo1"},
			existing: map[string]string{"Policies/gpo1": "Policies/missing_gpt_ini"},
			want:     map[string]string{"Policies/gpo1": "Policies/gpo1"},
		},
		"Local gpo redownloaded on NaN version in GPT.INI": {
			gpos:     []string{"gpo1"},
			existing: map[string]string{"Policies/gpo1": "Policies/gpt_ini_version_NaN"},
			want:     map[string]string{"Policies/gpo1": "Policies/gpo1"},
		},
		"Local gpo redownloaded on version entry missing in GPT.INI": {
			gpos:     []string{"gpo1"},
			existing: map[string]string{"Policies/gpo1": "Policies/gpt_ini_version_missing"},
			want:     map[string]string{"Policies/gpo1": "Policies/gpo1"},
		},

		// Assets cases
		"assets only are downloaded": {
			adDomain:            "assetsonly.com",
			assetsURL:           "Distro",
			want:                map[string]string{"assets": "Distro"},
			wantAssetsRefreshed: true,
		},
		"assets root directory not present on SYSVOL issues a warning only": {
			adDomain:            "gpoonly.com",
			assetsURL:           "Distro",
			want:                nil,
			wantAssetsRefreshed: false,
		},
		"assets are updated to latest version": {
			adDomain:            "assetsonly.com",
			assetsURL:           "Distro",
			existing:            map[string]string{"assets": "Distroold"},
			want:                map[string]string{"assets": "Distro"},
			wantAssetsRefreshed: true,
		},
		"assets are not updated if version matches": {
			adDomain:            "assetsonly.com",
			assetsURL:           "Distro",
			existing:            map[string]string{"assets": "Distro"},
			want:                map[string]string{"assets": "Distro"},
			wantAssetsRefreshed: false,
		},
		"existing assets are kept if no assets downloadable provided": {
			adDomain:            "assetsonly.com",
			assetsURL:           "",
			existing:            map[string]string{"assets": "Distro"},
			want:                map[string]string{"assets": "Distro"},
			wantAssetsRefreshed: false,
		},
		"existing assets are removed if not present on SYSVOL": {
			adDomain:            "fakegpo.com",
			assetsURL:           "Distro",
			existing:            map[string]string{"assets": "Policies/gpo1"},
			want:                nil,
			wantAssetsRefreshed: true,
		},
		"assets is a file is not downloaded": {
			adDomain:            "assetsdirisfile.com",
			assetsURL:           "Ubuntu",
			want:                nil,
			wantAssetsRefreshed: false,
		},

		// Mix
		"gpos and assets": {
			adDomain:            "assetsandfakegpo.com",
			gpos:                []string{"gpo1"},
			assetsURL:           "Distro",
			want:                map[string]string{"assets": "Distro", "Policies/gpo1": "Policies/gpo1"},
			wantAssetsRefreshed: true,
		},

		// Concurrent downloads
		"concurrent different gpos": {
			gpos:                   []string{"gpo1"},
			concurrentGposDownload: []string{"gpo2"},
			want: map[string]string{
				"Policies/gpo1": "Policies/gpo1",
				"Policies/gpo2": "Policies/gpo2",
			},
		},
		"concurrent same gpos": {
			gpos:                   []string{"gpo1"},
			concurrentGposDownload: []string{"gpo1"},
			want: map[string]string{
				"Policies/gpo1": "Policies/gpo1",
			},
		},

		// Errors
		"Error unexistant remote gpo": {
			gpos: []string{"gpo_does_not_exists"}, want: nil, wantErr: true},
		"Error missing remote GPT.INI": {
			gpos: []string{"missing_gpt_ini"}, want: nil, wantErr: true},
		"Error remote version NaN": {
			gpos: []string{"gpt_ini_version_NaN"}, want: nil, wantErr: true},
		"Error remote version entry missing": {
			gpos: []string{"gpt_ini_version_missing"}, want: nil, wantErr: true},
		"Error keeps downloading other GPOS": {
			gpos:    []string{"missing_gpt_ini", "gpo2"},
			want:    map[string]string{"Policies/gpo2": "Policies/gpo2"},
			wantErr: true},
		/*
			This is to cover the error case on os.Removall() to clean up the directory. However
			Marking the assets/ directory or any subelement read only doesn’t help.
			"Error on cached assets not overwritable on refresh": {
				adDomain:             "assetsonly.com",
				assetsURL:            "Distro",
				existing:             map[string]string{"assets": "Distroold"},
				makeReadOnlyOnSource: []string{"assets"},
				want:                 map[string]string{"assets": "Distro"},
				wantErr:              true,
				wantAssetsRefreshed:  false,
			},
			"Error on cached assets not removable on remove": {
				adDomain:             "fakegpo.com",
				assetsURL:            "Distro",
				existing:             map[string]string{"assets": "Policies/gpo1"},
				makeReadOnlyOnSource: []string{"assets/GPT.INI", "assets"},
				wantErr:              true,
				want:                 map[string]string{"assets": "Policies/gpo1"},
				wantAssetsRefreshed:  false,
			},
		*/
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel() // libsmbclient overrides SIGCHILD, but we have one global lock
			dest, rundir := t.TempDir(), t.TempDir()

			if tc.adDomain == "" {
				tc.adDomain = "fakegpo.com"
			}

			adc, err := New(context.Background(), "ldap://UNUSED:1636/", tc.adDomain, bus,
				WithCacheDir(dest), WithRunDir(rundir), withoutKerberos(), WithSSSCacheDir("testdata/sss/db"))

			require.NoError(t, err, "Setup: cannot create ad object")

			// prepare by copying downloadables if any
			for n, src := range tc.existing {
				require.NoError(t,
					shutil.CopyTree(
						filepath.Join("testdata", "AD", "SYSVOL", tc.adDomain, src),
						filepath.Join(adc.sysvolCacheDir, n),
						&shutil.CopyTreeOptions{Symlinks: true, CopyFunction: shutil.Copy}),
					"Setup: can't copy initial downloadable directory")
			}

			for _, p := range tc.makeReadOnlyOnSource {
				testutils.MakeReadOnly(t, filepath.Join(adc.sysvolCacheDir, p))
			}

			smbBaseURL := fmt.Sprintf("smb://localhost:%d/SYSVOL/%s/", SmbPort, tc.adDomain)
			downloadables := make(map[string]string)
			for _, n := range tc.gpos {
				// differentiate the gpo name from the url base path
				downloadables[n+"-name"] = smbBaseURL + "Policies/" + n
			}

			if tc.assetsURL != "" {
				downloadables["assets"] = smbBaseURL + tc.assetsURL
			}

			var assetsRefreshed bool
			if tc.concurrentGposDownload == nil {
				assetsRefreshed, err = adc.fetch(context.Background(), "", downloadables)
				if tc.wantErr {
					require.NotNil(t, err, "fetch should return an error but didn't")
				} else {
					require.NoError(t, err, "fetch returned an error but shouldn't")
				}
				require.Equal(t, tc.wantAssetsRefreshed, assetsRefreshed, "returned value assetsRefreshed should be as expected")
			} else {
				concurrentGpos := make(map[string]string)
				for _, n := range tc.concurrentGposDownload {
					// differentiate the gpo name from the url base path
					concurrentGpos[n+"-name"] = smbBaseURL + "Policies/" + n
				}

				wg := sync.WaitGroup{}
				wg.Add(2)
				var assetsRefreshed1, assetsRefreshed2 bool
				go func() {
					defer wg.Done()
					assetsRefreshed1, err = adc.fetch(context.Background(), "", downloadables)
					if tc.wantErr {
						require.NotNil(t, err, "fetch should return an error but didn't")
					} else {
						require.NoError(t, err, "fetch returned an error but shouldn't")
					}
				}()
				go func() {
					defer wg.Done()
					var err2 error
					assetsRefreshed2, err2 = adc.fetch(context.Background(), "", concurrentGpos)
					if tc.wantErr {
						require.NotNil(t, err2, "fetch should return an error but didn't")
					} else {
						require.NoError(t, err2, "fetch returned an error but shouldn't")
					}
				}()
				wg.Wait()
				if tc.wantAssetsRefreshed {
					require.NotEqual(t, assetsRefreshed1, assetsRefreshed2, "only one fetch call should have assetsRefreshed set to true")
				} else {
					require.False(t, assetsRefreshed1, "assetsRefreshed1 should be false")
					require.False(t, assetsRefreshed2, "assetsRefreshed2 should be false")
				}
			}

			// Ensure that only wanted GPOs are cached
			cacheRootFiles, err := os.ReadDir(adc.sysvolCacheDir)
			require.NoError(t, err, "coudn't read gpo cache root directory")
			gotDirs, err := os.ReadDir(filepath.Join(adc.sysvolCacheDir, "Policies"))
			require.NoError(t, err, "coudn't read gpo cache Policies directory")
			gotDirs = append(gotDirs, cacheRootFiles...)

			// Diff on each gpo/assets dir content
			for _, f := range gotDirs {
				dirname := f.Name()
				switch dirname {
				case "Policies":
					// ignored, we will compare each gpo
					continue
				case "assets":
					// nothing to do
				default:
					dirname = filepath.Join("Policies", dirname)
				}
				_, ok := tc.want[dirname]
				assert.Truef(t, ok, "fetched file %s which is not in want list", dirname)

				goldPath := filepath.Join("testdata", "AD", "SYSVOL", tc.adDomain, tc.want[dirname])
				gpoTree := md5Tree(t, filepath.Join(adc.sysvolCacheDir, dirname))
				goldTree := md5Tree(t, goldPath)
				assert.Equalf(t, goldTree, gpoTree, "expected and after fetch for %q does not match", dirname)
			}
			// We add the Policies/ directory
			assert.Len(t, gotDirs, len(tc.want)+1, "unexpected number of elements in downloaded policy or assets")
		})
	}
}

func TestFetchWithUnreadableFile(t *testing.T) {
	t.Parallel() // libsmbclient overrides SIGCHILD, but we have one global lock

	bus := testutils.NewDbusConn(t)

	// Prepare downloadables with unreadable file.
	// Defer will work after all tests are done because we don’t run it in parallel
	downloadables := map[string]string{
		"gpo1-name": fmt.Sprintf("smb://localhost:%d/SYSVOL/broken.com/Policies/%s", SmbPort, "gpo1"),
	}

	tests := map[string]struct {
		withExistingGPO bool
	}{
		"without gpo initially don’t commit new partial GPO": {},
		"existing gpo is preserved":                          {withExistingGPO: true},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel() // libsmbclient overrides SIGCHILD, but we have one global lock

			dest, rundir := t.TempDir(), t.TempDir()

			adc, err := New(context.Background(), "ldap://UNUSED:1636/", "fakegpo.com", bus,
				WithCacheDir(dest), WithRunDir(rundir), withoutKerberos(), WithSSSCacheDir("testdata/sss/db"))
			require.NoError(t, err, "Setup: cannot create ad object")

			if tc.withExistingGPO {
				require.NoError(t,
					shutil.CopyTree(
						filepath.Join("testdata", "AD", "SYSVOL", "fakegpo.com", "Policies", "old_version"),
						filepath.Join(adc.sysvolCacheDir, "Policies", "gpo1"),
						&shutil.CopyTreeOptions{Symlinks: true, CopyFunction: shutil.Copy}),
					"Setup: can't copy initial gpo directory")
			}

			assetsRefreshed, err := adc.fetch(context.Background(), "", downloadables)
			require.NotNil(t, err, "fetch should return an error but didn't")

			if !tc.withExistingGPO {
				require.NoDirExists(t, filepath.Join(adc.sysvolCacheDir, "Policies", "gpo1"), "GPO directory shouldn't be committed on disk")
				return
			}

			// Diff on each gpo dir content
			goldPath := filepath.Join("testdata", "AD", "SYSVOL", "fakegpo.com", "Policies", "old_version")
			gpoTree := md5Tree(t, filepath.Join(adc.sysvolCacheDir, "Policies", "gpo1"))
			goldTree := md5Tree(t, goldPath)
			assert.Equalf(t, goldTree, gpoTree, "expected and after fetch GPO %q does not match", "gpo1")
			assert.False(t, assetsRefreshed, "we haven't refreshed assets")
		})
	}
}

func TestFetchTweakSysvolCacheDir(t *testing.T) {
	t.Parallel() // libsmbclient overrides SIGCHILD, but we have one global lock

	bus := testutils.NewDbusConn(t)

	tests := map[string]struct {
		removeSysvolCacheDir bool
		roSysvolCacheDir     bool
	}{
		"SysvolCacheDir doesn't exist": {removeSysvolCacheDir: true},
		"SysvolCacheDir is read only":  {roSysvolCacheDir: true},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel() // libsmbclient overrides SIGCHILD, but we have one global lock

			dest, rundir := t.TempDir(), t.TempDir()
			adc, err := New(context.Background(), "ldap://UNUSED:1636/", "fakegpo.com", bus,
				WithCacheDir(dest), WithRunDir(rundir), withoutKerberos(), WithSSSCacheDir("testdata/sss/db"))
			require.NoError(t, err, "Setup: cannot create ad object")

			if tc.removeSysvolCacheDir {
				require.NoError(t, os.RemoveAll(adc.sysvolCacheDir), "Setup: can’t remove sysvolCacheDir")
			}
			if tc.roSysvolCacheDir {
				testutils.MakeReadOnly(t, adc.sysvolCacheDir)
			}

			assetsRefreshed, err := adc.fetch(context.Background(), "", map[string]string{"gpo1-name": fmt.Sprintf("smb://localhost:%d/SYSVOL/fakegpo.com/Policies/gpo1", SmbPort)})

			require.NotNil(t, err, "fetch should return an error but didn't")
			assert.NoDirExists(t, filepath.Join(adc.sysvolCacheDir, "Policies", "gpo1"), "gpo1 shouldn't be downloaded")
			assert.False(t, assetsRefreshed, "we haven't refreshed assets")
		})
	}
}

func TestFetchOneGPOWhileParsingItConcurrently(t *testing.T) {
	t.Parallel() // libsmbclient overrides SIGCHILD, but we have one global lock

	bus := testutils.NewDbusConn(t)

	dest, rundir := t.TempDir(), t.TempDir()

	adc, err := New(context.Background(), "ldap://UNUSED:1636/", "gpoonly.com", bus,
		WithCacheDir(dest), WithRunDir(rundir), withoutKerberos(), WithSSSCacheDir("testdata/sss/db"))
	require.NoError(t, err, "Setup: cannot create ad object")

	// ensure the GPO is already downloaded with an older version to force redownload
	require.NoError(t,
		shutil.CopyTree(
			filepath.Join("testdata", "AD", "SYSVOL", "gpoonly.com", "Policies", "standard-old"),
			filepath.Join(adc.sysvolCacheDir, "Policies", "standard"),
			&shutil.CopyTreeOptions{Symlinks: true, CopyFunction: shutil.Copy}),
		"Setup: can't copy initial gpo directory")
	// create the lock made by fetch which is always called before parseGPOs in the public API
	adc.downloadables["standard-name"] = &downloadable{
		name: "standard-name",
		url:  fmt.Sprintf("smb://localhost:%d/SYSVOL/gpoonly.com/Policies/standard", SmbPort),
		mu:   &sync.RWMutex{},
	}

	// concurrent downloads and parsing
	gpos := map[string]string{
		"standard-name": adc.downloadables["standard-name"].url,
	}
	orderedGPOs := []gpo{{name: "standard-name", url: gpos["standard-name"]}}

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()

		assetsRefreshed, err := adc.fetch(context.Background(), "", gpos)
		require.NoError(t, err, "fetch returned an error but shouldn't")
		assert.False(t, assetsRefreshed, "we haven't refreshed assets")
	}()
	go func() {
		defer wg.Done()
		// we can’t test returned values as it’s either the old of new version of the gpo
		_, err := adc.parseGPOs(context.Background(), orderedGPOs, UserObject)
		require.NoError(t, err, "parseGPOs returned an error but shouldn't")
	}()
	wg.Wait()
}

func TestParseGPOConcurrent(t *testing.T) {
	t.Parallel() // libsmbclient overrides SIGCHILD, but we have one global lock

	bus := testutils.NewDbusConn(t)

	dest, rundir := t.TempDir(), t.TempDir()

	adc, err := New(context.Background(), "ldap://UNUSED:1636/", "gpoonly.com", bus,
		WithCacheDir(dest), WithRunDir(rundir), withoutKerberos(), WithSSSCacheDir("testdata/sss/db"))
	require.NoError(t, err, "Setup: cannot create ad object")

	// Fetch the GPO to set it up
	gpos := map[string]string{
		"standard-name": fmt.Sprintf("smb://localhost:%d/SYSVOL/gpoonly.com/Policies/standard", SmbPort),
	}
	orderedGPOs := []gpo{{name: "standard-name", url: gpos["standard-name"]}}
	assetsRefreshed, err := adc.fetch(context.Background(), "", gpos)
	require.NoError(t, err, "Setup: couldn’t do initial GPO fetch as returned an error but shouldn't")
	assert.False(t, assetsRefreshed, "we haven't refreshed assets")

	// concurrent parsing of GPO
	wg := sync.WaitGroup{}
	wg.Add(1000)
	for i := 0; i < 1000; i++ {
		go func() {
			defer wg.Done()
			// we can’t test returned values as it’s either the old of new version of the gpo
			_, err := adc.parseGPOs(context.Background(), orderedGPOs, UserObject)
			require.NoError(t, err, "parseGPOs returned an error but shouldn't")
		}()
	}
	wg.Wait()
}

const SmbPort = 1445

func TestMain(m *testing.M) {
	flag.BoolVar(&Update, "update", false, "update golden files")
	flag.Parse()

	// Don’t setup samba or sssd for mock helpers
	if strings.Contains(strings.Join(os.Args, " "), "TestMock") {
		m.Run()
		testutils.MergeCoverages()
		return
	}

	debug := flag.Bool("verbose", false, "Print debug log level information within the test")
	flag.Parse()
	if *debug {
		logrus.StandardLogger().SetLevel(logrus.DebugLevel)
	}

	// Samba
	// Prepare sysvol
	sysvolDir, err := os.MkdirTemp("", "adsys_tests_smbd_sysvol_")
	if err != nil {
		log.Fatalf("Setup: failed to create temporary sysvol for smb: %v", err)
	}
	// Copy content from our testdata
	if err := os.RemoveAll(sysvolDir); err != nil {
		log.Fatalf("Setup: failed to remove temporary sysvol for smb before copy: %v", err)
	}
	if err := shutil.CopyTree(
		filepath.Join("testdata", "AD", "SYSVOL"),
		sysvolDir,
		&shutil.CopyTreeOptions{Symlinks: true, CopyFunction: shutil.Copy}); err != nil {
		log.Fatalf("Setup: failed to copy sysvol to temporary directory for smb: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(sysvolDir); err != nil {
			log.Fatalf("Teardown: failed to cleanup temporary sysvol directory for smb: %v", err)
		}
	}()
	// change permission on our broken directory
	if err := os.Chmod(filepath.Join(sysvolDir, "broken.com", "Policies/gpo1/User/Gpo1File1"), 0200); err != nil {
		log.Fatalf("Setup: can't change permission on gpo file to simulate broken GPO: %v", err)
	}
	defer testutils.SetupSmb(SmbPort, sysvolDir)()

	// export SSSD domains
	defer testutils.StartLocalSystemBus()()

	conn, err := dbus.SystemBusPrivate()
	if err != nil {
		log.Fatalf("Setup: can't get a private system bus: %v", err)
	}
	defer func() {
		if err = conn.Close(); err != nil {
			log.Fatalf("Teardown: can't close system dbus connection: %v", err)
		}
	}()
	if err = conn.Auth(nil); err != nil {
		log.Fatalf("Setup: can't auth on private system bus: %v", err)
	}
	if err = conn.Hello(); err != nil {
		log.Fatalf("Setup: can't send hello message on private system bus: %v", err)
	}

	intro := fmt.Sprintf(`
	<node>
		<interface name="%s">
			<method name="ActiveServer">
				<arg direction="in" type="s"/>
				<arg direction="out" type="s"/>
			</method>
			<method name="IsOnline">
				<arg direction="out" type="b"/>
			</method>
		</interface>̀%s</node>`, consts.SSSDDbusInterface, introspect.IntrospectDataString)

	for _, s := range []sssd{
		{
			endpoint: "gpoonly_2ecom",
			domain:   "gpoonly.com",
			online:   true,
		},
		{
			endpoint: "assetsandgpo_2ecom",
			domain:   "assetsandgpo.com",
			online:   true,
		},
		{
			endpoint: "assetsonly_2ecom",
			domain:   "assetsonly.com",
			online:   true,
		},
		{
			endpoint: "assetsdirisfile_2ecom",
			domain:   "assetsdirisfile.com",
			online:   true,
		},
		{
			endpoint: "offline",
			domain:   "offline.com",
			online:   false,
		},
		{
			endpoint: "fakegpo_2ecom",
			domain:   "fakegpo.com",
			online:   true,
		},
		{
			endpoint: "emptyserver",
			domain:   "",
			online:   true,
		},
	} {
		if err := conn.Export(s, dbus.ObjectPath(consts.SSSDDbusBaseObjectPath+"/"+s.endpoint), consts.SSSDDbusInterface); err != nil {
			log.Fatalf("Setup: could not export %s %v", s.endpoint, err)
		}
		if err := conn.Export(introspect.Introspectable(intro), dbus.ObjectPath(consts.SSSDDbusBaseObjectPath+"/"+s.endpoint),
			"org.freedesktop.DBus.Introspectable"); err != nil {
			log.Fatalf("Setup: could not export introspectable for %s: %v", s.endpoint, err)
		}
	}
	reply, err := conn.RequestName(consts.SSSDDbusRegisteredName, dbus.NameFlagDoNotQueue)
	if err != nil {
		log.Fatalf("Setup: Failed to acquire sssd name on local system bus: %v", err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		log.Fatalf("Setup: Failed to acquire sssd name on local system bus: name is already taken")
	}

	m.Run()
	testutils.MergeCoverages()
}

// md5Tree build a recursive file list of dir and with their md5sum.
func md5Tree(t *testing.T, dir string) map[string]string {
	t.Helper()

	r := make(map[string]string)

	err := filepath.WalkDir(dir, func(path string, de fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("couldn't access path %q: %w", path, err)
		}

		md5Val := ""
		if !de.IsDir() {
			d, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			// #nosec: G401: we are using it only for comparing directory tree content in tests.
			md5Val = fmt.Sprintf("%x", md5.Sum(d))
		}
		r[strings.TrimPrefix(path, dir)] = md5Val
		return nil
	})

	if err != nil {
		t.Fatalf("error while listing directory: %v", err)
	}

	return r
}

type sssd struct {
	endpoint string
	domain   string
	online   bool
}

func (s sssd) ActiveServer(_ string) (string, *dbus.Error) {
	if s.domain == "" {
		return "", nil
	}
	return "myserver." + s.domain, nil
}

func (s sssd) IsOnline() (bool, *dbus.Error) {
	return s.online, nil
}

package ad

import (
	"context"
	"crypto/md5"
	"flag"
	"fmt"
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
	"github.com/ubuntu/adsys/internal/testutils"
)

const policyPath = "SYSVOL/localdomain/Policies"

var Update bool

func TestFetchGPO(t *testing.T) {
	t.Parallel() // libsmbclient overrides SIGCHILD, but we have one global lock

	bus := GetSystemBus(t)

	tests := map[string]struct {
		gpos                   []string
		concurrentGposDownload []string
		existingGpos           map[string]string

		want    map[string]string
		wantErr bool
	}{
		"one new gpo": {
			gpos: []string{"gpo1"},
			want: map[string]string{"gpo1": "gpo1"},
		},
		"two new gpos": {
			gpos: []string{"gpo1", "gpo2"},
			want: map[string]string{
				"gpo1": "gpo1",
				"gpo2": "gpo2",
			},
		},

		"gpo already up to date": {
			gpos:         []string{"gpo1"},
			existingGpos: map[string]string{"gpo1": "gpo1"},
			want:         map[string]string{"gpo1": "gpo1"},
		},
		"two gpos, one already up to date, one new": {
			gpos:         []string{"gpo1", "gpo2"},
			existingGpos: map[string]string{"gpo1": "gpo1"},
			want: map[string]string{
				"gpo1": "gpo1",
				"gpo2": "gpo2",
			},
		},

		"gpo is refreshed": {
			gpos:         []string{"gpo1"},
			existingGpos: map[string]string{"gpo1": "old_version"},
			want:         map[string]string{"gpo1": "gpo1"},
		},
		"two gpos, one already up to date, one should be refreshed": {
			gpos: []string{"gpo1", "gpo2"},
			existingGpos: map[string]string{
				"gpo2": "gpo2",
				"gpo1": "old_version",
			},
			want: map[string]string{
				"gpo1": "gpo1",
				"gpo2": "gpo2",
			},
		},
		"two gpos, one should be refreshed, one new": {
			gpos:         []string{"gpo1", "gpo2"},
			existingGpos: map[string]string{"gpo1": "old_version"},
			want: map[string]string{
				"gpo1": "gpo1",
				"gpo2": "gpo2",
			},
		},

		"local gpo is more recent than AD one": {
			gpos:         []string{"gpo2"},
			existingGpos: map[string]string{"gpo2": "new_version"},
			want:         map[string]string{"gpo2": "new_version"},
		},
		"two gpos, one more recent, one up to date": {
			gpos: []string{"gpo2", "gpo1"},
			existingGpos: map[string]string{
				"gpo2": "new_version",
				"gpo1": "gpo1",
			},
			want: map[string]string{
				"gpo2": "new_version",
				"gpo1": "gpo1",
			},
		},
		"two gpos, one more recent, one should be refreshed": {
			gpos: []string{"gpo2", "gpo1"},
			existingGpos: map[string]string{
				"gpo2": "new_version",
				"gpo1": "old_version",
			},
			want: map[string]string{
				"gpo2": "new_version",
				"gpo1": "gpo1",
			},
		},
		"two gpos, one more recent, one new": {
			gpos:         []string{"gpo2", "gpo1"},
			existingGpos: map[string]string{"gpo2": "new_version"},
			want: map[string]string{
				"gpo2": "new_version",
				"gpo1": "gpo1",
			},
		},

		"keep existing gpos intact": {
			gpos: []string{"gpo1"},
			existingGpos: map[string]string{
				"gpo1": "gpo1",
				"gpo2": "gpo2",
			},
			want: map[string]string{
				"gpo1": "gpo1",
				"gpo2": "gpo2",
			},
		},

		"Local gpo redownloaded on missing GPT.INI": {
			gpos:         []string{"gpo1"},
			existingGpos: map[string]string{"gpo1": "missing_gpt_ini"},
			want:         map[string]string{"gpo1": "gpo1"},
		},
		"Local gpo redownloaded on NaN version in GPT.INI": {
			gpos:         []string{"gpo1"},
			existingGpos: map[string]string{"gpo1": "gpt_ini_version_NaN"},
			want:         map[string]string{"gpo1": "gpo1"},
		},
		"Local gpo redownloaded on version entry missing in GPT.INI": {
			gpos:         []string{"gpo1"},
			existingGpos: map[string]string{"gpo1": "gpt_ini_version_missing"},
			want:         map[string]string{"gpo1": "gpo1"},
		},

		// Concurrent downloads
		"concurrent different gpos": {
			gpos:                   []string{"gpo1"},
			concurrentGposDownload: []string{"gpo2"},
			want: map[string]string{
				"gpo1": "gpo1",
				"gpo2": "gpo2",
			},
		},
		"concurrent same gpos": {
			gpos:                   []string{"gpo1"},
			concurrentGposDownload: []string{"gpo1"},
			want: map[string]string{
				"gpo1": "gpo1",
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
			want:    map[string]string{"gpo2": "gpo2"},
			wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel() // libsmbclient overrides SIGCHILD, but we have one global lock
			dest, rundir := t.TempDir(), t.TempDir()

			adc, err := New(context.Background(), "ldap://UNUSED:1636/", "localdomain", bus,
				WithCacheDir(dest), WithRunDir(rundir), withoutKerberos(), WithSSSCacheDir("testdata/sss/db"))

			require.NoError(t, err, "Setup: cannot create ad object")

			// prepare by copying GPOs if any
			for n, src := range tc.existingGpos {
				require.NoError(t,
					shutil.CopyTree(
						filepath.Join("testdata", "AD", policyPath, src),
						filepath.Join(adc.gpoCacheDir, n),
						&shutil.CopyTreeOptions{Symlinks: true, CopyFunction: shutil.Copy}),
					"Setup: can't copy initial gpo directory")
			}

			gpos := make(map[string]string)
			for _, n := range tc.gpos {
				// differentiate the gpo name from the url base path
				gpos[n+"-name"] = fmt.Sprintf("smb://localhost:%d/%s/%s", SmbPort, policyPath, n)
			}

			if tc.concurrentGposDownload == nil {
				err = adc.fetch(context.Background(), "", gpos)
				if tc.wantErr {
					require.NotNil(t, err, "fetch should return an error but didn't")
				} else {
					require.NoError(t, err, "fetch returned an error but shouldn't")
				}
			} else {
				concurrentGpos := make(map[string]string)
				for _, n := range tc.concurrentGposDownload {
					// differentiate the gpo name from the url base path
					concurrentGpos[n+"-name"] = fmt.Sprintf("smb://localhost:%d/%s/%s", SmbPort, policyPath, n)
				}

				wg := sync.WaitGroup{}
				wg.Add(2)
				go func() {
					defer wg.Done()
					err := adc.fetch(context.Background(), "", gpos)
					if tc.wantErr {
						require.NotNil(t, err, "fetch should return an error but didn't")
					} else {
						require.NoError(t, err, "fetch returned an error but shouldn't")
					}
				}()
				go func() {
					defer wg.Done()
					err := adc.fetch(context.Background(), "", concurrentGpos)
					if tc.wantErr {
						require.NotNil(t, err, "fetch should return an error but didn't")
					} else {
						require.NoError(t, err, "fetch returned an error but shouldn't")
					}
				}()
				wg.Wait()
			}

			// Ensure that only wanted GPOs are cached
			files, err := os.ReadDir(adc.gpoCacheDir)
			require.NoError(t, err, "coudn't read destination directory")
			for _, f := range files {
				_, ok := tc.want[f.Name()]
				assert.Truef(t, ok, "fetched file %s which is not in want list", f.Name())
			}
			assert.Len(t, files, len(tc.want), "unexpected number of elements in downloaded policy")

			// Diff on each gpo dir content
			for _, f := range files {
				goldPath := filepath.Join("testdata", "AD", policyPath, tc.want[f.Name()])
				gpoTree := md5Tree(t, filepath.Join(adc.gpoCacheDir, f.Name()))
				goldTree := md5Tree(t, goldPath)
				assert.Equalf(t, goldTree, gpoTree, "expected and after fetch GPO %q does not match", f.Name())
			}
		})
	}
}

func TestFetchGPOWithUnreadableFile(t *testing.T) {
	t.Parallel() // libsmbclient overrides SIGCHILD, but we have one global lock

	bus := GetSystemBus(t)

	// Prepare GPO with unreadable file.
	// Defer will work after all tests are done because we don’t run it in parallel
	gpos := map[string]string{
		"gpo1-name": fmt.Sprintf("smb://localhost:%d/broken/%s/%s", SmbPort, policyPath, "gpo1"),
	}
	require.NoError(t,
		shutil.CopyTree(
			filepath.Join("testdata", "AD", policyPath, "gpo1"),
			filepath.Join(brokenSmbDirShare, policyPath, "gpo1"),
			&shutil.CopyTreeOptions{Symlinks: true, CopyFunction: shutil.Copy}),
		"Setup: can't copy initial gpo directory")
	require.NoError(t,
		os.Chmod(filepath.Join(brokenSmbDirShare, policyPath, "gpo1/User/Gpo1File1"), 0200),
		"Setup: can't change permission on gpo file")
	t.Cleanup(func() { os.RemoveAll(filepath.Join(brokenSmbDirShare, policyPath, "gpo1")) })

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

			adc, err := New(context.Background(), "ldap://UNUSED:1636/", "localdomain", bus,
				WithCacheDir(dest), WithRunDir(rundir), withoutKerberos(), WithSSSCacheDir("testdata/sss/db"))
			require.NoError(t, err, "Setup: cannot create ad object")

			if tc.withExistingGPO {
				require.NoError(t,
					shutil.CopyTree(
						filepath.Join("testdata", "AD", policyPath, "old_version"),
						filepath.Join(adc.gpoCacheDir, "gpo1"),
						&shutil.CopyTreeOptions{Symlinks: true, CopyFunction: shutil.Copy}),
					"Setup: can't copy initial gpo directory")
			}

			err = adc.fetch(context.Background(), "", gpos)
			require.NotNil(t, err, "fetch should return an error but didn't")

			if !tc.withExistingGPO {
				require.NoDirExists(t, filepath.Join(adc.gpoCacheDir, "gpo1"), "GPO directory shouldn’t be committed on disk")
				return
			}

			// Diff on each gpo dir content
			goldPath := filepath.Join("testdata", "AD", policyPath, "old_version")
			gpoTree := md5Tree(t, filepath.Join(adc.gpoCacheDir, "gpo1"))
			goldTree := md5Tree(t, goldPath)
			assert.Equalf(t, goldTree, gpoTree, "expected and after fetch GPO %q does not match", "gpo1")
		})
	}
}

func TestFetchGPOTweakGPOCacheDir(t *testing.T) {
	t.Parallel() // libsmbclient overrides SIGCHILD, but we have one global lock

	bus := GetSystemBus(t)

	tests := map[string]struct {
		removeGPOCacheDir bool
		roGPOCacheDir     bool
	}{
		"GPOCacheDir doesn't exist": {removeGPOCacheDir: true},
		"GPOCacheDir is read only":  {roGPOCacheDir: true},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel() // libsmbclient overrides SIGCHILD, but we have one global lock

			dest, rundir := t.TempDir(), t.TempDir()
			adc, err := New(context.Background(), "ldap://UNUSED:1636/", "localdomain", bus,
				WithCacheDir(dest), WithRunDir(rundir), withoutKerberos(), WithSSSCacheDir("testdata/sss/db"))
			require.NoError(t, err, "Setup: cannot create ad object")

			if tc.removeGPOCacheDir {
				require.NoError(t, os.RemoveAll(adc.gpoCacheDir), "Setup: can’t remove gpoCacheDir")
			}
			if tc.roGPOCacheDir {
				require.NoError(t, os.Chmod(adc.gpoCacheDir, 0400), "Setup: can’t set gpoCacheDir to Read only")
			}

			err = adc.fetch(context.Background(), "", map[string]string{"gpo1-name": fmt.Sprintf("smb://localhost:%d/%s/gpo1", SmbPort, policyPath)})

			require.NotNil(t, err, "fetch should return an error but didn't")
			assert.NoDirExists(t, filepath.Join(adc.gpoCacheDir, "gpo1"), "gpo1 shouldn't be downloaded")
		})
	}
}

func TestFetchOneGPOWhileParsingItConcurrently(t *testing.T) {
	t.Parallel() // libsmbclient overrides SIGCHILD, but we have one global lock

	bus := GetSystemBus(t)

	const policyPath = "SYSVOL/example.com/Policies"
	dest, rundir := t.TempDir(), t.TempDir()

	adc, err := New(context.Background(), "ldap://UNUSED:1636/", "example.com", bus,
		WithCacheDir(dest), WithRunDir(rundir), withoutKerberos(), WithSSSCacheDir("testdata/sss/db"))
	require.NoError(t, err, "Setup: cannot create ad object")

	// ensure the GPO is already downloaded with an older version to force redownload
	require.NoError(t,
		shutil.CopyTree(
			filepath.Join("testdata", "AD", policyPath, "standard-old"),
			filepath.Join(adc.gpoCacheDir, "standard"),
			&shutil.CopyTreeOptions{Symlinks: true, CopyFunction: shutil.Copy}),
		"Setup: can't copy initial gpo directory")
	// create the lock made by fetch which is always called before parseGPOs in the public API
	adc.gpos["standard-name"] = &gpo{
		name: "standard-name",
		url:  fmt.Sprintf("smb://localhost:%d/%s/standard", SmbPort, policyPath),
		mu:   &sync.RWMutex{},
	}

	// concurrent downloads and parsing
	gpos := map[string]string{
		"standard-name": adc.gpos["standard-name"].url,
	}
	orderedGPOs := []gpo{{name: "standard-name", url: gpos["standard-name"]}}

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()

		err := adc.fetch(context.Background(), "", gpos)
		require.NoError(t, err, "fetch returned an error but shouldn't")
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

	bus := GetSystemBus(t)

	const policyPath = "SYSVOL/example.com/Policies"
	dest, rundir := t.TempDir(), t.TempDir()

	adc, err := New(context.Background(), "ldap://UNUSED:1636/", "example.com", bus,
		WithCacheDir(dest), WithRunDir(rundir), withoutKerberos(), WithSSSCacheDir("testdata/sss/db"))
	require.NoError(t, err, "Setup: cannot create ad object")

	// Fetch the GPO to set it up
	gpos := map[string]string{
		"standard-name": fmt.Sprintf("smb://localhost:%d/%s/standard", SmbPort, policyPath),
	}
	orderedGPOs := []gpo{{name: "standard-name", url: gpos["standard-name"]}}
	err = adc.fetch(context.Background(), "", gpos)
	require.NoError(t, err, "Setup: couldn’t do initial GPO fetch as returned an error but shouldn't")

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

var brokenSmbDirShare string

func TestMain(m *testing.M) {
	flag.BoolVar(&Update, "update", false, "update golden files")
	flag.Parse()

	// Don’t setup samba or sssd for mock helpers
	if !strings.Contains(strings.Join(os.Args, " "), "TestMock") {
		debug := flag.Bool("verbose", false, "Print debug log level information within the test")
		flag.Parse()
		if *debug {
			logrus.StandardLogger().SetLevel(logrus.DebugLevel)
		}

		// Samba
		var err error
		brokenSmbDirShare, err = os.MkdirTemp("", "adsys_smbd_broken_share_")
		if err != nil {
			log.Fatalf("Setup: failed to create temporary broken smb share directory: %v", err)
		}
		if err = os.MkdirAll(filepath.Join(brokenSmbDirShare, policyPath), 0700); err != nil {
			log.Fatalf("Setup: failed to created temporary broken smb share AD structure: %v", err)
		}
		defer func() {
			if err := os.RemoveAll(brokenSmbDirShare); err != nil {
				log.Fatalf("Teardown: failed to remove broken smb directory: %v", err)
			}
		}()
		defer testutils.SetupSmb(SmbPort, "testdata/AD/SYSVOL", brokenSmbDirShare)()

		// SSSD domains
		defer testutils.StartLocalSystemBus()()

		conn, err := dbus.SystemBusPrivate()
		if err != nil {
			log.Fatalf("Setup: can’t get a private system bus: %v", err)
		}
		defer func() {
			if err = conn.Close(); err != nil {
				log.Fatalf("Teardown: can’t close system dbus connection: %v", err)
			}
		}()
		if err = conn.Auth(nil); err != nil {
			log.Fatalf("Setup: can’t auth on private system bus: %v", err)
		}
		if err = conn.Hello(); err != nil {
			log.Fatalf("Setup: can’t send hello message on private system bus: %v", err)
		}

		sssdOnlineExample := sssd{
			domain: "example.com",
			online: true,
		}
		sssdOnlineLocalDomain := sssd{
			domain: "locadomain",
			online: true,
		}
		sssdEmptyServerDomain := sssd{
			domain: "",
			online: true,
		}
		sssdOfflineExample := sssd{
			domain: "example.com",
			online: false,
		}
		const intro = `
	<node>
		<interface name="org.freedesktop.sssd.infopipe.Domains.Domain">
			<method name="ActiveServer">
				<arg direction="in" type="s"/>
				<arg direction="out" type="s"/>
			</method>
			<method name="IsOnline">
				<arg direction="out" type="b"/>
			</method>
		</interface>` + introspect.IntrospectDataString + `</node>`
		conn.Export(sssdOnlineExample, "/org/freedesktop/sssd/infopipe/Domains/example_2ecom", "org.freedesktop.sssd.infopipe.Domains.Domain")
		conn.Export(introspect.Introspectable(intro), "/org/freedesktop/sssd/infopipe/Domains/example_2ecom",
			"org.freedesktop.DBus.Introspectable")
		conn.Export(sssdOnlineLocalDomain, "/org/freedesktop/sssd/infopipe/Domains/localdomain", "org.freedesktop.sssd.infopipe.Domains.Domain")
		conn.Export(introspect.Introspectable(intro), "/org/freedesktop/sssd/infopipe/Domains/localdomain",
			"org.freedesktop.DBus.Introspectable")
		conn.Export(sssdEmptyServerDomain, "/org/freedesktop/sssd/infopipe/Domains/emptyserver", "org.freedesktop.sssd.infopipe.Domains.Domain")
		conn.Export(introspect.Introspectable(intro), "/org/freedesktop/sssd/infopipe/Domains/emptyserver",
			"org.freedesktop.DBus.Introspectable")
		conn.Export(sssdOfflineExample, "/org/freedesktop/sssd/infopipe/Domains/offline", "org.freedesktop.sssd.infopipe.Domains.Domain")
		conn.Export(introspect.Introspectable(intro), "/org/freedesktop/sssd/infopipe/Domains/offline",
			"org.freedesktop.DBus.Introspectable")

		reply, err := conn.RequestName("org.freedesktop.sssd.infopipe", dbus.NameFlagDoNotQueue)
		if err != nil {
			log.Fatalf("Setup: Failed to aquire sssd name on local system bus: %v", err)
		}
		if reply != dbus.RequestNameReplyPrimaryOwner {
			log.Fatalf("Setup: Failed to aquire sssd name on local system bus: name is already taken")
		}
	}
	m.Run()
	testutils.MergeCoverages()
}

// md5Tree build a recursive file list of dir and with their md5sum
func md5Tree(t *testing.T, dir string) map[string]string {
	t.Helper()

	r := make(map[string]string)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("couldn't access path %q: %v", path, err)
		}

		md5Val := ""
		if !info.IsDir() {
			d, err := os.ReadFile(path)
			if err != nil {
				return err
			}
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
	domain string
	online bool
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

// GetSystemBus helper functionality to get one system bus which automatically close on test shutdown
func GetSystemBus(t *testing.T) *dbus.Conn {
	// Don’t call dbus.SystemBus which caches globally system dbus (issues in tests)
	bus, err := dbus.SystemBusPrivate()
	require.NoError(t, err, "can’t get private system bus")
	t.Cleanup(func() { _ = bus.Close() })
	err = bus.Auth(nil)
	require.NoError(t, err, "can’t auth on private system bus")
	err = bus.Hello()
	require.NoError(t, err, "can’t ping private system bus")
	return bus
}

package ad

import (
	"context"
	"crypto/md5"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/termie/go-shutil"
)

const policyPath = "SYSVOL/localdomain/Policies"

func TestFetchGPO(t *testing.T) {
	//t.Parallel() // libsmbclient overrides SIGCHILD, keep one AD object

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
			//t.Parallel() // libsmbclient overrides SIGCHILD, keep one AD object
			dest, rundir := t.TempDir(), t.TempDir()

			adc, err := New(context.Background(), "ldap://UNUSED:1636/", "localdomain",
				withCacheDir(dest), withRunDir(rundir), withoutKerberos(), withKinitCmd(MockKinit{}))

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
				gpos[n] = fmt.Sprintf("smb://localhost:%d/%s/%s", smbPort, policyPath, n)
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
					concurrentGpos[n] = fmt.Sprintf("smb://localhost:%d/%s/%s", smbPort, policyPath, n)
				}

				wg := sync.WaitGroup{}
				wg.Add(2)
				go func() {
					defer wg.Done()
					err = adc.fetch(context.Background(), "", gpos)
					if tc.wantErr {
						require.NotNil(t, err, "fetch should return an error but didn't")
					} else {
						require.NoError(t, err, "fetch returned an error but shouldn't")
					}
				}()
				go func() {
					defer wg.Done()
					err = adc.fetch(context.Background(), "", concurrentGpos)
					if tc.wantErr {
						require.NotNil(t, err, "fetch should return an error but didn't")
					} else {
						require.NoError(t, err, "fetch returned an error but shouldn't")
					}
				}()
				wg.Wait()
			}

			// Ensure that only wanted GPOs are cached
			files, err := ioutil.ReadDir(adc.gpoCacheDir)
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
	//t.Parallel() // libsmbclient overrides SIGCHILD, keep one AD object

	// Prepare GPO with unreadable file.
	// Defer will work after all tests are done because we don’t run it in parallel
	gpos := map[string]string{
		"gpo1": fmt.Sprintf("smb://localhost:%d/broken/%s/%s", smbPort, policyPath, "gpo1"),
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
			//t.Parallel() // libsmbclient overrides SIGCHILD, keep one AD object

			dest, rundir := t.TempDir(), t.TempDir()

			adc, err := New(context.Background(), "ldap://UNUSED:1636/", "localdomain",
				withCacheDir(dest), withRunDir(rundir), withoutKerberos(), withKinitCmd(MockKinit{}))
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
	//t.Parallel() // libsmbclient overrides SIGCHILD, keep one AD object
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
			//t.Parallel() // libsmbclient overrides SIGCHILD, keep one AD object

			dest, rundir := t.TempDir(), t.TempDir()
			adc, err := New(context.Background(), "ldap://UNUSED:1636/", "localdomain",
				withCacheDir(dest), withRunDir(rundir), withoutKerberos(), withKinitCmd(MockKinit{}))
			require.NoError(t, err, "Setup: cannot create ad object")

			if tc.removeGPOCacheDir {
				require.NoError(t, os.RemoveAll(adc.gpoCacheDir), "Setup: can’t remove gpoCacheDir")
			}
			if tc.roGPOCacheDir {
				require.NoError(t, os.Chmod(adc.gpoCacheDir, 0400), "Setup: can’t set gpoCacheDir to Read only")
			}

			err = adc.fetch(context.Background(), "", map[string]string{"gpo1": fmt.Sprintf("smb://localhost:%d/%s/gpo1", smbPort, policyPath)})

			require.NotNil(t, err, "fetch should return an error but didn't")
			assert.NoDirExists(t, filepath.Join(adc.gpoCacheDir, "gpo1"), "gpo1 shouldn't be downloaded")
		})
	}
}

var brokenSmbDirShare string

const (
	smbPort         = 1445
	smbConfTemplate = `[global]
workgroup = TESTGROUP
interfaces = lo 127.0.0.0/8
smb ports = {{.SmbPort}}
log level = 2
map to guest = Bad User
passdb backend = smbpasswd
smb passwd file = {{.Tempdir}}/smbpasswd
lock directory = {{.Tempdir}}/intern
state directory = {{.Tempdir}}/intern
cache directory = {{.Tempdir}}/intern
pid directory = {{.Tempdir}}/intern
private dir = {{.Tempdir}}/intern
ncalrpc dir = {{.Tempdir}}/intern

[SYSVOL]
path = {{.Cwd}}/testdata/AD/SYSVOL
guest ok = yes

[broken]
path = {{.BrokenRoot}}
guest ok = yes
`
)

func mkSmbDir() (string, func()) {
	dir, err := ioutil.TempDir("", "adsys_smbd_")
	if err != nil {
		log.Fatalf("Setup: failed to create temporary smb directory: %v", err)
	}

	brokenSmbDirShare, err = ioutil.TempDir("", "adsys_smbd_broken_share_")
	if err != nil {
		log.Fatalf("Setup: failed to create temporary broken smb share directory: %v", err)
	}
	if err = os.MkdirAll(filepath.Join(brokenSmbDirShare, policyPath), 0700); err != nil {
		log.Fatalf("Setup: failed to created temporary broken smb share AD structure: %v", err)
	}

	type smbConfVars struct {
		Tempdir    string
		Cwd        string
		SmbPort    int
		BrokenRoot string
	}
	t, err := template.New("smb-conf").Parse(smbConfTemplate)
	if err != nil {
		log.Fatalf("Setup: can’t open template for smbd configuration: %v", err)
	}

	f, err := os.Create(filepath.Join(dir, "smbd.conf"))
	if err != nil {
		log.Fatalf("Setup: can’t create smbd configuration: %v", err)
	}
	defer f.Close()

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Setup: can’t determine current work directory: %v", err)
	}
	if err := t.Execute(f, smbConfVars{Tempdir: dir, Cwd: cwd, SmbPort: smbPort, BrokenRoot: brokenSmbDirShare}); err != nil {
		log.Fatalf("Setup: failed to create smb.conf: %v", err)
	}

	return dir, func() {
		os.RemoveAll(dir)
	}
}

func TestMain(m *testing.M) {
	defer setupSmb()()
	m.Run()
}

func setupSmb() func() {
	dir, cleanup := mkSmbDir()

	cmd := exec.Command("smbd", "-FS", "-s", filepath.Join(dir, "smbd.conf"))
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		cleanup()
		log.Fatalf("Setup: can’t start smb: %v", err)
	}

	waitForPortReady(smbPort)
	return func() {
		if err := cmd.Process.Kill(); err != nil {
			log.Fatalf("Setup: failed to kill smbd process: %v", err)
		}

		_, err := cmd.Process.Wait()
		if err != nil {
			log.Fatalf("Setup: failed to wait for smbd: %v", err)
		}

		cleanup()
	}
}

// waitForPortReady to be opened.
func waitForPortReady(port int) {
	timeout := time.NewTimer(5 * time.Second)
	for {
		select {
		case <-timeout.C:
			log.Fatalf("Setup: smbd hasn’t started successfully")
		default:
		}

		conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", port))
		if err != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		conn.Close()
		time.Sleep(10 * time.Millisecond)
		return
	}
}

// waitForPortDone to be closed.
func waitForPortDone(port int) {
	timeout := time.NewTimer(5 * time.Second)
	for {
		select {
		case <-timeout.C:
			log.Fatalf("Setup: smbd hasn’t stopped successfully")
		default:
		}

		conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", port))
		if err == nil {
			conn.Close()
			time.Sleep(10 * time.Millisecond)
			continue
		}
		return
	}
}

// md5Tree build a recursive file list of dir and with their md5sum
func md5Tree(t *testing.T, dir string) map[string]string {
	//t.Helper()

	r := make(map[string]string)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("couldn't access path %q: %v", path, err)
		}

		md5Val := ""
		if !info.IsDir() {
			d, err := ioutil.ReadFile(path)
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

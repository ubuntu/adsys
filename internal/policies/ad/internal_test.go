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
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

/*
testdata
	/AD/SYSVOL/domain/policies/{....}
	/golden
*/

func TestFetchGPO(t *testing.T) {
	t.Parallel()

	const policyPath = "SYSVOL/localdomain/Policies"
	tests := map[string]struct {
		gpos []string

		want    map[string]string
		wantErr bool
	}{
		"one new gpo": {
			gpos: []string{"gpo1"},
			want: map[string]string{"gpo1": filepath.Join("AD", policyPath, "gpo1")},
		},

		// Errors
		"Error missing remote GPT.INI": {
			gpos:    []string{"missing_gpt_ini"},
			want:    nil,
			wantErr: true,
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			//name := name
			t.Parallel()
			dest := t.TempDir()

			adc, err := New(context.Background(), "ldap://UNUSED:1636/", "localdomain", withRunDir(dest))
			require.NoError(t, err, "Setup: cannot create ad object")

			gpos := make(map[string]string)
			for _, n := range tc.gpos {
				gpos[n] = fmt.Sprintf("smb://localhost:%d/%s/%s", smbPort, policyPath, n)
			}

			err = adc.fetch(context.Background(), "", gpos)
			if tc.wantErr {
				require.NotNil(t, err, "fetch should return an error but didn't")
			} else {
				require.NoError(t, err, "fetch returned an error but shouldn't")
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
				goldPath := filepath.Join("testdata", tc.want[f.Name()])
				gpoTree := md5Tree(t, filepath.Join(adc.gpoCacheDir, f.Name()))
				goldTree := md5Tree(t, goldPath)
				assert.Equalf(t, goldTree, gpoTree, "expected and downloaded GPO %q does not match", f.Name())
			}
		})
	}
}

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
`
)

func mkSmbDir() (string, func()) {
	dir, err := ioutil.TempDir("", "adsys_smbd_")
	if err != nil {
		log.Fatalf("Setup: failed to created temporary directory: %v", err)
	}

	type smbConfVars struct {
		Tempdir string
		Cwd     string
		SmbPort int
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
	if err := t.Execute(f, smbConfVars{Tempdir: dir, Cwd: cwd, SmbPort: smbPort}); err != nil {
		log.Fatalf("Setup: failed to create smb.conf: %v", err)
	}

	return dir, func() {
		os.RemoveAll(dir)
	}
}

func TestMain(m *testing.M) {
	dir, cleanup := mkSmbDir()
	defer cleanup()

	cmd := exec.Command("smbd", "-FS", "-s", filepath.Join(dir, "smbd.conf"))
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		log.Fatalf("Setup: can’t start smb: %v", err)
	}

	origPath := os.Getenv("PATH")
	if err := os.Setenv("PATH", "./testdata:"+origPath); err != nil {
		log.Fatalf("Setup: can’t change PATH to include mocks: %v", err)
	}
	defer func() {
		os.Setenv("PATH", origPath)
	}()

	waitForPortReady(smbPort)
	defer func() {
		if err := cmd.Process.Kill(); err != nil {
			log.Fatalf("Setup: failed to kill smbd process: %v", err)
		}

		// XXX: wait will segfault because libsmbclient overrides sigchld
		cmd.Process.Release()
		waitForPortDone(smbPort)
		/*_, err = cmd.Process.Wait()
		if err != nil {
			log.Fatalf("Setup: failed to wait for smbd: %v", err)
		}*/
	}()

	m.Run()
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
	t.Helper()

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

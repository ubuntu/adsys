package testutils

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
	"time"
)

func SetupSmb(port int, sysvolDir, brokenSmbDir string) func() {
	smbPort := port
	dir, cleanup := mkSmbDir(smbPort, sysvolDir, brokenSmbDir)

	cmd := exec.Command("smbd", "-FS", "-s", filepath.Join(dir, "smbd.conf"))
	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Fatalf("Setup: can’t get smb output: %v", err)
	}

	if err := cmd.Start(); err != nil {
		cleanup()
		log.Fatalf("Setup: can’t start smb: %v", err)
	}

	waitForPortReady(smbPort)
	return func() {
		if err := cmd.Process.Kill(); err != nil {
			log.Fatalf("Setup: failed to kill smbd process: %v", err)
		}

		d, err := io.ReadAll(stderr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Setup: Can't show stderr from smbd command: %v", err)
		}
		if string(d) != "" {
			fmt.Fprintf(os.Stderr, "Setup: samba output: %s\n", d)
		}

		if _, err = cmd.Process.Wait(); err != nil {
			log.Fatalf("Setup: failed to wait for smbd: %v", err)
		}

		cleanup()
	}
}

const (
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
path = {{.Cwd}}/{{.SysvolRoot}}
guest ok = yes

[broken]
path = {{.BrokenRoot}}
guest ok = yes
`
)

func mkSmbDir(smbPort int, sysvolDir, brokenSmbDir string) (string, func()) {
	dir, err := os.MkdirTemp("", "adsys_smbd_")
	if err != nil {
		log.Fatalf("Setup: failed to create temporary smb directory: %v", err)
	}
	type smbConfVars struct {
		Tempdir    string
		Cwd        string
		SmbPort    int
		SysvolRoot string
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
	if err := t.Execute(f, smbConfVars{Tempdir: dir, Cwd: cwd, SmbPort: smbPort, SysvolRoot: sysvolDir, BrokenRoot: brokenSmbDir}); err != nil {
		log.Fatalf("Setup: failed to create smb.conf: %v", err)
	}
	if err := os.Setenv("ADSYS_TESTS_SMB_PORT", fmt.Sprintf("%d", smbPort)); err != nil {
		log.Fatalf("Setup: failed to set test env variable: %v", err)
	}

	return dir, func() {
		os.RemoveAll(dir)
		if err = os.Unsetenv("ADSYS_TESTS_SMB_PORT"); err != nil {
			log.Fatalf("Setup: failed to unset test env variable: %v", err)
		}
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

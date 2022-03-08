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

// SetupSmb starts a local smbd process on specified part, serving sysvolDir.
func SetupSmb(port int, sysvolDir string) func() {
	smbPort := port
	dir, cleanup := mkSmbDirWithConf(smbPort, sysvolDir)

	version, err := exec.Command("smbd", "-V").Output()
	if err != nil {
		log.Fatalf("Setup: can’t get smbd version: %v", err)
	}

	var major, minor int
	_, err = fmt.Sscanf(string(version), "Version %d.%d", &major, &minor)
	if err != nil {
		log.Fatalf("Setup: couldn't understand smbd version %q: %v", version, err)
	}

	args := []string{"-F", "-s", filepath.Join(dir, "smbd.conf")}
	if major > 4 || minor >= 15 {
		args = append(args, "--debug-stdout")
	} else {
		args = append(args, "-S")
	}

	// #nosec:G204 - we control the arguments and directory we run smbd on (on tests)
	cmd := exec.Command("smbd", args...)

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

		if err := stderr.Close(); err != nil {
			log.Fatalf("Setup: failed to close stderr on smbd process: %v", err)
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
path = {{.SysvolRoot}}
guest ok = yes
`
)

func mkSmbDirWithConf(smbPort int, sysvolDir string) (string, func()) {
	dir, err := os.MkdirTemp("", "adsys_smbd_")
	if err != nil {
		log.Fatalf("Setup: failed to create temporary smb directory: %v", err)
	}
	type smbConfVars struct {
		Tempdir    string
		Cwd        string
		SmbPort    int
		SysvolRoot string
	}
	t, err := template.New("smb-conf").Parse(smbConfTemplate)
	if err != nil {
		log.Fatalf("Setup: can’t open template for smbd configuration: %v", err)
	}

	f, err := os.Create(filepath.Join(dir, "smbd.conf"))
	if err != nil {
		log.Fatalf("Setup: can’t create smbd configuration: %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Fatalf("Setup: could not close smbd.conf file: %v", err)
		}
	}()

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Setup: can’t determine current work directory: %v", err)
	}
	if err := t.Execute(f, smbConfVars{Tempdir: dir, Cwd: cwd, SmbPort: smbPort, SysvolRoot: sysvolDir}); err != nil {
		log.Fatalf("Setup: failed to create smb.conf: %v", err)
	}
	if err := os.Setenv("ADSYS_TESTS_SMB_PORT", fmt.Sprintf("%d", smbPort)); err != nil {
		log.Fatalf("Setup: failed to set test env variable: %v", err)
	}

	return dir, func() {
		if err = os.RemoveAll(dir); err != nil {
			log.Fatalf("Teardown: can’t clean up temporary directory: %v", err)
		}
		if err = os.Unsetenv("ADSYS_TESTS_SMB_PORT"); err != nil {
			log.Fatalf("Teardown: failed to unset test env variable: %v", err)
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
		if err := conn.Close(); err != nil {
			log.Fatalf("Setup: can’t close connection made to smbd port: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
		return
	}
}

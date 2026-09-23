// Package remote provides a wrapper around the SSH client to run commands on a
// remote client.
package remote

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// commandTimeout is the maximum time a command can run before being cancelled.
const commandTimeout = 90 * time.Minute

// keepAliveInterval is how often we poke the server to keep the connection
// from being considered idle. Commands such as a distribution upgrade can go
// for minutes without writing anything, and the connection crosses a VPN and
// the stateful equipment along with it, which drops silent flows well before
// the command itself has had a chance to finish.
const keepAliveInterval = 30 * time.Second

const (
	// linkProbeSize is how much output CheckLink asks the host to produce. It
	// only needs to be large enough to require a long run of full-size TCP
	// segments, which is what a link that only carries small packets fails to
	// deliver.
	linkProbeSize = 64 * 1024

	// linkProbeTimeout bounds the probe. A healthy link answers in well under
	// a second; one that drops full-size packets never answers at all.
	linkProbeTimeout = 30 * time.Second
)

const (
	// DomainUserPassword is the password to login as domain users.
	DomainUserPassword = "supersecretpassword"

	// PAMModuleDirectory is the default directory for PAM modules on an amd64 system.
	PAMModuleDirectory = "/usr/lib/x86_64-linux-gnu/security"
)

// quiesceAPTScript stops the periodic apt work on a freshly booted host.
//
// The apt-daily timers run apt-get and unattended-upgrade in the background,
// and both are Persistent=true, so a machine that was off when they were due
// starts the runs it considers missed as soon as it boots. That is exactly
// when we start using apt ourselves, and whichever of the two gets there
// second fails outright:
//
//	E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 4044 (unattended-upgr)
//	E: Could not get lock /var/lib/apt/lists/lock. It is held by process 6129 (apt-get)
//
// unattended-upgrades.service is masked along with them for completeness, but
// it is only the shutdown helper and has never been what runs an upgrade.
//
// Masking does not reclaim the locks from a run already under way, as these
// units let their children outlive the stop, so apt is also told to wait for
// the dpkg lock rather than fail on it. That covers everything except the
// lists lock, which APTUpdate has to retry for.
const quiesceAPTScript = `set -eu
%[1]ssystemctl mask --now \
    apt-daily.timer apt-daily-upgrade.timer \
    apt-daily.service apt-daily-upgrade.service \
    unattended-upgrades.service
%[1]stee /etc/apt/apt.conf.d/99adsys-e2e >/dev/null <<EOF
APT::Periodic::Enable "0";
DPkg::Lock::Timeout "600";
EOF`

// aptUpdateScript runs apt-get update, retrying while the lists lock is held.
//
// DPkg::Lock::Timeout, set by quiesceAPTScript, only makes apt wait for the
// dpkg locks. The lists lock that apt-get update needs is taken without a
// timeout and fails immediately, so waiting out a periodic run that was
// already under way has to happen here.
const aptUpdateScript = `for attempt in $(seq 1 %[2]d); do
    %[1]sapt-get -y update && break
    if [ "${attempt}" = %[2]d ]; then
        echo "apt-get update still failing after ${attempt} attempts" >&2
        exit 1
    fi
    echo "apt-get update failed, retrying in %[3]ds (attempt ${attempt})"
    sleep %[3]d
done`

const (
	// aptUpdateAttempts is how many times APTUpdate tries before giving up.
	aptUpdateAttempts = 10

	// aptUpdateInterval is how long APTUpdate waits between attempts. A
	// periodic run holds the lists lock for as long as it takes to fetch the
	// indices, so the total wait has to be generous.
	aptUpdateInterval = 15
)

// sudoPrefix returns what a command must be prefixed with to run as root, which
// is nothing at all when we are already connected as root.
func (c Client) sudoPrefix() string {
	if c.config.User == "root" {
		return ""
	}
	return "sudo "
}

// QuiesceAPT disables the periodic apt activity on the remote host so that it
// cannot take the apt and dpkg locks from underneath the commands we run.
//
// It is safe to call on a host where the units are absent, as masking a unit
// that does not exist succeeds.
func (c Client) QuiesceAPT(ctx context.Context) error {
	if _, err := c.Run(ctx, fmt.Sprintf(quiesceAPTScript, c.sudoPrefix())); err != nil {
		return fmt.Errorf("failed to disable periodic apt activity: %w", err)
	}
	return nil
}

// APTUpdateCmd returns a command refreshing the package indices, retrying for
// as long as something else holds the lists lock.
//
// It is returned rather than run so that callers can chain it with the apt
// invocation it is refreshing the indices for.
func (c Client) APTUpdateCmd() string {
	return fmt.Sprintf(aptUpdateScript, c.sudoPrefix(), aptUpdateAttempts, aptUpdateInterval)
}

// Client represents a remote SSH client.
type Client struct {
	client *ssh.Client
	config *ssh.ClientConfig
	host   string

	done      chan struct{}
	closeOnce *sync.Once
}

// NewClient creates a new SSH client.
// It establishes a connection to the remote host using the given authentication.
// The secret will be treated as a private key if the path exists, otherwise it
// will be treated as a password.
func NewClient(host string, username string, secret string) (Client, error) {
	var authMethod ssh.AuthMethod
	privateBytes, err := os.ReadFile(secret)
	if err == nil {
		signer, err := ssh.ParsePrivateKey(privateBytes)
		if err != nil {
			return Client{}, err
		}
		authMethod = ssh.PublicKeys(signer)
	} else {
		// Could not read file, assuming password authentication
		authMethod = ssh.Password(secret)
	}

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{authMethod},
		// nolint:gosec // This is used for E2E tests where machines are created on the fly
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	var client *ssh.Client

	interval := 3 * time.Second
	retries := 10

	for i := 1; i <= retries; i++ {
		log.Debugf("Establishing SSH connection to %q (attempt %d/%d)", host, i, retries)
		client, err = ssh.Dial("tcp", host+":22", config)
		if err == nil {
			break
		}
		log.Warningf("Failed to connect to %q: %v (attempt %d/%d)", host, err, i, retries)
		time.Sleep(interval)
	}
	if err != nil {
		return Client{}, fmt.Errorf("failed to connect to %q: %w", host, err)
	}

	c := Client{
		client:    client,
		config:    config,
		host:      host,
		done:      make(chan struct{}),
		closeOnce: &sync.Once{},
	}
	go c.keepAlive(client)

	return c, nil
}

// keepAlive periodically sends a request over the given connection so that it
// keeps carrying traffic even while a command produces no output.
//
// The connection is passed explicitly rather than read from the client, as a
// reboot replaces it and each goroutine must keep polling the one it was
// started for.
func (c Client) keepAlive(client *ssh.Client) {
	ticker := time.NewTicker(keepAliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				// The connection is gone; whatever was running on it reports
				// the failure with far more context than we could here.
				return
			}
		}
	}
}

// Close closes the SSH connection.
func (c *Client) Close() error {
	c.closeOnce.Do(func() { close(c.done) })

	return c.client.Close()
}

// CheckLink verifies that the connection can carry a sustained transfer, not
// just the short exchanges that establishing it consists of.
//
// A link whose packets are capped below what the interface advertises still
// completes a handshake, answers pings and returns short commands, so it looks
// healthy right up until something produces real output and the connection
// stalls with no indication of why. Provoke that here instead, where it can be
// reported against the connection rather than against whichever command
// happened to be running.
//
// The output is deliberately read without logging it.
func (c Client) CheckLink(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, linkProbeTimeout)
	defer cancel()

	session, err := c.client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	log.Infof("Checking link to %q can carry a sustained transfer", c.host)

	type outcome struct {
		out []byte
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		out, err := session.Output(fmt.Sprintf("head -c %d /dev/zero | tr '\\0' 'a'", linkProbeSize))
		done <- outcome{out: out, err: err}
	}()

	select {
	case <-ctx.Done():
		return fmt.Errorf("link to %q stalled after transferring less than %d bytes: the connection carries small packets but not large ones, which points at an MTU too large for the tunnel it crosses", c.host, linkProbeSize)
	case res := <-done:
		if res.err != nil {
			return fmt.Errorf("link check against %q failed: %w", c.host, res.err)
		}
		if len(res.out) != linkProbeSize {
			return fmt.Errorf("link to %q delivered %d bytes out of %d", c.host, len(res.out), linkProbeSize)
		}
	}

	return nil
}

// Run runs the given command on the remote host and returns the combined output
// while also printing the command output as it occurs.
func (c Client) Run(ctx context.Context, cmd string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()

	// Create a session
	session, err := c.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// Create pipes for stdout and stderr
	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	log.Infof("Running command %q on remote host %q", cmd, c.client.RemoteAddr().String())

	// Start the remote command
	startTime := time.Now()
	if err := session.Start(cmd); err != nil {
		return nil, fmt.Errorf("failed to start command: %w", err)
	}

	// Create scanners to read stdout and stderr line by line
	stdoutScanner := bufio.NewScanner(stdout)
	stderrScanner := bufio.NewScanner(stderr)
	var combinedOutput []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Use goroutines to read and print both stdout and stderr concurrently
	wg.Add(2)
	go func() {
		for stdoutScanner.Scan() {
			line := stdoutScanner.Text()
			// Report at info level: these commands run for minutes at a time
			// against a remote machine, and when one stops making progress or
			// the connection drops mid-way, this output is the only record of
			// how far it got.
			log.Info("\t", line)
			mu.Lock()
			combinedOutput = append(combinedOutput, line)
			mu.Unlock()
		}
		wg.Done()
	}()
	go func() {
		for stderrScanner.Scan() {
			line := stderrScanner.Text()
			log.Warning("\t", line)
			mu.Lock()
			combinedOutput = append(combinedOutput, line)
			mu.Unlock()
		}
		wg.Done()
	}()

	waitDone := make(chan error, 1)
	go func() {
		waitDone <- session.Wait()
	}()

	select {
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("command timed out after %s", commandTimeout)
		}
		return nil, fmt.Errorf("command cancelled: %w", ctx.Err())
	case err := <-waitDone:
		elapsedTime := time.Since(startTime)
		wg.Wait() // wait for scanners to finish
		mu.Lock()
		defer mu.Unlock()

		out := []byte(strings.Join(combinedOutput, "\n"))
		if err != nil {
			log.Warningf("Command %q failed in %s", cmd, elapsedTime)
			return out, fmt.Errorf("command failed: %w", err)
		}
		log.Infof("Command %q finished in %s", cmd, elapsedTime)

		return out, nil
	}
}

// Upload uploads the given local file to the remote host.
func (c Client) Upload(localPath string, remotePath string) error {
	log.Infof("Uploading %q to %q on host %q", localPath, remotePath, c.client.RemoteAddr().String())
	local, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer local.Close()

	ftp, err := sftp.NewClient(c.client,
		sftp.UseConcurrentReads(true),
		sftp.UseConcurrentWrites(true),
		sftp.MaxConcurrentRequestsPerFile(64),
		sftp.MaxPacketUnchecked(1<<17),
	)
	if err != nil {
		return err
	}
	defer ftp.Close()

	stat, err := ftp.Stat(remotePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to stat remote path: %w", err)
	}
	// If the remote path is a directory, append the local file name to it
	if stat != nil && stat.IsDir() {
		remotePath = filepath.Join(remotePath, filepath.Base(localPath))
	}

	// Check if the parent directory structure exists, create it if not
	parentDir := filepath.Dir(remotePath)
	if _, err := ftp.Stat(parentDir); err != nil && errors.Is(err, os.ErrNotExist) {
		log.Debugf("Creating directory %q on remote host %q", parentDir, c.client.RemoteAddr().String())
		if err := ftp.MkdirAll(parentDir); err != nil {
			return fmt.Errorf("failed to create directory %q on remote host %q: %w", parentDir, c.client.RemoteAddr().String(), err)
		}
	}

	// Create the remote file
	remote, err := ftp.Create(remotePath)
	if err != nil {
		return err
	}
	defer remote.Close()

	if _, err := remote.ReadFrom(local); err != nil {
		return err
	}
	log.Info("File uploaded successfully")
	return nil
}

// Download downloads the given remote file to the local path.
func (c Client) Download(remotePath string, localPath string) error {
	log.Infof("Downloading %q from host %q to %q", remotePath, c.client.RemoteAddr(), localPath)

	ftp, err := sftp.NewClient(c.client)
	if err != nil {
		return err
	}
	defer ftp.Close()

	remote, err := ftp.Open(remotePath)
	if err != nil {
		return err
	}
	defer remote.Close()

	local, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer local.Close()

	if _, err := remote.WriteTo(local); err != nil {
		return err
	}
	log.Info("File downloaded successfully")

	return nil
}

// Reboot reboots the remote host and waits for it to come back online, then
// reestablishes the SSH connection.
// It first waits for the host to go offline, then returns an error if the host
// does not come back online within 3 minutes.
//
// The reboot is requested with -i so that inhibitor locks cannot deny it.
// Services that run during provisioning, snapd among them, hold a block
// inhibitor while they are busy, and logind refuses a plain reboot for as long
// as one is held:
//
//	Call to Reboot failed: Operation denied due to active block inhibitor
//
// The host is a disposable VM that the scenario has just asked to restart, so
// there is nothing worth deferring the reboot for, and honouring the lock only
// left the machine running until the wait below gave up.
func (c *Client) Reboot() error {
	log.Infof("Rebooting host %q", c.client.RemoteAddr().String())

	// The connection drops as the host goes down, so a failure here is
	// expected and not conclusive on its own. Keep the error to report it if
	// the host turns out to still be up, which is the case it explains.
	_, rebootErr := c.Run(context.Background(), "systemctl reboot -i")

	waitDone := make(chan error, 1)
	go func() {
		waitDone <- c.client.Wait()
	}()

	// Sleep a few seconds in case SSH is still available
	time.Sleep(10 * time.Second)

	// Wait for the host to go offline
	select {
	case <-waitDone:
	case <-time.After(30 * time.Second):
		if rebootErr != nil {
			return fmt.Errorf("host did not go offline in time, reboot was refused: %w", rebootErr)
		}
		return errors.New("host did not go offline in time")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Wait for the host to come back online
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("host %q did not come back online after reboot", c.client.RemoteAddr().String())
		default:
			newClient, err := ssh.Dial("tcp", c.host+":22", c.config)
			if err == nil {
				log.Infof("Host has rebooted successfully")
				c.client.Close()
				c.client = newClient
				go c.keepAlive(newClient)

				return nil
			}
			time.Sleep(5 * time.Second)
		}
	}
}

// apportReportCmd produces the apport report for adsys on the remote host.
//
// The Ubuntu general apport hook asks whether the contents of each modified
// conffile belong in the report, and adsys rewrites its own sudoers conffile
// as soon as the privilege manager applies a policy, so the question comes up
// on every machine the suite has exercised. apport reads the answer straight
// from the terminal, which a command started over SSH does not have, and the
// report died on the resulting ioctl error before writing anything:
//
//	termios.error: (25, 'Inappropriate ioctl for device')
//
// Give it a terminal and decline the questions, as the report sits next to the
// journal and the /var/log archive and is not worth an interactive collection.
// The answers are a short fixed stream rather than an endless one so a prompt
// they do not satisfy runs out of input instead of spinning on an answer it
// keeps rejecting, and the timeout bounds that case as well.
const apportReportCmd = `printf 'NNNNNNNNNNNNNNNN' | timeout 300 script --quiet --return ` +
	`--command 'APPORT_DISABLE_DISTRO_CHECK=1 ubuntu-bug --save=/root/bug adsys' /dev/null`

// CollectLogs collects logs from the remote host and writes them to disk under
// a relative logs directory named after the client host.
func (c *Client) CollectLogs(ctx context.Context, hostname string) (err error) {
	defer func() {
		if err != nil {
			log.Errorf("Failed to collect logs from host %q: %v", hostname, err)
		}
	}()

	log.Infof("Collecting logs from host %q", c.client.RemoteAddr().String())

	// Create local directory to store logs
	logDir := filepath.Join("logs", hostname)
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Check if we are still connected to remote server, attempt to reconnect if not
	if c.client == nil {
		c.client, err = ssh.Dial("tcp", c.host+":22", c.config)
		if err != nil {
			return fmt.Errorf("failed to reconnect to %q: %w", c.host, err)
		}
	}

	artifacts := []struct {
		name       string
		command    string
		remotePath string
		localName  string
	}{
		{"apport report", apportReportCmd, "/root/bug", "apport.log"},
		{"journal", "journalctl --no-pager --output=short-precise --no-hostname > /root/journal", "/root/journal", "journal.log"},
		{"/var/log archive", "tar --exclude=/var/log/journal -czf /root/varlog.tar.gz /var/log", "/root/varlog.tar.gz", "varlog.tar.gz"},
	}

	// These artifacts are only gathered because something already went wrong,
	// so collect each one independently and report the failures together at
	// the end. Giving up on the first one used to leave the run with no
	// artifacts at all, hiding the journal and /var/log behind an unrelated
	// failure of the apport report.
	var errs []error
	for _, artifact := range artifacts {
		if _, err := c.Run(ctx, artifact.command); err != nil {
			errs = append(errs, fmt.Errorf("failed to collect %s: %w", artifact.name, err))
		}

		// Download whatever the command managed to produce: a truncated
		// artifact still carries more than a missing one.
		if err := c.Download(artifact.remotePath, filepath.Join(logDir, artifact.localName)); err != nil {
			errs = append(errs, fmt.Errorf("failed to download %s: %w", artifact.name, err))
		}
	}

	return errors.Join(errs...)
}

// CollectLogsOnFailure collects logs from the remote host and writes them to disk if passed a non-nil error.
func (c *Client) CollectLogsOnFailure(ctx context.Context, err *error, hostname string) error {
	if *err != nil {
		return c.CollectLogs(ctx, hostname)
	}

	return nil
}

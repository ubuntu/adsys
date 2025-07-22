// Package remote provides a wrapper around the SSH client to run commands on a
// remote client.
package remote

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pkg/sftp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// commandTimeout is the maximum time a command can run before being cancelled.
const commandTimeout = 90 * time.Minute

const (
	// DomainUserPassword is the password to login as domain users.
	DomainUserPassword = "supersecretpassword"

	// PAMModuleDirectory is the default directory for PAM modules on an amd64 system.
	PAMModuleDirectory = "/usr/lib/x86_64-linux-gnu/security"
)

// Client represents a remote SSH client.
type Client struct {
	client *ssh.Client
	config *ssh.ClientConfig
	host   string
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

	interval := 3 * time.Second
	retries := 10

	var connErr error
	var sshClient Client
	for i := 1; i <= retries; i++ {
		dialer := net.Dialer{
			KeepAlive: 30 * time.Second,
			KeepAliveConfig: net.KeepAliveConfig{
				Enable:   true,
				Idle:     30 * time.Second,
				Interval: 30 * time.Second,
				Count:    60,
			},
		}

		conn, err := dialer.Dial("tcp", host+":22")
		if err != nil {
			connErr = err
			log.Warningf("Failed to connect to %q: %v (attempt %d/%d)", host, err, i, retries)
			time.Sleep(interval)
			continue
		}

		log.Debugf("Establishing SSH connection to %q (attempt %d/%d)", host, i, retries)
		sshCon, newChan, reqChan, err := ssh.NewClientConn(conn, host+":22", config)
		if err != nil {
			connErr = err
			log.Warningf("Failed to connect to %q: %v (attempt %d/%d)", host, err, i, retries)
			time.Sleep(interval)
			continue
		}

		sshClient = Client{
			client: ssh.NewClient(sshCon, newChan, reqChan),
			config: config,
			host:   host,
		}
		break
	}
	if connErr != nil {
		return Client{}, fmt.Errorf("failed to connect to %q: %w", host, err)
	}

	return sshClient, nil
}

// Close closes the SSH connection.
func (c *Client) Close() error {
	return c.client.Close()
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
	session.Stdin = nil

	log.Infof("Running command %q on remote host %q", cmd, c.client.RemoteAddr().String())
	// Create scanners to read stdout and stderr line by line
	var stdoutBuff, stderrBuff bytes.Buffer
	var wg sync.WaitGroup

	// Use goroutines to read and print both stdout and stderr concurrently
	wg.Add(2)
	go func() {
		defer wg.Done()
		log.Debug("Starting to read stdout")
		written, err := io.Copy(&stdoutBuff, stdout)
		if err != nil {
			log.Warningf("Error when copying stdout: %v", err)
		}
		log.Debugf("Written %d bytes to stdout", written)
	}()
	go func() {
		defer wg.Done()
		log.Debug("Starting to read stderr")
		written, err := io.Copy(&stderrBuff, stderr)
		if err != nil {
			log.Warningf("Error when copying stderr: %v", err)
		}
		log.Debugf("Written %d bytes to stderr", written)
	}()

	// Start keepalive goroutine
	keepaliveDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_, _, err := c.client.SendRequest("keepalive@openssh.com", true, nil)
				if err != nil {
					log.Warnf("Keepalive failed: %v", err)
					return
				}
			case <-keepaliveDone:
				return
			}
		}
	}()

	// Start the remote command
	startTime := time.Now()
	if err := session.Start(cmd); err != nil {
		return nil, fmt.Errorf("failed to start command: %w", err)
	}

	waitDone := make(chan error, 1)
	go func() {
		waitDone <- session.Wait()
	}()

	select {
	case <-ctx.Done():
		close(keepaliveDone)
		if err := session.Signal(ssh.SIGKILL); err != nil {
			log.Warningf("Failed to stop the running session: %v", err)
		}

		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("command timed out after %s", commandTimeout)
		}
		return nil, fmt.Errorf("command cancelled: %w", ctx.Err())
	case err := <-waitDone:
		elapsedTime := time.Since(startTime)
		wg.Wait() // wait for scanners to finish
		close(keepaliveDone)

		out := []byte("STDOUT: " + stdoutBuff.String() + "\nSTDERR: " + stderrBuff.String())
		if err != nil && errors.Is(err, &ssh.ExitMissingError{}) {
			log.Warningf("Command %q did not return any exit status: %v", cmd, err)
			log.Warningf("Output: %s", out)
			return nil, err
		}
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
func (c *Client) Reboot() error {
	log.Infof("Rebooting host %q", c.client.RemoteAddr().String())
	_, _ = c.Run(context.Background(), "reboot")

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
		return fmt.Errorf("host did not go offline in time")
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

				return nil
			}
			time.Sleep(5 * time.Second)
		}
	}
}

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

	// Run ubuntu-bug to collect logs
	_, err = c.Run(ctx, "APPORT_DISABLE_DISTRO_CHECK=1 ubuntu-bug --save=/root/bug adsys")
	if err != nil {
		return fmt.Errorf("failed to collect logs: %w", err)
	}
	// Save journalctl logs
	_, err = c.Run(ctx, "journalctl --no-pager --output=short-precise --no-hostname > /root/journal")
	if err != nil {
		return fmt.Errorf("failed to read logs: %w", err)
	}

	// Archive and download /var/log
	if _, err := c.Run(ctx, "tar --exclude=/var/log/journal -czf /root/varlog.tar.gz /var/log"); err != nil {
		return fmt.Errorf("failed to archive logs: %w", err)
	}

	// Download remote logs
	if err := c.Download("/root/varlog.tar.gz", filepath.Join(logDir, "varlog.tar.gz")); err != nil {
		return fmt.Errorf("failed to download logs: %w", err)
	}
	if err := c.Download("/root/bug", filepath.Join(logDir, "apport.log")); err != nil {
		return fmt.Errorf("failed to download logs: %w", err)
	}
	if err := c.Download("/root/journal", filepath.Join(logDir, "journal.log")); err != nil {
		return fmt.Errorf("failed to download logs: %w", err)
	}

	return nil
}

// CollectLogsOnFailure collects logs from the remote host and writes them to disk if passed a non-nil error.
func (c *Client) CollectLogsOnFailure(ctx context.Context, err *error, hostname string) error {
	if *err != nil {
		return c.CollectLogs(ctx, hostname)
	}

	return nil
}

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

// DomainUserPassword is the password to login as domain users.
const DomainUserPassword = "supersecretpassword"

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

	client, err := ssh.Dial("tcp", host+":22", config)
	if err != nil {
		return Client{}, fmt.Errorf("failed to establish connection to remote host: %w", err)
	}

	return Client{
		client: client,
		config: config,
		host:   host,
	}, nil
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
			log.Debug("\t", line)
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
		wg.Wait() // wait for scanners to finish
		log.Infof("Command %q finished in %s", cmd, time.Since(startTime).String())
		mu.Lock()
		defer mu.Unlock()
		out := []byte(strings.Join(combinedOutput, "\n"))
		if err != nil {
			return out, fmt.Errorf("command failed: %w", err)
		}

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

// Reboot reboots the remote host and waits for it to come back online, then
// reestablishes the SSH connection.
// It first waits for the host to go offline, then returns an error if the host
// does not come back online within 1 minute.
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

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
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

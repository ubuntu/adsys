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

// Client represents a remote SSH client.
type Client struct {
	*ssh.Client
}

// NewClient creates a new SSH client.
// It parses the private key from the given path and establishes a connection to
// the remote host.
func NewClient(host string, username string, sshKeyPath string) (Client, error) {
	privateBytes, err := os.ReadFile(sshKeyPath)
	if err != nil {
		return Client{}, err
	}

	signer, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return Client{}, err
	}

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		// nolint:gosec // This is used for integration tests where machines are created on the fly
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	client, err := ssh.Dial("tcp", host+":22", config)
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}

	return Client{client}, nil
}

// Run runs the given command on the remote host and returns the combined output
// while also printing the command output as it occurs.
func (c Client) Run(ctx context.Context, cmd string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()

	// Create a session
	session, err := c.NewSession()
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

	log.Infof("Running command %q on remote host %q", cmd, c.RemoteAddr().String())

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

	// Use goroutines to read and print both stdout and stderr concurrently
	go func() {
		for stdoutScanner.Scan() {
			line := stdoutScanner.Text()
			log.Debug("\t", line)
			mu.Lock()
			combinedOutput = append(combinedOutput, line)
			mu.Unlock()
		}
	}()
	go func() {
		for stderrScanner.Scan() {
			line := stderrScanner.Text()
			log.Warning("\t", line)
			mu.Lock()
			combinedOutput = append(combinedOutput, line)
			mu.Unlock()
		}
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
	log.Infof("Uploading %q to %q on host %q", localPath, remotePath, c.RemoteAddr().String())
	local, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer local.Close()

	ftp, err := sftp.NewClient(c.Client,
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

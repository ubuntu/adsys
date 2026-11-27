//go:build !windows

package remote

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestCollectLogsKeepsPartialOutputWithoutStaleFiles(t *testing.T) {
	t.Chdir(t.TempDir())
	home := t.TempDir()
	client := newLogTestClient(t, home, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	require.NoError(t, client.CollectLogs(ctx, "test-vm"))
	reports, err := filepath.Glob("logs/test-vm/failure-*/apport.log")
	require.NoError(t, err)
	require.Len(t, reports, 1)
	first := filepath.Dir(reports[0])

	require.NoError(t, os.WriteFile(filepath.Join(home, "fail-apport"), nil, 0600))
	err = client.CollectLogs(ctx, "test-vm")
	require.ErrorContains(t, err, "failed to collect apport.log")
	require.ErrorContains(t, err, "failed to collect journal.log")
	dirs, err := filepath.Glob("logs/test-vm/failure-*")
	require.NoError(t, err)
	require.Len(t, dirs, 2)
	for _, dir := range dirs {
		if dir == first {
			require.FileExists(t, filepath.Join(dir, "apport.log"))
			continue
		}
		require.NoFileExists(t, filepath.Join(dir, "apport.log"))
		journal, err := os.ReadFile(filepath.Join(dir, "journal.log"))
		require.NoError(t, err)
		require.Equal(t, "journal\n", string(journal))
		require.FileExists(t, filepath.Join(dir, "varlog.tar.gz"))
	}
}

func TestCollectLogsTimesOutAfterSavingJournal(t *testing.T) {
	t.Chdir(t.TempDir())
	stalled := make(chan struct{})
	client := newLogTestClient(t, t.TempDir(), stalled)
	result := make(chan error, 1)
	go func() { result <- client.collectLogs(t.Context(), "test-vm", time.Second) }()

	select {
	case <-stalled:
	case err := <-result:
		t.Fatalf("Log collection returned before the stalled transfer: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Log collection did not reach the stalled transfer")
	}
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.ErrorContains(t, err, "failed to download varlog.tar.gz")
	case <-time.After(5 * time.Second):
		t.Fatal("Log collection did not time out")
	}

	journals, err := filepath.Glob("logs/test-vm/failure-*/journal.log")
	require.NoError(t, err)
	require.Len(t, journals, 1)
	journal, err := os.ReadFile(journals[0])
	require.NoError(t, err)
	require.Equal(t, "journal\n", string(journal))
}

func newLogTestClient(t *testing.T, home string, stalled chan struct{}) Client {
	t.Helper()
	bin := t.TempDir()
	for name, script := range map[string]string{
		"python3":    "[ ! -e fail-apport ] && printf 'report\\n' > \"$3\"",
		"journalctl": "printf 'journal\\n'; [ ! -e fail-apport ]",
		"tar":        "printf 'archive\\n' > \"$3\"",
	} {
		// #nosec G306 -- The private command fixtures must be executable.
		require.NoError(t, os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+script+"\n"), 0700))
	}
	client, _ := newTestSSHClient(t, func(channels <-chan ssh.NewChannel) {
		transfers := 0
		for channel := range channels {
			session, requests, err := channel.Accept()
			if err != nil {
				return
			}
			request, ok := <-requests
			if !ok || request.Reply(true, nil) != nil {
				session.Close()
				return
			}
			if request.Type == "subsystem" {
				transfers++
				if stalled != nil && transfers == 2 {
					close(stalled)
					ssh.DiscardRequests(requests)
				} else if server, err := sftp.NewServer(session, sftp.ReadOnly(), sftp.WithServerWorkingDirectory(home)); err == nil {
					_ = server.Serve()
					server.Close()
				}
			} else {
				var payload struct{ Command string }
				status := uint32(1)
				if ssh.Unmarshal(request.Payload, &payload) == nil {
					// #nosec G204 -- The client sends only the log commands under test.
					cmd := exec.CommandContext(t.Context(), "/bin/sh", "-c", payload.Command)
					cmd.Dir, cmd.Env = home, []string{"PATH=" + bin + ":/usr/bin:/bin"}
					cmd.Stdout, cmd.Stderr = session, session.Stderr()
					if cmd.Run() == nil {
						status = 0
					}
				}
				_, _ = session.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
			}
			session.Close()
		}
	})
	return Client{client: client, host: "test-vm"}
}

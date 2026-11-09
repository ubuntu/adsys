package remote

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestCheckLink(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		stallAt string
		size    int
		wantErr string
	}{
		"successful transfer":  {size: linkProbeSize},
		"short transfer":       {size: 10, wantErr: "delivered 10 bytes"},
		"session open stalls":  {stallAt: "session"},
		"command start stalls": {stallAt: "exec"},
		"output stalls":        {stallAt: "output"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, key, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			signer, err := ssh.NewSignerFromKey(key)
			require.NoError(t, err)
			config := &ssh.ServerConfig{NoClientAuth: true}
			config.AddHostKey(signer)

			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() { listener.Close() })

			serverDone := make(chan struct{})
			stalled := make(chan struct{})
			go func() {
				defer close(serverDone)
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				server, channels, requests, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for channel := range channels {
					if tc.stallAt == "session" {
						close(stalled)
						continue
					}
					session, requests, err := channel.Accept()
					if err != nil {
						return
					}
					for request := range requests {
						if tc.stallAt == "exec" {
							close(stalled)
							continue
						}
						if err := request.Reply(true, nil); err != nil {
							return
						}
						if tc.stallAt == "output" {
							close(stalled)
							continue
						}
						if _, err := session.Write([]byte(strings.Repeat("a", tc.size))); err != nil {
							return
						}
						if _, err := session.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0})); err != nil {
							return
						}
						session.Close()
					}
				}
			}()

			client, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{
				// nolint:gosec // The server is created locally for this test.
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         5 * time.Second,
			})
			require.NoError(t, err)
			t.Cleanup(func() {
				client.Close()
				select {
				case <-serverDone:
				case <-time.After(5 * time.Second):
					t.Error("SSH server did not stop after closing the connection")
				}
			})

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- (Client{client: client, host: "test"}).CheckLink(ctx) }()

			if tc.stallAt != "" {
				select {
				case <-stalled:
				case <-time.After(5 * time.Second):
					t.Fatal("SSH probe did not reach the expected stall")
				}
			}
			select {
			case err := <-result:
				switch {
				case tc.stallAt != "":
					require.ErrorIs(t, err, context.DeadlineExceeded)
					require.ErrorContains(t, err, "stalled")
					select {
					case <-serverDone:
					case <-time.After(5 * time.Second):
						t.Fatal("Timed-out probe did not close the SSH connection")
					}
				case tc.wantErr != "":
					require.ErrorContains(t, err, tc.wantErr)
				default:
					require.NoError(t, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("SSH probe was not bounded by its context")
			}
		})
	}
}

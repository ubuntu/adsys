package testutils

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/ubuntu/adsys/internal/ad/backends"
)

// FormatBackendCalls takes a backend and returns a string containing a pretty
// representation of all calls to the exported functions of the interface.
func FormatBackendCalls(t *testing.T, backend backends.Backend) string {
	t.Helper()

	var got bytes.Buffer
	got.WriteString(fmt.Sprintf("* Domain(): %s\n", backend.Domain()))

	serverURL, err := backend.ServerURL(context.Background())
	serverLine := fmt.Sprintf("* ServerURL(): %s\n", serverURL)
	if err != nil {
		serverLine = fmt.Sprintf("* ServerURL ERROR(): %s\n", err)
	}
	got.WriteString(serverLine)

	isOnline, err := backend.IsOnline()
	isOnlineLine := fmt.Sprintf("* IsOnline(): %t\n", isOnline)
	if err != nil {
		isOnlineLine = fmt.Sprintf("* IsOnline ERROR(): %s\n", err)
	}
	got.WriteString(isOnlineLine)

	hostKrb5CCName, err := backend.HostKrb5CCName()
	hostKrb5CCNameLine := fmt.Sprintf("* HostKrb5CCName(): %s\n", hostKrb5CCName)
	if err != nil {
		hostKrb5CCNameLine = fmt.Sprintf("* HostKrb5CCName ERROR(): %s\n", err)
	}
	got.WriteString(hostKrb5CCNameLine)

	got.WriteString(fmt.Sprintf("* DefaultDomainSuffix(): %s\n", backend.DefaultDomainSuffix()))
	got.WriteString(fmt.Sprintf("* Config():\n%s\n", backend.Config()))

	return got.String()
}

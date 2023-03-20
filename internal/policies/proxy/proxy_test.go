package proxy_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/policies/proxy"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestApplyPolicy(t *testing.T) {
	t.Cleanup(testutils.StartLocalSystemBus())
	t.Parallel()

	bus := testutils.NewDbusConn(t)
	tests := map[string]struct {
		entries []entry.Entry

		isUser        bool
		dbusCallError bool

		wantErr       bool
		wantApplyArgs []string
	}{
		// Computer cases
		"Computer, no entries":                   {},
		"Computer, no entries, D-Bus call error": {dbusCallError: true},
		"Computer, single enabled entry": {
			entries:       []entry.Entry{{Key: "proxy/auto", Value: "http://example.com:8080/proxy.pac"}},
			wantApplyArgs: []string{"", "", "", "", "", "http://example.com:8080/proxy.pac"},
		},
		"Computer, single disabled entry": {
			entries:       []entry.Entry{{Key: "proxy/http", Value: "", Disabled: true}},
			wantApplyArgs: []string{"", "", "", "", "", ""},
		},
		"Computer, all entries set": {
			entries: []entry.Entry{
				{Key: "proxy/http", Value: "http://example.com:8080"},
				{Key: "proxy/https", Value: "https://example.com:8080"},
				{Key: "proxy/ftp", Value: "ftp://example.com:8080"},
				{Key: "proxy/socks", Value: "socks://example.com:8080"},
				{Key: "proxy/no-proxy", Value: "localhost,127.0.0.1"},
				{Key: "proxy/auto", Value: "http://example.com:8080/proxy.pac"},
			},
			wantApplyArgs: []string{
				"http://example.com:8080",
				"https://example.com:8080",
				"ftp://example.com:8080",
				"socks://example.com:8080",
				"localhost,127.0.0.1",
				"http://example.com:8080/proxy.pac",
			},
		},

		// User cases
		"User, no entries":        {isUser: true},
		"User, non-empty entries": {isUser: true, entries: []entry.Entry{{Key: "not-applied", Value: "not-applied"}}},

		"Error when D-Bus call fails": {
			entries:       []entry.Entry{{Key: "proxy/http", Value: "http://example.com:8080"}},
			dbusCallError: true,
			wantErr:       true,
		},
	}

	for name, tc := range tests {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			proxyApplier := &proxy.ProxyApplierMock{WantApplyError: tc.dbusCallError}
			m := proxy.New(bus, proxy.WithProxyApplier(proxyApplier))
			err := m.ApplyPolicy(context.Background(), "ubuntu", !tc.isUser, tc.entries)

			if tc.wantApplyArgs != nil {
				require.Equal(t, tc.wantApplyArgs, proxyApplier.Args())
			}

			if tc.wantErr {
				require.Error(t, err, "ApplyPolicy should have failed but it didn't")
				return
			}

			require.NoError(t, err, "ApplyPolicy should have succeeded but it didn't")
		})
	}
}

func TestWarnOnUnsupportedKeys(t *testing.T) {
	// capture log output (set to stderr, but captured when loading logrus)
	r, w, err := os.Pipe()
	require.NoError(t, err, "Setup: pipe shouldn’t fail")
	orig := logrus.StandardLogger().Out
	logrus.StandardLogger().SetOutput(w)

	m := proxy.New(testutils.NewDbusConn(t), proxy.WithProxyApplier(&proxy.ProxyApplierMock{}))
	err = m.ApplyPolicy(context.Background(), "ubuntu", true, []entry.Entry{{Key: "not-applied", Value: "not-applied"}})
	require.NoError(t, err, "ApplyPolicy should have succeeded but it didn't")

	logrus.StandardLogger().SetOutput(orig)
	w.Close()

	var out bytes.Buffer
	_, errCopy := io.Copy(&out, r)
	require.NoError(t, errCopy, "Setup: Couldn't copy logs to buffer")

	require.Contains(t, out.String(), "Encountered unsupported key 'not-applied'", "Should have logged unsupported key but didn't")
}

func TestWarnOnMissingDBusService(t *testing.T) {
	// capture log output (set to stderr, but captured when loading logrus)
	r, w, err := os.Pipe()
	require.NoError(t, err, "Setup: pipe shouldn’t fail")
	orig := logrus.StandardLogger().Out
	logrus.StandardLogger().SetOutput(w)

	m := proxy.New(testutils.NewDbusConn(t), proxy.WithProxyApplier(&proxy.ProxyApplierMock{WantNoService: true}))
	err = m.ApplyPolicy(context.Background(), "ubuntu", true, []entry.Entry{{Key: "proxy/http", Value: "not-applied"}})
	require.NoError(t, err, "ApplyPolicy should have succeeded but it didn't")

	logrus.StandardLogger().SetOutput(orig)
	w.Close()

	var out bytes.Buffer
	_, errCopy := io.Copy(&out, r)
	require.NoError(t, errCopy, "Setup: Couldn't copy logs to buffer")

	require.Contains(t, out.String(), "Not applying proxy settings as ubuntu-proxy-manager is not installed", "Should have logged unsupported key but didn't")
}

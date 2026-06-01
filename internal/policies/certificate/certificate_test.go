package certificate_test

import (
	"context"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/policies/certificate"
	"github.com/ubuntu/adsys/internal/policies/entry"
)

const (
	enrollValue   = "7"     // string representation of 0b111
	unenrollValue = "6"     // string representation of 0b110
	disabledValue = "32768" // string representation of 0x8000
)

var enrollEntry = entry.Entry{Key: "autoenroll", Value: enrollValue}

// mockLDAPConn implements the ldapClient interface for testing.
type mockLDAPConn struct {
	searchResults map[string]*ldap.SearchResult
	searchErr     error
}

func (m *mockLDAPConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if m.searchErr != nil {
		return nil, m.searchErr
	}
	if result, ok := m.searchResults[req.BaseDN]; ok {
		return result, nil
	}
	// Root DSE query
	if req.BaseDN == "" {
		return m.searchResults[""], nil
	}
	return &ldap.SearchResult{}, nil
}

func (m *mockLDAPConn) Close() error { return nil }

// mockLDAPConnector returns a connector function that returns the mock connection.
func mockLDAPConnector(conn *mockLDAPConn) func(string) (certificate.LDAPClient, error) {
	return func(server string) (certificate.LDAPClient, error) {
		return conn, nil
	}
}

// mockLDAPConnectorErr returns a connector function that always errors.
func mockLDAPConnectorErr() func(string) (certificate.LDAPClient, error) {
	return func(server string) (certificate.LDAPClient, error) {
		return nil, fmt.Errorf("mock LDAP connection error")
	}
}

// newMockLDAPWithCA creates a mock LDAP connection with a single CA and templates.
func newMockLDAPWithCA(t *testing.T, caName, hostname string, templates []string) *mockLDAPConn {
	t.Helper()

	// Generate a self-signed CA certificate for testing
	caCert := generateTestCACert(t)

	configDN := "CN=Configuration,DC=example,DC=com"
	enrollBaseDN := fmt.Sprintf("CN=Enrollment Services,CN=Public Key Services,CN=Services,%s", configDN)
	templateBaseDN := fmt.Sprintf("CN=Certificate Templates,CN=Public Key Services,CN=Services,%s", configDN)

	// Build enrollment services search result
	enrollEntry := ldap.NewEntry(
		fmt.Sprintf("CN=%s,%s", caName, enrollBaseDN),
		map[string][]string{
			"cn":                   {caName},
			"dNSHostName":          {hostname},
			"certificateTemplates": templates,
		},
	)
	enrollEntry.Attributes = append(enrollEntry.Attributes, &ldap.EntryAttribute{
		Name:       "cACertificate",
		ByteValues: [][]byte{caCert},
	})

	// Build template search results
	templateEntries := make([]*ldap.Entry, 0, len(templates))
	for _, tmpl := range templates {
		templateEntries = append(templateEntries, ldap.NewEntry(
			fmt.Sprintf("CN=%s,%s", tmpl, templateBaseDN),
			map[string][]string{
				"cn":                     {tmpl},
				"msPKI-Minimal-Key-Size": {"2048"},
			},
		))
	}

	return &mockLDAPConn{
		searchResults: map[string]*ldap.SearchResult{
			"": {
				Entries: []*ldap.Entry{
					ldap.NewEntry("", map[string][]string{
						"configurationNamingContext": {configDN},
					}),
				},
			},
			enrollBaseDN: {
				Entries: []*ldap.Entry{enrollEntry},
			},
			templateBaseDN: {
				Entries: templateEntries,
			},
		},
	}
}

// generateTestCACert generates a DER-encoded self-signed CA certificate for testing.
func generateTestCACert(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)

	// Validate it parses correctly
	_, err = x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return certDER
}

func TestApplyPolicy(t *testing.T) {
	// Silence the unused import warning for asn1
	_ = asn1.NullRawValue

	tests := map[string]struct {
		entries []entry.Entry

		isUser    bool
		isOffline bool

		ldapConnErr bool
		noCA        bool
		submitErr   bool

		// For unenroll testing
		existingState  bool
		sambaDirExists bool

		wantErr bool
	}{
		// No-op cases
		"Computer, no entries":           {},
		"Computer, autoenroll disabled":  {entries: []entry.Entry{{Key: "autoenroll", Value: disabledValue}}},
		"Computer, domain is offline":    {entries: []entry.Entry{enrollEntry}, isOffline: true},
		"User, autoenroll not supported": {isUser: true, entries: []entry.Entry{enrollEntry}},

		// Enroll cases
		"Computer, configured to enroll":               {entries: []entry.Entry{enrollEntry}},
		"Computer, configured to enroll, no CAs found": {entries: []entry.Entry{enrollEntry}, noCA: true},

		// Unenroll cases
		"Computer, configured to unenroll":          {entries: []entry.Entry{{Key: "autoenroll", Value: unenrollValue}}},
		"Computer, no entries, samba cache present": {sambaDirExists: true},
		"Computer, no entries, existing state":      {existingState: true},

		// Error cases
		"Error on LDAP connection failure":  {ldapConnErr: true, entries: []entry.Entry{enrollEntry}, wantErr: true},
		"Error on invalid autoenroll value": {entries: []entry.Entry{{Key: "autoenroll", Value: "notanumber"}}, wantErr: true},
		"No successful enrollments do not fail": {entries: []entry.Entry{enrollEntry}, submitErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			tmpdir := t.TempDir()
			stateDir := filepath.Join(tmpdir, "statedir")
			globalTrustDir := filepath.Join(tmpdir, "trustdir")

			// Create samba cache dir if needed
			if tc.sambaDirExists {
				require.NoError(t, os.MkdirAll(filepath.Join(stateDir, "samba"), 0750))
			}

			// Create existing enrollment state if needed
			if tc.existingState {
				stateJSON, _ := json.Marshal(map[string]any{
					"object_name": "keypress",
					"domain":      "example.com",
					"cas":         []any{},
				})
				require.NoError(t, os.MkdirAll(filepath.Join(stateDir, "certs"), 0755))
				require.NoError(t, os.WriteFile(filepath.Join(stateDir, "certs", "state_keypress.json"), stateJSON, 0600))
			}

			// Set up LDAP mock
			var ldapConnect func(string) (certificate.LDAPClient, error)
			switch {
			case tc.ldapConnErr:
				ldapConnect = mockLDAPConnectorErr()
			case tc.noCA:
				ldapConnect = mockLDAPConnector(&mockLDAPConn{
					searchResults: map[string]*ldap.SearchResult{
						"": {
							Entries: []*ldap.Entry{
								ldap.NewEntry("", map[string][]string{
									"configurationNamingContext": {"CN=Configuration,DC=example,DC=com"},
								}),
							},
						},
					},
				})
			default:
				ldapConnect = mockLDAPConnector(newMockLDAPWithCA(t, "TestCA", "ca.example.com", []string{"Machine"}))
			}

			submitter := func(context.Context, string, string, string, string) (string, error) {
				if tc.submitErr {
					return "", fmt.Errorf("mock submit error")
				}
				return testIssuedCertificatePEM(t), nil
			}

			m := certificate.New(
				"example.com",
				certificate.WithStateDir(stateDir),
				certificate.WithRunDir(filepath.Join(tmpdir, "rundir")),
				certificate.WithShareDir(filepath.Join(tmpdir, "sharedir")),
				certificate.WithGlobalTrustDir(globalTrustDir),
				certificate.WithEnrollmentMethod("ldap"),
				certificate.WithLDAPConnector(ldapConnect),
				certificate.WithCSRSubmitter(submitter),
			)

			err := m.ApplyPolicy(context.Background(), "keypress", !tc.isUser, !tc.isOffline, tc.entries)
			if tc.wantErr {
				require.Error(t, err, "ApplyPolicy should fail")
				return
			}
			require.NoError(t, err, "ApplyPolicy should succeed")

			if name == "Computer, configured to enroll" {
				require.FileExists(t, filepath.Join(stateDir, "certs", "TestCA.Machine.crt"))
				require.FileExists(t, filepath.Join(stateDir, "private", "certs", "TestCA.Machine.key"))
			}
		})
	}
}

func testIssuedCertificatePEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "issued"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
}

func TestMain(m *testing.M) {
	m.Run()
}

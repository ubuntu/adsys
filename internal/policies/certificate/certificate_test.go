package certificate_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

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
var advancedLDAPEndpointEntries = []entry.Entry{
	{Key: "Software/Policies/Microsoft/Cryptography/PolicyServers/37c9dc30f207f27f61a2f7c3aed598a6e2920b54/URL", Value: "LDAP:"},
	{Key: "Software/Policies/Microsoft/Cryptography/PolicyServers/37c9dc30f207f27f61a2f7c3aed598a6e2920b54/Flags", Value: "20"},
}
var disabledLDAPEndpointEntries = []entry.Entry{
	{Key: "Software/Policies/Microsoft/Cryptography/PolicyServers/37c9dc30f207f27f61a2f7c3aed598a6e2920b54/URL", Value: "LDAP:"},
	{Key: "Software/Policies/Microsoft/Cryptography/PolicyServers/37c9dc30f207f27f61a2f7c3aed598a6e2920b54/Flags", Value: "0"},
}

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
	return func(_ string) (certificate.LDAPClient, error) {
		return conn, nil
	}
}

// mockLDAPConnectorErr returns a connector function that always errors.
func mockLDAPConnectorErr() func(string) (certificate.LDAPClient, error) {
	return func(_ string) (certificate.LDAPClient, error) {
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
		KeyUsage:              x509.KeyUsageCertSign,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)

	// Validate it parses correctly
	_, err = x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return certDER
}

func TestApplyPolicy(t *testing.T) {
	tests := map[string]struct {
		entries []entry.Entry

		isUser    bool
		isOffline bool

		ldapConnErr bool
		noCA        bool
		submitErr   bool

		// For unenroll testing
		existingState  bool
		corruptedState bool
		sambaDirExists bool

		wantErr bool
	}{
		// No-op cases
		"Computer, no entries":           {},
		"Computer, autoenroll disabled":  {entries: []entry.Entry{{Key: "autoenroll", Value: disabledValue}}},
		"Computer, domain is offline":    {entries: []entry.Entry{enrollEntry}, isOffline: true},
		"User, autoenroll not supported": {isUser: true, entries: []entry.Entry{enrollEntry}},

		// Enroll cases
		"Computer, configured to enroll":                         {entries: []entry.Entry{enrollEntry}},
		"Computer, configured to enroll, advanced LDAP endpoint": {entries: append([]entry.Entry{enrollEntry}, advancedLDAPEndpointEntries...)},
		"Computer, configured to enroll, no CAs found":           {entries: []entry.Entry{enrollEntry}, noCA: true},

		// Unenroll cases
		"Computer, configured to unenroll":          {entries: []entry.Entry{{Key: "autoenroll", Value: unenrollValue}}},
		"Computer, no entries, samba cache present": {sambaDirExists: true},
		"Computer, no entries, existing state":      {existingState: true},
		"Computer, no entries, corrupted state":     {corruptedState: true},

		// Skip cases (previously errors, now graceful skips)
		"Computer, disabled advanced LDAP endpoint": {entries: append([]entry.Entry{enrollEntry}, disabledLDAPEndpointEntries...)},

		// Error cases
		"Error on LDAP connection failure":              {ldapConnErr: true, entries: []entry.Entry{enrollEntry}, wantErr: true},
		"Error on invalid autoenroll value":             {entries: []entry.Entry{{Key: "autoenroll", Value: "notanumber"}}, wantErr: true},
		"Error on invalid advanced LDAP endpoint flags": {entries: []entry.Entry{enrollEntry, {Key: "Software/Policies/Microsoft/Cryptography/PolicyServers/37c9dc30f207f27f61a2f7c3aed598a6e2920b54/URL", Value: "LDAP:"}, {Key: "Software/Policies/Microsoft/Cryptography/PolicyServers/37c9dc30f207f27f61a2f7c3aed598a6e2920b54/Flags", Value: "NotANumber"}}, wantErr: true},
		"Error when no certificate enrollments succeed": {entries: []entry.Entry{enrollEntry}, submitErr: true, wantErr: true},
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
				require.NoError(t, os.MkdirAll(filepath.Join(stateDir, "certs"), 0750))
				require.NoError(t, os.WriteFile(filepath.Join(stateDir, "certs", "state_keypress.json"), stateJSON, 0600))
			}
			if tc.corruptedState {
				require.NoError(t, os.MkdirAll(filepath.Join(stateDir, "certs"), 0750))
				require.NoError(t, os.WriteFile(filepath.Join(stateDir, "certs", "state_keypress.json"), []byte("{"), 0600))
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

			submitter := func(_ context.Context, _, _, _, csrPEM string) (string, error) {
				if tc.submitErr {
					return "", fmt.Errorf("mock submit error")
				}
				return testIssuedCertificateFromCSR(t, csrPEM), nil
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
				if tc.submitErr {
					require.NoFileExists(t, filepath.Join(stateDir, "certs", "TestCA.crt"))
					require.NoFileExists(t, filepath.Join(globalTrustDir, "TestCA.crt"))
					require.NoFileExists(t, filepath.Join(stateDir, "certs", "state_keypress.json"))
				}
				return
			}
			require.NoError(t, err, "ApplyPolicy should succeed")

			if name == "Computer, configured to enroll" {
				require.FileExists(t, filepath.Join(stateDir, "certs", "TestCA.Machine.crt"))
				require.FileExists(t, filepath.Join(stateDir, "private", "certs", "TestCA.Machine.key"))
			}
			if tc.corruptedState {
				require.NoFileExists(t, filepath.Join(stateDir, "certs", "state_keypress.json"))
			}
		})
	}
}

func testIssuedCertificateFromCSR(t *testing.T, csrPEM string) string {
	t.Helper()

	block, _ := pem.Decode([]byte(csrPEM))
	require.NotNil(t, block, "failed to decode CSR PEM")

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err, "failed to parse CSR")

	// Create a self-signed cert using the CSR's public key.
	// In tests, the "CA" and the issued cert share the same key for simplicity.
	// The verifyIssuedCertificate function only checks that the cert's public
	// key matches the private key, which this satisfies.
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "issued"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	// We need the private key to sign the cert. Since we can't get it from
	// the CSR, we extract the public key and use it with a random key for
	// signing — but that won't produce a valid signature. Instead, use the
	// public key from the CSR and self-sign with a separate test key.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, csr.PublicKey, caKey)
	require.NoError(t, err)

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
}

func TestMain(m *testing.M) {
	m.Run()
}

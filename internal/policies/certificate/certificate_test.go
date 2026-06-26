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
	return issueCertFromCSR(t, csrPEM, time.Now().Add(24*time.Hour))
}

// issueCertFromCSR signs the public key carried in csrPEM with a throwaway test
// CA, producing a leaf certificate valid until notAfter. Only the leaf's public
// key (matched against the enrolled private key) and validity window are
// meaningful to the code under test.
func issueCertFromCSR(t *testing.T, csrPEM string, notAfter time.Time) string {
	t.Helper()

	block, _ := pem.Decode([]byte(csrPEM))
	require.NotNil(t, block, "failed to decode CSR PEM")

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err, "failed to parse CSR")

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

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "issued"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, csr.PublicKey, caKey)
	require.NoError(t, err)

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
}

// TestLDAPEnrollmentRenewal verifies that a still-valid certificate is reused
// across policy refreshes, while a certificate within the renewal window (or
// past expiry) is re-enrolled.
func TestLDAPEnrollmentRenewal(t *testing.T) {
	tmpdir := t.TempDir()
	stateDir := filepath.Join(tmpdir, "statedir")
	globalTrustDir := filepath.Join(tmpdir, "trustdir")

	var submitCount int
	leafValidity := 365 * 24 * time.Hour
	var submitter certificate.CSRSubmitter = func(_ context.Context, _, _, _, csrPEM string) (string, error) {
		submitCount++
		return issueCertFromCSR(t, csrPEM, time.Now().Add(leafValidity)), nil
	}

	apply := func() error {
		m := certificate.New(
			"example.com",
			certificate.WithStateDir(stateDir),
			certificate.WithRunDir(filepath.Join(tmpdir, "rundir")),
			certificate.WithShareDir(filepath.Join(tmpdir, "sharedir")),
			certificate.WithGlobalTrustDir(globalTrustDir),
			certificate.WithEnrollmentMethod("ldap"),
			certificate.WithLDAPConnector(mockLDAPConnector(newMockLDAPWithCA(t, "TestCA", "ca.example.com", []string{"Machine"}))),
			certificate.WithCSRSubmitter(submitter),
		)
		return m.ApplyPolicy(context.Background(), "keypress", true, true, []entry.Entry{enrollEntry})
	}

	certFile := filepath.Join(stateDir, "certs", "TestCA.Machine.crt")

	// Initial enrollment issues a long-lived certificate.
	require.NoError(t, apply())
	require.Equal(t, 1, submitCount, "first apply should enroll once")
	require.FileExists(t, certFile)

	// A still-valid certificate is reused without contacting the CA again.
	require.NoError(t, apply())
	require.Equal(t, 1, submitCount, "valid certificate should be reused, not re-enrolled")

	// Once the stored certificate falls inside the renewal window it is
	// re-enrolled on the next policy refresh.
	require.NoError(t, os.WriteFile(certFile, selfSignedCertPEM(t, 10*24*time.Hour), 0600))
	require.NoError(t, apply())
	require.Equal(t, 2, submitCount, "near-expiry certificate should be re-enrolled")
}

// TestRenewalFailureKeepsValidCert ensures that when a near-expiry certificate
// fails to renew but is still valid, it is retained rather than being deleted
// by orphan cleanup (which would otherwise happen once another template on the
// CA enrolls successfully).
func TestRenewalFailureKeepsValidCert(t *testing.T) {
	tmpdir := t.TempDir()
	stateDir := filepath.Join(tmpdir, "statedir")
	globalTrustDir := filepath.Join(tmpdir, "trustdir")

	var fail bool
	var submitter certificate.CSRSubmitter = func(_ context.Context, _, _, _, csrPEM string) (string, error) {
		if fail {
			return "", fmt.Errorf("mock transient submit failure")
		}
		return issueCertFromCSR(t, csrPEM, time.Now().Add(365*24*time.Hour)), nil
	}

	apply := func() error {
		m := certificate.New(
			"example.com",
			certificate.WithStateDir(stateDir),
			certificate.WithRunDir(filepath.Join(tmpdir, "rundir")),
			certificate.WithShareDir(filepath.Join(tmpdir, "sharedir")),
			certificate.WithGlobalTrustDir(globalTrustDir),
			certificate.WithEnrollmentMethod("ldap"),
			certificate.WithLDAPConnector(mockLDAPConnector(newMockLDAPWithCA(t, "TestCA", "ca.example.com", []string{"Machine", "WebServer"}))),
			certificate.WithCSRSubmitter(submitter),
		)
		return m.ApplyPolicy(context.Background(), "keypress", true, true, []entry.Entry{enrollEntry})
	}

	machineCert := filepath.Join(stateDir, "certs", "TestCA.Machine.crt")
	machineKey := filepath.Join(stateDir, "private", "certs", "TestCA.Machine.key")

	// Initial enrollment issues long-lived certs for both templates.
	require.NoError(t, apply())
	require.FileExists(t, machineCert)
	require.FileExists(t, machineKey)

	// Push the Machine cert into the renewal window, then make enrollment fail.
	// WebServer remains long-lived and is reused, so enrollment overall succeeds.
	require.NoError(t, os.WriteFile(machineCert, selfSignedCertPEM(t, 10*24*time.Hour), 0600))
	fail = true
	require.NoError(t, apply())

	// The still-valid Machine cert and key must survive the failed renewal.
	require.FileExists(t, machineCert, "valid cert must be retained after a failed renewal")
	require.FileExists(t, machineKey, "private key must be retained after a failed renewal")
}

// selfSignedCertPEM returns a PEM self-signed certificate valid for validFor,
// used to simulate a stored certificate close to expiry.
func selfSignedCertPEM(t *testing.T, validFor time.Duration) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "issued"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(validFor),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestMain(m *testing.M) {
	m.Run()
}

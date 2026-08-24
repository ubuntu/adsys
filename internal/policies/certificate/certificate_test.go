package certificate_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/policies/certificate"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/testutils"
)

const (
	enrollValue   = "7"     // string representation of 0b111
	unenrollValue = "6"     // string representation of 0b110
	disabledValue = "32768" // string representation of 0x8000
)

var enrollEntry = entry.Entry{Key: "autoenroll", Value: enrollValue}
var advancedConfigurationEntries = []entry.Entry{
	{Key: "Software/Policies/Microsoft/Cryptography/PolicyServers/37c9dc30f207f27f61a2f7c3aed598a6e2920b54/AuthFlags", Value: "2"},
	{Key: "Software/Policies/Microsoft/Cryptography/PolicyServers/37c9dc30f207f27f61a2f7c3aed598a6e2920b54/Cost", Value: "2147483645"},
	{Key: "Software/Policies/Microsoft/Cryptography/PolicyServers/37c9dc30f207f27f61a2f7c3aed598a6e2920b54/Flags", Value: "20"},
	{Key: "Software/Policies/Microsoft/Cryptography/PolicyServers/37c9dc30f207f27f61a2f7c3aed598a6e2920b54/FriendlyName", Value: "ActiveDirectoryEnrollmentPolicy"},
	{Key: "Software/Policies/Microsoft/Cryptography/PolicyServers/37c9dc30f207f27f61a2f7c3aed598a6e2920b54/PolicyID", Value: "{A5E9BF57-71C6-443A-B7FC-79EFA6F73EBD}"},
	{Key: "Software/Policies/Microsoft/Cryptography/PolicyServers/37c9dc30f207f27f61a2f7c3aed598a6e2920b54/URL", Value: "LDAP:"},
	{Key: "Software/Policies/Microsoft/Cryptography/PolicyServers/Flags", Value: "0"},
}
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
func mockLDAPConnector(conn *mockLDAPConn) certificate.LDAPConnector {
	return certificate.LDAPConnectorFunc(func(context.Context, string) (certificate.LDAPClient, error) {
		return conn, nil
	})
}

// mockLDAPConnectorErr returns a connector function that always errors.
func mockLDAPConnectorErr() certificate.LDAPConnector {
	return certificate.LDAPConnectorFunc(func(context.Context, string) (certificate.LDAPClient, error) {
		return nil, fmt.Errorf("mock LDAP connection error")
	})
}

type testCAFixture struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// newMockLDAPWithCA creates a mock LDAP connection with a single CA and templates.
//
//nolint:unparam // caName is kept generic so new fixtures can use other CAs.
func newMockLDAPWithCA(t *testing.T, caName, hostname string, templates []string, ca *testCAFixture) *mockLDAPConn {
	t.Helper()

	if ca == nil {
		ca = generateTestCA(t)
	}

	configDN := "CN=Configuration,DC=example,DC=com"
	defaultDN := "DC=example,DC=com"
	enrollBaseDN := fmt.Sprintf("CN=Enrollment Services,CN=Public Key Services,CN=Services,%s", configDN)
	caBaseDN := fmt.Sprintf("CN=Certification Authorities,CN=Public Key Services,CN=Services,%s", configDN)
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
		ByteValues: [][]byte{ca.cert.Raw},
	})

	// Build template search results
	templateEntries := make([]*ldap.Entry, 0, len(templates))
	for _, tmpl := range templates {
		templateEntry := ldap.NewEntry(
			fmt.Sprintf("CN=%s,%s", tmpl, templateBaseDN),
			map[string][]string{
				"cn":                            {tmpl},
				"flags":                         {"64"},
				"msPKI-Template-Schema-Version": {"2"},
				"msPKI-Enrollment-Flag":         {"32"},
				"msPKI-Minimal-Key-Size":        {"2048"},
			},
		)
		templateEntry.Attributes = append(templateEntry.Attributes, &ldap.EntryAttribute{
			Name:       "nTSecurityDescriptor",
			ByteValues: [][]byte{nullDACLDescriptor()},
		})
		templateEntries = append(templateEntries, templateEntry)
	}

	computerDN := "CN=keypress,CN=Computers," + defaultDN
	computerResult := ldap.NewEntry(computerDN, map[string][]string{
		"sAMAccountName": {"keypress$"},
		"dNSHostName":    {"keypress.example.com"},
	})
	computerEntry := ldap.NewEntry(computerDN, map[string][]string{
		"sAMAccountName": {"keypress$"},
		"dNSHostName":    {"keypress.example.com"},
		"primaryGroupID": {"515"},
	})
	computerEntry.Attributes = append(computerEntry.Attributes,
		&ldap.EntryAttribute{Name: "objectSid", ByteValues: [][]byte{testSID(1, 5, 21, 1, 2, 3, 1000)}},
		&ldap.EntryAttribute{Name: "tokenGroups", ByteValues: [][]byte{testSID(1, 5, 21, 1, 2, 3, 515)}},
	)

	return &mockLDAPConn{
		searchResults: map[string]*ldap.SearchResult{
			"": {
				Entries: []*ldap.Entry{
					ldap.NewEntry("", map[string][]string{
						"configurationNamingContext": {configDN},
						"defaultNamingContext":       {defaultDN},
					}),
				},
			},
			enrollBaseDN: {
				Entries: []*ldap.Entry{enrollEntry},
			},
			caBaseDN: {
				Entries: []*ldap.Entry{enrollEntry},
			},
			templateBaseDN: {
				Entries: templateEntries,
			},
			defaultDN:  {Entries: []*ldap.Entry{computerResult}},
			computerDN: {Entries: []*ldap.Entry{computerEntry}},
		},
	}
}

func generateTestCA(t *testing.T) *testCAFixture {
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

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return &testCAFixture{cert: cert, key: key}
}

func nullDACLDescriptor() []byte {
	descriptor := make([]byte, 20)
	descriptor[0] = 1
	descriptor[2] = 0x04
	descriptor[3] = 0x80
	return descriptor
}

func testSID(revision byte, authority uint64, subAuthorities ...uint32) []byte {
	sid := make([]byte, 8+4*len(subAuthorities))
	sid[0] = revision
	sid[1] = byte(len(subAuthorities)) //nolint:gosec // Test SIDs are bounded well below the protocol maximum.
	for i := 0; i < 6; i++ {
		sid[7-i] = byte(authority)
		authority >>= 8
	}
	for i, value := range subAuthorities {
		binary.LittleEndian.PutUint32(sid[8+i*4:], value)
	}
	return sid
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
		"Computer, no entries, corrupted state":     {corruptedState: true, wantErr: true},

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
			caFixture := generateTestCA(t)

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
			var ldapConnect certificate.LDAPConnector
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
									"defaultNamingContext":       {"DC=example,DC=com"},
								}),
							},
						},
					},
				})
			default:
				ldapConnect = mockLDAPConnector(newMockLDAPWithCA(t, "TestCA", "ca.example.com", []string{"Machine"}, caFixture))
			}

			submitter := func(_ context.Context, _, _, _, csrPEM string) (string, error) {
				if tc.submitErr {
					return "", fmt.Errorf("mock submit error")
				}
				return issueCertFromCSR(t, csrPEM, time.Now().Add(24*time.Hour), caFixture, "keypress.example.com"), nil
			}

			m, err := certificate.New(
				"example.com",
				certificate.WithStateDir(stateDir),
				certificate.WithRunDir(filepath.Join(tmpdir, "rundir")),
				certificate.WithShareDir(filepath.Join(tmpdir, "sharedir")),
				certificate.WithGlobalTrustDir(globalTrustDir),
				certificate.WithEnrollmentMethod("ldap"),
				certificate.WithLDAPConnector(ldapConnect),
				certificate.WithCertificateRequester(certificate.IssuedCertificateRequester(submitter)),
				// Only invoked when a legacy Samba cache exists, to retire it.
				certificate.WithCertAutoenrollCmd(mockMigrationScript(t, filepath.Join(tmpdir, "script-log"), false, false)),
				// Refreshing the system trust store needs root and is not what this test exercises.
				certificate.WithTrustStoreUpdater(func() error { return nil }),
			)
			require.NoError(t, err)

			err = m.ApplyPolicy(context.Background(), "keypress", !tc.isUser, !tc.isOffline, tc.entries)
			if tc.wantErr {
				require.Error(t, err, "ApplyPolicy should fail")
				if tc.submitErr {
					require.NoFileExists(t, filepath.Join(stateDir, "certs", "TestCA.crt"))
					require.NoFileExists(t, filepath.Join(globalTrustDir, "TestCA.crt"))
					stateFiles, globErr := filepath.Glob(filepath.Join(stateDir, "certs", "state_keypress*.json"))
					require.NoError(t, globErr)
					require.Empty(t, stateFiles)
				}
				return
			}
			require.NoError(t, err, "ApplyPolicy should succeed")

			if name == "Computer, configured to enroll" {
				certs, err := filepath.Glob(filepath.Join(stateDir, "private", "certs", "TestCA.Machine.*", "current", "certificate.crt"))
				require.NoError(t, err)
				require.Len(t, certs, 1, "expected exactly one enrolled certificate")
				keys, err := filepath.Glob(filepath.Join(stateDir, "private", "certs", "TestCA.Machine.*", "current", "private.key"))
				require.NoError(t, err)
				require.Len(t, keys, 1, "expected exactly one enrolled private key")
			}
		})
	}
}

//nolint:unparam // identity is kept generic so new fixtures can enroll other names.
func issueCertFromCSR(t *testing.T, csrPEM string, notAfter time.Time, ca *testCAFixture, identity string) string {
	t.Helper()

	block, _ := pem.Decode([]byte(csrPEM))
	require.NotNil(t, block, "failed to decode CSR PEM")

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err, "failed to parse CSR")

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: identity},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, ca.cert, csr.PublicKey, ca.key)
	require.NoError(t, err)

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
}

// singleGlobMatch returns the sole file matching pattern, failing the test when
// zero or multiple files match. Enrollment embeds a raw-identity hash in each
// leaf generation directory, so tests locate it by its stable nickname prefix.
func singleGlobMatch(t *testing.T, pattern string) string {
	t.Helper()
	matches, err := filepath.Glob(pattern)
	require.NoError(t, err)
	require.Len(t, matches, 1, "expected exactly one file matching %s", pattern)
	return matches[0]
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
	caFixture := generateTestCA(t)
	//nolint:unparam // The error result is required by IssuedCertificateRequester.
	submitter := func(_ context.Context, _, _, _, csrPEM string) (string, error) {
		submitCount++
		return issueCertFromCSR(t, csrPEM, time.Now().Add(leafValidity), caFixture, "keypress.example.com"), nil
	}

	apply := func() error {
		m, err := certificate.New(
			"example.com",
			certificate.WithStateDir(stateDir),
			certificate.WithRunDir(filepath.Join(tmpdir, "rundir")),
			certificate.WithShareDir(filepath.Join(tmpdir, "sharedir")),
			certificate.WithGlobalTrustDir(globalTrustDir),
			certificate.WithEnrollmentMethod("ldap"),
			certificate.WithLDAPConnector(mockLDAPConnector(newMockLDAPWithCA(t, "TestCA", "ca.example.com", []string{"Machine"}, caFixture))),
			certificate.WithCertificateRequester(certificate.IssuedCertificateRequester(submitter)),
			// Refreshing the system trust store needs root and is not what this test exercises.
			certificate.WithTrustStoreUpdater(func() error { return nil }),
		)
		require.NoError(t, err)
		return m.ApplyPolicy(context.Background(), "keypress", true, true, []entry.Entry{enrollEntry})
	}

	// Initial enrollment issues a long-lived certificate.
	require.NoError(t, apply())
	require.Equal(t, 1, submitCount, "first apply should enroll once")
	certFile := singleGlobMatch(t, filepath.Join(stateDir, "private", "certs", "TestCA.Machine.*", "current", "certificate.crt"))
	require.FileExists(t, certFile)

	// A still-valid certificate is reused without contacting the CA again.
	require.NoError(t, apply())
	require.Equal(t, 1, submitCount, "valid certificate should be reused, not re-enrolled")

	// Once the stored certificate falls inside the renewal window it is
	// re-enrolled on the next policy refresh.
	require.NoError(t, os.WriteFile(certFile, renewalDueCertPEM(t), 0600))
	require.NoError(t, apply())
	require.Equal(t, 2, submitCount, "near-expiry certificate should be re-enrolled")
}

// TestLDAPEnrollmentRenewalShortLived verifies that short-lived certificates
// are not considered due for renewal right after issuance: the renewal window
// is bounded by a fraction of the certificate's own lifetime, so a 6-day
// certificate is reused until its last days.
func TestLDAPEnrollmentRenewalShortLived(t *testing.T) {
	tmpdir := t.TempDir()
	stateDir := filepath.Join(tmpdir, "statedir")
	globalTrustDir := filepath.Join(tmpdir, "trustdir")

	var submitCount int
	caFixture := generateTestCA(t)
	//nolint:unparam // The error result is required by IssuedCertificateRequester.
	submitter := func(_ context.Context, _, _, _, csrPEM string) (string, error) {
		submitCount++
		return issueCertFromCSR(t, csrPEM, time.Now().Add(6*24*time.Hour), caFixture, "keypress.example.com"), nil
	}

	apply := func() error {
		m, err := certificate.New(
			"example.com",
			certificate.WithStateDir(stateDir),
			certificate.WithRunDir(filepath.Join(tmpdir, "rundir")),
			certificate.WithShareDir(filepath.Join(tmpdir, "sharedir")),
			certificate.WithGlobalTrustDir(globalTrustDir),
			certificate.WithEnrollmentMethod("ldap"),
			certificate.WithLDAPConnector(mockLDAPConnector(newMockLDAPWithCA(t, "TestCA", "ca.example.com", []string{"Machine"}, caFixture))),
			certificate.WithCertificateRequester(certificate.IssuedCertificateRequester(submitter)),
			// Refreshing the system trust store needs root and is not what this test exercises.
			certificate.WithTrustStoreUpdater(func() error { return nil }),
		)
		require.NoError(t, err)
		return m.ApplyPolicy(context.Background(), "keypress", true, true, []entry.Entry{enrollEntry})
	}

	// Initial enrollment issues a 6-day certificate.
	require.NoError(t, apply())
	require.Equal(t, 1, submitCount, "first apply should enroll once")
	certFile := singleGlobMatch(t, filepath.Join(stateDir, "private", "certs", "TestCA.Machine.*", "current", "certificate.crt"))

	// A freshly issued short-lived certificate is reused: with a fixed 30-day
	// window it would instead re-enroll on every policy refresh.
	require.NoError(t, apply())
	require.Equal(t, 1, submitCount, "fresh short-lived certificate should be reused, not re-enrolled")

	// Once inside its bounded renewal window it is re-enrolled.
	require.NoError(t, os.WriteFile(certFile, selfSignedCertPEMWithValidity(t, time.Now().Add(-5*24*time.Hour), time.Now().Add(24*time.Hour)), 0600))
	require.NoError(t, apply())
	require.Equal(t, 2, submitCount, "short-lived certificate inside its renewal window should be re-enrolled")
}

// TestRenewalFailureRejectsUnexpectedStoredCert ensures an otherwise
// time-valid certificate is not retained when it is not bound to the selected
// CA and private key.
func TestRenewalFailureRejectsUnexpectedStoredCert(t *testing.T) {
	tmpdir := t.TempDir()
	stateDir := filepath.Join(tmpdir, "statedir")
	globalTrustDir := filepath.Join(tmpdir, "trustdir")
	caFixture := generateTestCA(t)

	var fail bool
	submitter := func(_ context.Context, _, _, _, csrPEM string) (string, error) {
		if fail {
			return "", fmt.Errorf("mock transient submit failure")
		}
		return issueCertFromCSR(t, csrPEM, time.Now().Add(365*24*time.Hour), caFixture, "keypress.example.com"), nil
	}

	apply := func() error {
		m, err := certificate.New(
			"example.com",
			certificate.WithStateDir(stateDir),
			certificate.WithRunDir(filepath.Join(tmpdir, "rundir")),
			certificate.WithShareDir(filepath.Join(tmpdir, "sharedir")),
			certificate.WithGlobalTrustDir(globalTrustDir),
			certificate.WithEnrollmentMethod("ldap"),
			certificate.WithLDAPConnector(mockLDAPConnector(newMockLDAPWithCA(t, "TestCA", "ca.example.com", []string{"Machine", "WebServer"}, caFixture))),
			certificate.WithCertificateRequester(certificate.IssuedCertificateRequester(submitter)),
			// Refreshing the system trust store needs root and is not what this test exercises.
			certificate.WithTrustStoreUpdater(func() error { return nil }),
		)
		require.NoError(t, err)
		return m.ApplyPolicy(context.Background(), "keypress", true, true, []entry.Entry{enrollEntry})
	}

	// Initial enrollment issues long-lived certs for both templates.
	require.NoError(t, apply())
	machineCert := singleGlobMatch(t, filepath.Join(stateDir, "private", "certs", "TestCA.Machine.*", "current", "certificate.crt"))
	machineKey := singleGlobMatch(t, filepath.Join(stateDir, "private", "certs", "TestCA.Machine.*", "current", "private.key"))
	require.FileExists(t, machineCert)
	require.FileExists(t, machineKey)

	// Push the Machine cert into the renewal window, then make enrollment fail.
	// WebServer remains long-lived and is reused, while the transient Machine
	// failure is still surfaced to the caller.
	require.NoError(t, os.WriteFile(machineCert, renewalDueCertPEM(t), 0600))
	fail = true
	require.ErrorContains(t, apply(), "mock transient submit failure")

	// The self-signed replacement is not from the expected CA and does not
	// match the stored key, so a failed renewal must not preserve it.
	require.NoFileExists(t, machineCert)
	require.NoFileExists(t, machineKey)
}

// TestApplyPolicyLDAPMigratesCEPCES verifies the transactional retirement of a
// legacy CEPCES enrollment when the native LDAP backend takes over: certmonger
// tracking is stopped and the Samba cache removed before any natively managed
// file is published, cleanup failures block the switch, and a missing
// certmonger lets the leftover cache be removed directly.
func TestApplyPolicyLDAPMigratesCEPCES(t *testing.T) {
	tests := map[string]struct {
		entries []entry.Entry

		noSambaCache   bool
		scriptFails    bool
		scriptKeepsDir bool

		wantErr          bool
		wantScriptRuns   int
		wantSambaCache   bool
		wantNativeEnroll bool
	}{
		"Fresh install never runs the legacy script": {
			entries:          []entry.Entry{enrollEntry},
			noSambaCache:     true,
			wantNativeEnroll: true,
		},
		"Backend switch retires CEPCES before enrolling natively": {
			entries:          []entry.Entry{enrollEntry},
			wantScriptRuns:   1,
			wantNativeEnroll: true,
		},
		"Failed legacy cleanup blocks the native enrollment": {
			entries:        []entry.Entry{enrollEntry},
			scriptFails:    true,
			wantErr:        true,
			wantScriptRuns: 1,
			wantSambaCache: true,
		},
		"Unenroll retires the legacy enrollment": {
			entries:        nil,
			wantScriptRuns: 1,
		},
		"Leftover cache without certmonger is kept for a later retry": {
			entries:          []entry.Entry{enrollEntry},
			scriptKeepsDir:   true,
			wantScriptRuns:   1,
			wantSambaCache:   true,
			wantNativeEnroll: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			tmpdir := t.TempDir()
			stateDir := filepath.Join(tmpdir, "statedir")
			globalTrustDir := filepath.Join(tmpdir, "trustdir")
			caFixture := generateTestCA(t)

			sambaCacheDir := filepath.Join(stateDir, "samba")
			if !tc.noSambaCache {
				require.NoError(t, os.MkdirAll(sambaCacheDir, 0750))
				require.NoError(t, os.WriteFile(filepath.Join(sambaCacheDir, "cert_gpo_state_keypress.tdb"), []byte("dummy"), 0600))
			}

			scriptLog := filepath.Join(tmpdir, "script-log")
			scriptCmd := mockMigrationScript(t, scriptLog, tc.scriptFails, tc.scriptKeepsDir)

			submitter := func(_ context.Context, _, _, _, csrPEM string) (string, error) {
				return issueCertFromCSR(t, csrPEM, time.Now().Add(365*24*time.Hour), caFixture, "keypress.example.com"), nil
			}

			m, err := certificate.New(
				"example.com",
				certificate.WithStateDir(stateDir),
				certificate.WithRunDir(filepath.Join(tmpdir, "rundir")),
				certificate.WithShareDir(filepath.Join(tmpdir, "sharedir")),
				certificate.WithGlobalTrustDir(globalTrustDir),
				certificate.WithEnrollmentMethod("ldap"),
				certificate.WithLDAPConnector(mockLDAPConnector(newMockLDAPWithCA(t, "TestCA", "ca.example.com", []string{"Machine"}, caFixture))),
				certificate.WithCertificateRequester(certificate.IssuedCertificateRequester(submitter)),
				certificate.WithCertAutoenrollCmd(scriptCmd),
				// Refreshing the system trust store needs root and is not what this test exercises.
				certificate.WithTrustStoreUpdater(func() error { return nil }),
			)
			require.NoError(t, err)

			err = m.ApplyPolicy(context.Background(), "keypress", true, true, tc.entries)
			if tc.wantErr {
				require.Error(t, err, "ApplyPolicy should fail")
			} else {
				require.NoError(t, err, "ApplyPolicy should succeed")
			}

			scriptRuns := 0
			if data, readErr := os.ReadFile(scriptLog); readErr == nil {
				content := string(data)
				require.Contains(t, content, "unenroll keypress example.com", "legacy script must run the unenroll action")
				require.Contains(t, content, "native_published=false", "legacy cleanup must run before any native file is published")
				scriptRuns = strings.Count(content, "unenroll keypress example.com")
			}
			require.Equal(t, tc.wantScriptRuns, scriptRuns, "unexpected number of legacy script runs")

			if tc.wantSambaCache {
				require.DirExists(t, sambaCacheDir, "legacy cache must be retained while the CEPCES artifacts it records are not retired")
			} else {
				require.NoDirExists(t, sambaCacheDir, "legacy cache should have been retired")
			}

			nativeCerts, globErr := filepath.Glob(filepath.Join(stateDir, "private", "certs", "TestCA.Machine.*", "current", "certificate.crt"))
			require.NoError(t, globErr)
			if tc.wantNativeEnroll {
				require.Len(t, nativeCerts, 1, "expected the native enrollment to publish a certificate")
			} else {
				require.Empty(t, nativeCerts, "no native certificate should be published")
			}
		})
	}
}

// TestApplyPolicyLDAPMigratesCEPCESRetried ensures a failed legacy cleanup is
// retried on the next policy refresh and the switch completes afterwards.
func TestApplyPolicyLDAPMigratesCEPCESRetried(t *testing.T) {
	tmpdir := t.TempDir()
	stateDir := filepath.Join(tmpdir, "statedir")
	globalTrustDir := filepath.Join(tmpdir, "trustdir")
	caFixture := generateTestCA(t)

	sambaCacheDir := filepath.Join(stateDir, "samba")
	require.NoError(t, os.MkdirAll(sambaCacheDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(sambaCacheDir, "cert_gpo_state_keypress.tdb"), []byte("dummy"), 0600))

	scriptLog := filepath.Join(tmpdir, "script-log")
	//nolint:unparam // The error result is required by IssuedCertificateRequester.
	submitter := func(_ context.Context, _, _, _, csrPEM string) (string, error) {
		return issueCertFromCSR(t, csrPEM, time.Now().Add(365*24*time.Hour), caFixture, "keypress.example.com"), nil
	}

	apply := func(scriptFails bool) error {
		m, err := certificate.New(
			"example.com",
			certificate.WithStateDir(stateDir),
			certificate.WithRunDir(filepath.Join(tmpdir, "rundir")),
			certificate.WithShareDir(filepath.Join(tmpdir, "sharedir")),
			certificate.WithGlobalTrustDir(globalTrustDir),
			certificate.WithEnrollmentMethod("ldap"),
			certificate.WithLDAPConnector(mockLDAPConnector(newMockLDAPWithCA(t, "TestCA", "ca.example.com", []string{"Machine"}, caFixture))),
			certificate.WithCertificateRequester(certificate.IssuedCertificateRequester(submitter)),
			certificate.WithCertAutoenrollCmd(mockMigrationScript(t, scriptLog, scriptFails, false)),
			// Refreshing the system trust store needs root and is not what this test exercises.
			certificate.WithTrustStoreUpdater(func() error { return nil }),
		)
		require.NoError(t, err)
		return m.ApplyPolicy(context.Background(), "keypress", true, true, []entry.Entry{enrollEntry})
	}

	require.Error(t, apply(true), "first apply should fail during legacy cleanup")
	require.DirExists(t, sambaCacheDir, "legacy cache must survive a failed cleanup")

	require.NoError(t, apply(false), "retry with a working script should succeed")
	require.NoDirExists(t, sambaCacheDir, "legacy cache should be retired after the retry")
	singleGlobMatch(t, filepath.Join(stateDir, "private", "certs", "TestCA.Machine.*", "current", "certificate.crt"))

	// A later refresh must not run the legacy script again.
	runsBefore := 0
	if data, err := os.ReadFile(scriptLog); err == nil {
		runsBefore = strings.Count(string(data), "unenroll keypress example.com")
	}
	require.NoError(t, apply(false))
	data, err := os.ReadFile(scriptLog)
	require.NoError(t, err)
	require.Equal(t, runsBefore, strings.Count(string(data), "unenroll keypress example.com"), "migration must not run once the legacy cache is gone")
}

// mockMigrationScript returns a command simulating the legacy CEPCES
// autoenroll script for migration tests. The helper process records its
// arguments and whether native files exist yet in outputFile, removes the
// Samba cache on success unless keepDir is set, and exits 1 when fail is set.
func mockMigrationScript(t *testing.T, outputFile string, fail, keepDir bool) []string {
	t.Helper()

	cmdArgs := []string{"env", "GO_WANT_HELPER_PROCESS=1", "ADSYS_MOCK_MIGRATION_OUTPUT=" + outputFile}
	if fail {
		cmdArgs = append(cmdArgs, "ADSYS_MOCK_MIGRATION_FAIL=1")
	}
	if keepDir {
		cmdArgs = append(cmdArgs, "ADSYS_MOCK_MIGRATION_KEEP_CACHE=1")
	}
	return append(cmdArgs, os.Args[0], "-test.run=TestMockMigrationScript", "--")
}

// TestMockMigrationScript is the helper process run by mockMigrationScript.
func TestMockMigrationScript(_ *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	defer os.Exit(0)

	outputFile := os.Getenv("ADSYS_MOCK_MIGRATION_OUTPUT")

	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	args = args[1:]

	var stateDir string
	for i, arg := range args {
		if arg == "--state_dir" && i+1 < len(args) {
			stateDir = args[i+1]
		}
	}

	nativePublished := false
	if matches, err := filepath.Glob(filepath.Join(stateDir, "private", "certs", "*", "current", "certificate.crt")); err == nil && len(matches) > 0 {
		nativePublished = true
	}

	record := strings.Join(args, " ") + "\n" + "native_published=" + strconv.FormatBool(nativePublished) + "\n"
	//#nosec G703 -- This is a test controlled environment
	f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err == nil {
		_, _ = f.WriteString(record)
		_ = f.Close()
	}

	if os.Getenv("ADSYS_MOCK_MIGRATION_FAIL") == "1" {
		fmt.Fprintln(os.Stderr, "EXIT 1 requested in mock")
		os.Exit(1)
	}
	if os.Getenv("ADSYS_MOCK_MIGRATION_KEEP_CACHE") != "1" {
		//#nosec G703 -- This is a test controlled environment
		_ = os.RemoveAll(filepath.Join(stateDir, "samba"))
	}
}

// renewalDueCertPEM returns a PEM self-signed certificate that is inside its
// bounded renewal window: issued 26 days ago with 5 days left, a third of its
// lifetime exceeds the remaining validity.
func renewalDueCertPEM(t *testing.T) []byte {
	t.Helper()
	return selfSignedCertPEMWithValidity(t, time.Now().Add(-26*24*time.Hour), time.Now().Add(5*24*time.Hour))
}

// selfSignedCertPEMWithValidity returns a PEM self-signed certificate with the
// given validity window.
func selfSignedCertPEMWithValidity(t *testing.T, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "issued"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestApplyPolicyCEPCES covers the legacy CEPCES enrollment backend, which
// shells out to the cert-autoenroll helper script for both enroll and
// unenroll actions.
func TestApplyPolicyCEPCES(t *testing.T) {
	tests := map[string]struct {
		entries []entry.Entry

		isUser    bool
		isOffline bool

		autoenrollScriptError bool
		runScript             bool
		sambaDirExists        bool

		wantErr bool
	}{
		// No-op cases
		"Computer, no entries":          {},
		"Computer, autoenroll disabled": {entries: []entry.Entry{{Key: "autoenroll", Value: disabledValue}}},
		"Computer, domain is offline":   {entries: []entry.Entry{enrollEntry}, isOffline: true},

		// Enroll cases
		"Computer, configured to enroll":                         {entries: []entry.Entry{enrollEntry}, runScript: true},
		"Computer, configured to enroll, advanced configuration": {entries: append(advancedConfigurationEntries, enrollEntry), runScript: true},

		// Unenroll cases
		"Computer, configured to unenroll":          {entries: []entry.Entry{{Key: "autoenroll", Value: unenrollValue}}, runScript: true},
		"Computer, no entries, Samba cache present": {sambaDirExists: true, runScript: true},

		"User, autoenroll not supported": {isUser: true, entries: []entry.Entry{enrollEntry}},

		// Error cases
		"Error on autoenroll script failure": {autoenrollScriptError: true, entries: []entry.Entry{enrollEntry}, wantErr: true},
		"Error on invalid autoenroll value":  {entries: []entry.Entry{{Key: "autoenroll", Value: "notanumber"}}, wantErr: true},
		"Error on invalid advanced configuration value": {
			entries: []entry.Entry{
				enrollEntry,
				{Key: "Software/Policies/Microsoft/Cryptography/PolicyServers/37c9dc30f207f27f61a2f7c3aed598a6e2920b54/Flags", Value: "NotANumber"},
			}, wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Test with a clean PYTHONPATH to avoid differences in the golden file output
			origPythonPath, existed := os.LookupEnv("PYTHONPATH")
			err := os.Unsetenv("PYTHONPATH")
			require.NoError(t, err, "Setup: Unable to unset PYTHONPATH")
			defer func() {
				if !existed {
					return
				}
				err := os.Setenv("PYTHONPATH", origPythonPath)
				require.NoError(t, err, "Teardown: Unable to restore PYTHONPATH")
			}()

			tmpdir := t.TempDir()
			sambaCacheDir := filepath.Join(tmpdir, "statedir", "samba")
			if tc.sambaDirExists {
				require.NoError(t, os.MkdirAll(sambaCacheDir, 0750), "Setup: Samba cache dir should be created")
			}

			autoenrollCmdOutputFile := filepath.Join(tmpdir, "autoenroll-output")
			autoenrollCmd := mockAutoenrollScript(t, autoenrollCmdOutputFile, tc.autoenrollScriptError)

			m, err := certificate.New(
				"example.com",
				certificate.WithStateDir(filepath.Join(tmpdir, "statedir")),
				certificate.WithRunDir(filepath.Join(tmpdir, "rundir")),
				certificate.WithShareDir(filepath.Join(tmpdir, "sharedir")),
				certificate.WithCertAutoenrollCmd(autoenrollCmd),
				certificate.WithEnrollmentMethod("cepces"),
			)
			require.NoError(t, err)

			err = m.ApplyPolicy(context.Background(), "keypress", !tc.isUser, !tc.isOffline, tc.entries)
			if tc.wantErr {
				require.Error(t, err, "ApplyPolicy should fail")
				return
			}
			require.NoError(t, err, "ApplyPolicy should succeed")

			// Check that the autoenroll script was called with the expected arguments
			// and that the output file was created
			if !tc.runScript {
				return
			}

			got, err := os.ReadFile(autoenrollCmdOutputFile)
			require.NoError(t, err, "Setup: Autoenroll mock output should be readable")

			want := testutils.LoadWithUpdateFromGolden(t, string(got))
			require.Equal(t, want, string(got), "Unexpected output from autoenroll mock")
		})
	}
}

func mockAutoenrollScript(t *testing.T, scriptOutputFile string, autoenrollScriptError bool) []string {
	t.Helper()

	cmdArgs := []string{"env", "GO_WANT_HELPER_PROCESS=1", os.Args[0], "-test.run=TestMockAutoenrollScript", "--", scriptOutputFile}
	if autoenrollScriptError {
		cmdArgs = append(cmdArgs, "-Exit1-")
	}

	return cmdArgs
}

func TestMockAutoenrollScript(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	defer os.Exit(0)

	var outputFile string

	args := os.Args
	for len(args) > 0 {
		if args[0] == "--" {
			outputFile = args[1]
			args = args[2:]
			break
		}
		args = args[1:]
	}

	if args[0] == "-Exit1-" {
		fmt.Fprintf(os.Stderr, "EXIT 1 requested in mock")
		os.Exit(1)
	}

	dataToWrite := strings.Join(args, " ") + "\n"
	dataToWrite += "KRB5CCNAME=" + os.Getenv("KRB5CCNAME") + "\n"
	dataToWrite += "PYTHONPATH=" + os.Getenv("PYTHONPATH") + "\n"

	// Replace tmpdir with a placeholder to avoid non-deterministic test failures
	tmpdir := filepath.Dir(outputFile)
	dataToWrite = strings.ReplaceAll(dataToWrite, tmpdir, "#TMPDIR#")

	//#nosec G703 -- This a test controlled environment
	err := os.WriteFile(outputFile, []byte(dataToWrite), 0600)
	require.NoError(t, err, "Setup: Can't write script args to output file")
}

func TestMain(m *testing.M) {
	m.Run()
}

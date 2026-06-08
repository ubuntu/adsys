package certificate

import (
	"fmt"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockLDAPClient implements LDAPClient for unit testing.
type mockLDAPClient struct {
	searchResults map[string]*ldap.SearchResult
	searchErr     error
	closed        bool
}

func (m *mockLDAPClient) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if m.searchErr != nil {
		return nil, m.searchErr
	}
	if result, ok := m.searchResults[req.BaseDN]; ok {
		return result, nil
	}
	return &ldap.SearchResult{}, nil
}

func (m *mockLDAPClient) Close() error {
	m.closed = true
	return nil
}

func TestFetchConfigDN(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		searchResults map[string]*ldap.SearchResult
		searchErr     error

		wantDN  string
		wantErr bool
	}{
		"Successful fetch": {
			searchResults: map[string]*ldap.SearchResult{
				"": {
					Entries: []*ldap.Entry{
						ldap.NewEntry("", map[string][]string{
							"configurationNamingContext": {"CN=Configuration,DC=example,DC=com"},
						}),
					},
				},
			},
			wantDN: "CN=Configuration,DC=example,DC=com",
		},
		"Error on LDAP search failure": {
			searchErr: fmt.Errorf("connection refused"),
			wantErr:   true,
		},
		"Error on empty result": {
			searchResults: map[string]*ldap.SearchResult{
				"": {Entries: []*ldap.Entry{}},
			},
			wantErr: true,
		},
		"Error on missing configurationNamingContext": {
			searchResults: map[string]*ldap.SearchResult{
				"": {
					Entries: []*ldap.Entry{
						ldap.NewEntry("", map[string][]string{
							"otherAttr": {"value"},
						}),
					},
				},
			},
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			conn := &mockLDAPClient{
				searchResults: tc.searchResults,
				searchErr:     tc.searchErr,
			}

			got, err := fetchConfigDN(conn)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantDN, got)
		})
	}
}

func TestFetchCertificationAuthorities(t *testing.T) {
	t.Parallel()

	configDN := "CN=Configuration,DC=example,DC=com"
	enrollBaseDN := fmt.Sprintf("CN=Enrollment Services,CN=Public Key Services,CN=Services,%s", configDN)

	tests := map[string]struct {
		searchResults map[string]*ldap.SearchResult
		searchErr     error

		wantCount int
		wantNames []string
		wantErr   bool
	}{
		"Single CA with templates": {
			searchResults: map[string]*ldap.SearchResult{
				enrollBaseDN: {
					Entries: []*ldap.Entry{
						newCAEntry(enrollBaseDN, "TestCA", "ca.example.com", []string{"Machine", "User"}, []byte{1, 2, 3}),
					},
				},
			},
			wantCount: 1,
			wantNames: []string{"TestCA"},
		},
		"Multiple CAs": {
			searchResults: map[string]*ldap.SearchResult{
				enrollBaseDN: {
					Entries: []*ldap.Entry{
						newCAEntry(enrollBaseDN, "CA1", "ca1.example.com", []string{"Machine"}, []byte{1}),
						newCAEntry(enrollBaseDN, "CA2", "ca2.example.com", []string{"User"}, []byte{2}),
					},
				},
			},
			wantCount: 2,
			wantNames: []string{"CA1", "CA2"},
		},
		"Entries with missing CN are skipped": {
			searchResults: map[string]*ldap.SearchResult{
				enrollBaseDN: {
					Entries: []*ldap.Entry{
						newCAEntry(enrollBaseDN, "", "ca.example.com", nil, nil),
						newCAEntry(enrollBaseDN, "GoodCA", "ca.example.com", []string{"Machine"}, []byte{1}),
					},
				},
			},
			wantCount: 1,
			wantNames: []string{"GoodCA"},
		},
		"No CAs found": {
			searchResults: map[string]*ldap.SearchResult{
				enrollBaseDN: {Entries: []*ldap.Entry{}},
			},
			wantCount: 0,
		},
		"Error on LDAP search failure": {
			searchErr: fmt.Errorf("search failed"),
			wantErr:   true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			conn := &mockLDAPClient{
				searchResults: tc.searchResults,
				searchErr:     tc.searchErr,
			}

			cas, err := fetchCertificationAuthorities(conn, configDN)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, cas, tc.wantCount)

			for i, name := range tc.wantNames {
				assert.Equal(t, name, cas[i].Name)
			}
		})
	}
}

func TestFetchTemplateAttrs(t *testing.T) {
	t.Parallel()

	configDN := "CN=Configuration,DC=example,DC=com"
	templateBaseDN := fmt.Sprintf("CN=Certificate Templates,CN=Public Key Services,CN=Services,%s", configDN)

	tests := map[string]struct {
		templateName  string
		searchResults map[string]*ldap.SearchResult
		searchErr     error

		wantMinKeySize int
	}{
		"Template with custom key size": {
			templateName: "Machine",
			searchResults: map[string]*ldap.SearchResult{
				templateBaseDN: {
					Entries: []*ldap.Entry{
						ldap.NewEntry(
							fmt.Sprintf("CN=Machine,%s", templateBaseDN),
							map[string][]string{
								"cn":                     {"Machine"},
								"msPKI-Minimal-Key-Size": {"4096"},
							},
						),
					},
				},
			},
			wantMinKeySize: 4096,
		},
		"Template not found defaults to 2048": {
			templateName: "Unknown",
			searchResults: map[string]*ldap.SearchResult{
				templateBaseDN: {Entries: []*ldap.Entry{}},
			},
			wantMinKeySize: 2048,
		},
		"Search error defaults to 2048": {
			templateName:   "Machine",
			searchErr:      fmt.Errorf("search failed"),
			wantMinKeySize: 2048,
		},
		"Missing key size attribute defaults to 2048": {
			templateName: "Machine",
			searchResults: map[string]*ldap.SearchResult{
				templateBaseDN: {
					Entries: []*ldap.Entry{
						ldap.NewEntry(
							fmt.Sprintf("CN=Machine,%s", templateBaseDN),
							map[string][]string{
								"cn": {"Machine"},
							},
						),
					},
				},
			},
			wantMinKeySize: 2048,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			conn := &mockLDAPClient{
				searchResults: tc.searchResults,
				searchErr:     tc.searchErr,
			}

			attrs, err := fetchTemplateAttrs(conn, configDN, tc.templateName)
			require.NoError(t, err)
			assert.Equal(t, tc.wantMinKeySize, attrs.MinKeySize)
		})
	}
}

func TestDiscoverCAsAndTemplates(t *testing.T) {
	t.Parallel()

	configDN := "CN=Configuration,DC=example,DC=com"
	enrollBaseDN := fmt.Sprintf("CN=Enrollment Services,CN=Public Key Services,CN=Services,%s", configDN)

	tests := map[string]struct {
		connErr       bool
		searchResults map[string]*ldap.SearchResult
		searchErr     error

		wantCount int
		wantErr   bool
	}{
		"Successful discovery": {
			searchResults: map[string]*ldap.SearchResult{
				"": {
					Entries: []*ldap.Entry{
						ldap.NewEntry("", map[string][]string{
							"configurationNamingContext": {configDN},
						}),
					},
				},
				enrollBaseDN: {
					Entries: []*ldap.Entry{
						newCAEntry(enrollBaseDN, "TestCA", "ca.example.com", []string{"Machine"}, []byte{1}),
					},
				},
			},
			wantCount: 1,
		},
		"Error on connection failure": {
			connErr: true,
			wantErr: true,
		},
		"Error on missing config DN": {
			searchResults: map[string]*ldap.SearchResult{
				"": {Entries: []*ldap.Entry{}},
			},
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var connector LDAPConnector
			if tc.connErr {
				connector = func(server string) (LDAPClient, error) {
					return nil, fmt.Errorf("connection failed")
				}
			} else {
				conn := &mockLDAPClient{
					searchResults: tc.searchResults,
					searchErr:     tc.searchErr,
				}
				connector = func(server string) (LDAPClient, error) {
					return conn, nil
				}
			}

			cas, err := discoverCAsAndTemplates(connector, "dc.example.com")
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, cas, tc.wantCount)
		})
	}
}

func TestDcHostnameFromDomain(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "example.com", dcHostnameFromDomain("EXAMPLE.COM"))
	assert.Equal(t, "test.local", dcHostnameFromDomain("test.local"))
}

// newCAEntry creates an LDAP entry representing a pKIEnrollmentService object.
func newCAEntry(baseDN, cn, hostname string, templates []string, caCert []byte) *ldap.Entry {
	e := ldap.NewEntry(
		fmt.Sprintf("CN=%s,%s", cn, baseDN),
		map[string][]string{
			"cn":                   {cn},
			"dNSHostName":          {hostname},
			"certificateTemplates": templates,
		},
	)
	if len(caCert) > 0 {
		e.Attributes = append(e.Attributes, &ldap.EntryAttribute{
			Name:       "cACertificate",
			ByteValues: [][]byte{caCert},
		})
	}
	return e
}

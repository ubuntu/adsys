package certificate

import (
	"context"
	"crypto/md5" //nolint:gosec // G501: MD5 mirrors the protocol-defined channel bindings transform under test.
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockLDAPClient implements LDAPClient for unit testing.
type mockLDAPClient struct {
	searchResults map[string]*ldap.SearchResult
	searchErr     error
	closed        bool

	// requests records every search request received, in order, so tests can
	// assert on how many searches were performed and with which filter.
	requests []*ldap.SearchRequest
}

func (m *mockLDAPClient) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	m.requests = append(m.requests, req)
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
			if tc.searchErr != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.wantMinKeySize, attrs.MinKeySize)
		})
	}
}

func templateEntry(baseDN, cn, minKeySize string) *ldap.Entry {
	attrs := map[string][]string{"cn": {cn}}
	if minKeySize != "" {
		attrs["msPKI-Minimal-Key-Size"] = []string{minKeySize}
	}
	return ldap.NewEntry(fmt.Sprintf("CN=%s,%s", cn, baseDN), attrs)
}

func TestFetchTemplateAttrsBulkContext(t *testing.T) {
	t.Parallel()

	configDN := "CN=Configuration,DC=example,DC=com"
	templateBaseDN := fmt.Sprintf("CN=Certificate Templates,CN=Public Key Services,CN=Services,%s", configDN)

	t.Run("One search fetches several templates", func(t *testing.T) {
		t.Parallel()

		conn := &mockLDAPClient{
			searchResults: map[string]*ldap.SearchResult{
				templateBaseDN: {
					Entries: []*ldap.Entry{
						templateEntry(templateBaseDN, "Machine", "2048"),
						templateEntry(templateBaseDN, "User", "4096"),
					},
				},
			},
		}

		got, err := fetchTemplateAttrsBulkContext(context.Background(), conn, configDN, []string{"Machine", "User", "Missing"})
		require.NoError(t, err)
		require.Len(t, conn.requests, 1, "expected exactly one bulk LDAP search, not one per template")

		assert.Equal(t, templateAttrs{Name: "Machine", MinKeySize: 2048}, got["Machine"])
		assert.Equal(t, templateAttrs{Name: "User", MinKeySize: 4096}, got["User"])
		// A template LDAP doesn't return still gets a safe default instead of
		// the whole call failing and discarding the entries that were found.
		assert.Equal(t, templateAttrs{Name: "Missing", MinKeySize: 2048}, got["Missing"])
	})

	t.Run("Filter escapes special characters and deduplicates names", func(t *testing.T) {
		t.Parallel()

		conn := &mockLDAPClient{
			searchResults: map[string]*ldap.SearchResult{
				templateBaseDN: {Entries: []*ldap.Entry{}},
			},
		}

		_, err := fetchTemplateAttrsBulkContext(context.Background(), conn, configDN, []string{"Foo(Bar)", "Machine", "Machine", "Foo(Bar)"})
		require.NoError(t, err)
		require.Len(t, conn.requests, 1)

		filter := conn.requests[0].Filter
		assert.Equal(t, fmt.Sprintf("(|(cn=%s)(cn=Machine))", ldap.EscapeFilter("Foo(Bar)")), filter)
	})

	t.Run("Empty input performs no search and returns no error", func(t *testing.T) {
		t.Parallel()

		conn := &mockLDAPClient{}

		got, err := fetchTemplateAttrsBulkContext(context.Background(), conn, configDN, nil)
		require.NoError(t, err)
		assert.Empty(t, got)
		assert.Empty(t, conn.requests, "no LDAP search should be issued for an empty template list")
	})

	t.Run("Search failure is reported and not swallowed", func(t *testing.T) {
		t.Parallel()

		conn := &mockLDAPClient{searchErr: fmt.Errorf("search failed")}

		_, err := fetchTemplateAttrsBulkContext(context.Background(), conn, configDN, []string{"Machine", "User"})
		require.Error(t, err)
	})

	t.Run("Case variants of the same template are deduplicated and all populated", func(t *testing.T) {
		t.Parallel()

		conn := &mockLDAPClient{
			searchResults: map[string]*ldap.SearchResult{
				templateBaseDN: {
					Entries: []*ldap.Entry{
						templateEntry(templateBaseDN, "Machine", "2048"),
					},
				},
			},
		}

		got, err := fetchTemplateAttrsBulkContext(context.Background(), conn, configDN, []string{"machine", "Machine", "MACHINE"})
		require.NoError(t, err)
		require.Len(t, conn.requests, 1, "case variants of the same name must be deduplicated into a single filter clause")

		// AD's CN matching is case-insensitive: a single "Machine" entry must
		// satisfy every originally requested spelling, under its own key, and
		// none of them should silently fall back to the 2048 default just
		// because the requested case differs from the returned CN's case.
		want := templateAttrs{Name: "Machine", MinKeySize: 2048}
		assert.Equal(t, want, got["machine"])
		assert.Equal(t, want, got["Machine"])
		assert.Equal(t, want, got["MACHINE"])
		assert.Len(t, got, 3)

		filter := conn.requests[0].Filter
		assert.Equal(t, 1, strings.Count(filter, "(cn="), "expected a single deduplicated filter clause for case variants of the same name")
	})

	t.Run("Unrequested entries never leak into the returned map", func(t *testing.T) {
		t.Parallel()

		conn := &mockLDAPClient{
			searchResults: map[string]*ldap.SearchResult{
				templateBaseDN: {
					Entries: []*ldap.Entry{
						templateEntry(templateBaseDN, "Machine", "2048"),
						// Not requested: a well-behaved LDAP server would
						// never return this given the filter, but the
						// result map must guard against it defensively.
						templateEntry(templateBaseDN, "OtherTemplate", "1024"),
					},
				},
			},
		}

		got, err := fetchTemplateAttrsBulkContext(context.Background(), conn, configDN, []string{"Machine"})
		require.NoError(t, err)
		assert.Equal(t, templateAttrs{Name: "Machine", MinKeySize: 2048}, got["Machine"])
		_, ok := got["OtherTemplate"]
		assert.False(t, ok, "unrequested entries must not appear in the returned map")
		assert.Len(t, got, 1)
	})

	t.Run("Conflicting case-insensitive duplicates fail closed", func(t *testing.T) {
		t.Parallel()

		conn := &mockLDAPClient{
			searchResults: map[string]*ldap.SearchResult{
				templateBaseDN: {
					Entries: []*ldap.Entry{
						templateEntry(templateBaseDN, "Machine", "2048"),
						templateEntry(templateBaseDN, "MACHINE", "4096"),
					},
				},
			},
		}

		got, err := fetchTemplateAttrsBulkContext(context.Background(), conn, configDN, []string{"machine"})
		require.Error(t, err, "ambiguous conflicting entries must fail closed instead of nondeterministically picking one")
		assert.Nil(t, got)
	})

	t.Run("Non-conflicting case-insensitive duplicates do not error", func(t *testing.T) {
		t.Parallel()

		conn := &mockLDAPClient{
			searchResults: map[string]*ldap.SearchResult{
				templateBaseDN: {
					Entries: []*ldap.Entry{
						templateEntry(templateBaseDN, "Machine", "2048"),
						templateEntry(templateBaseDN, "Machine", "2048"),
					},
				},
			},
		}

		got, err := fetchTemplateAttrsBulkContext(context.Background(), conn, configDN, []string{"machine"})
		require.NoError(t, err)
		assert.Equal(t, templateAttrs{Name: "Machine", MinKeySize: 2048}, got["machine"])
	})
}

func TestFetchTemplateAttrsWithConnectorUsesSingleBulkSearch(t *testing.T) {
	t.Parallel()

	configDN := "CN=Configuration,DC=example,DC=com"
	templateBaseDN := fmt.Sprintf("CN=Certificate Templates,CN=Public Key Services,CN=Services,%s", configDN)

	conn := &mockLDAPClient{
		searchResults: map[string]*ldap.SearchResult{
			"": {
				Entries: []*ldap.Entry{
					ldap.NewEntry("", map[string][]string{"configurationNamingContext": {configDN}}),
				},
			},
			templateBaseDN: {
				Entries: []*ldap.Entry{
					templateEntry(templateBaseDN, "Machine", "2048"),
					templateEntry(templateBaseDN, "User", "4096"),
					templateEntry(templateBaseDN, "WebServer", "2048"),
				},
			},
		},
	}
	connector := LDAPConnectorFunc(func(context.Context, string) (LDAPClient, error) {
		return conn, nil
	})

	got, err := fetchTemplateAttrsWithConnector(context.Background(), connector, "dc.example.com", []string{"Machine", "User", "WebServer", "Machine"})
	require.NoError(t, err)

	// One search for configurationNamingContext plus exactly one bulk search
	// for all (deduplicated) templates, instead of one per template.
	require.Len(t, conn.requests, 2)
	assert.Len(t, got, 3)
	assert.Equal(t, 4096, got["User"].MinKeySize)
}

func TestFetchTemplateAttrsWithConnectorEmptyInputSkipsLDAP(t *testing.T) {
	t.Parallel()

	connectCalled := false
	connector := LDAPConnectorFunc(func(context.Context, string) (LDAPClient, error) {
		connectCalled = true
		return nil, errors.New("unexpected connection")
	})

	got, err := fetchTemplateAttrsWithConnector(context.Background(), connector, "dc.example.com", nil)
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.False(t, connectCalled)
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
				connector = LDAPConnectorFunc(func(context.Context, string) (LDAPClient, error) {
					return nil, fmt.Errorf("connection failed")
				})
			} else {
				conn := &mockLDAPClient{
					searchResults: tc.searchResults,
					searchErr:     tc.searchErr,
				}
				connector = LDAPConnectorFunc(func(context.Context, string) (LDAPClient, error) {
					return conn, nil
				})
			}

			cas, err := discoverCAsAndTemplates(context.Background(), connector, "dc.example.com")
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, cas, tc.wantCount)
		})
	}
}

func TestDiscoverCAsAndTemplatesContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	_, err := discoverCAsAndTemplates(ctx, LDAPConnectorFunc(func(context.Context, string) (LDAPClient, error) {
		called = true
		return nil, nil
	}), "example.com")
	require.ErrorIs(t, err, context.Canceled)
	assert.False(t, called)
}

type contextLDAPTestClient struct {
	search func(context.Context, *ldap.SearchRequest) (*ldap.SearchResult, error)
	closed bool
}

func (c *contextLDAPTestClient) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	return c.SearchContext(context.Background(), req)
}

func (c *contextLDAPTestClient) SearchContext(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	return c.search(ctx, req)
}

func (c *contextLDAPTestClient) Close() error {
	c.closed = true
	return nil
}

type candidateLDAPTestConnector struct {
	candidates []ldapServerCandidate
	connect    func(context.Context, ldapServerCandidate) (LDAPClient, error)
}

func (c *candidateLDAPTestConnector) Connect(ctx context.Context, server string) (LDAPClient, error) {
	return c.connect(ctx, ldapServerCandidate{address: server, host: tlsServerName(server)})
}

func (c *candidateLDAPTestConnector) Candidates(context.Context, string) ([]ldapServerCandidate, error) {
	return c.candidates, nil
}

func (c *candidateLDAPTestConnector) ConnectCandidate(ctx context.Context, candidate ldapServerCandidate) (LDAPClient, error) {
	return c.connect(ctx, candidate)
}

func TestDiscoveryRestartsWholeTransactionOnNextCandidate(t *testing.T) {
	t.Parallel()

	const configDN = "CN=Configuration,DC=example,DC=com"
	var connected []string
	var searchesByDC = map[string][]string{}
	connector := &candidateLDAPTestConnector{
		candidates: []ldapServerCandidate{
			{address: "dc1.example.com:389", host: "dc1.example.com"},
			{address: "dc2.example.com:389", host: "dc2.example.com"},
		},
		connect: func(_ context.Context, candidate ldapServerCandidate) (LDAPClient, error) {
			connected = append(connected, candidate.host)
			return &contextLDAPTestClient{search: func(_ context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
				searchesByDC[candidate.host] = append(searchesByDC[candidate.host], req.BaseDN)
				if req.BaseDN == "" {
					return &ldap.SearchResult{Entries: []*ldap.Entry{
						ldap.NewEntry("", map[string][]string{"configurationNamingContext": {configDN}}),
					}}, nil
				}
				if candidate.host == "dc1.example.com" {
					return nil, fmt.Errorf("CA search stalled")
				}
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					newCAEntry(req.BaseDN, "TestCA", "ca.example.com", []string{"Machine"}, []byte{1}),
				}}, nil
			}}, nil
		},
	}

	result, err := discoverCAsAndTemplates(context.Background(), connector, "example.com")
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, []string{"dc1.example.com", "dc2.example.com"}, connected)
	assert.Equal(t, []string{"", "CN=Enrollment Services,CN=Public Key Services,CN=Services," + configDN}, searchesByDC["dc1.example.com"])
	assert.Equal(t, []string{"", "CN=Enrollment Services,CN=Public Key Services,CN=Services," + configDN}, searchesByDC["dc2.example.com"])
}

func TestLDAPTransactionDeadFirstCandidate(t *testing.T) {
	t.Parallel()

	var connected []string
	connector := &candidateLDAPTestConnector{
		candidates: []ldapServerCandidate{
			{address: "dead.example.com:389", host: "dead.example.com"},
			{address: "live.example.com:389", host: "live.example.com"},
		},
		connect: func(_ context.Context, candidate ldapServerCandidate) (LDAPClient, error) {
			connected = append(connected, candidate.host)
			if candidate.host == "dead.example.com" {
				return nil, fmt.Errorf("connection refused")
			}
			return &contextLDAPTestClient{
				search: func(context.Context, *ldap.SearchRequest) (*ldap.SearchResult, error) {
					return &ldap.SearchResult{}, nil
				},
			}, nil
		},
	}

	_, err := runLDAPTransaction(context.Background(), connector, "example.com", func(ctx context.Context, client LDAPClient) (struct{}, error) {
		_, err := ldapSearchContext(ctx, client, ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil, nil))
		return struct{}{}, err
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"dead.example.com", "live.example.com"}, connected)
}

func TestLDAPTransactionCancellation(t *testing.T) {
	t.Parallel()

	connector := &candidateLDAPTestConnector{
		candidates: []ldapServerCandidate{{address: "dc1.example.com:389", host: "dc1.example.com"}},
		connect: func(_ context.Context, _ ldapServerCandidate) (LDAPClient, error) {
			return &contextLDAPTestClient{
				search: func(ctx context.Context, _ *ldap.SearchRequest) (*ldap.SearchResult, error) {
					<-ctx.Done()
					return nil, ctx.Err()
				},
			}, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	defer cancel()

	start := time.Now()
	_, err := runLDAPTransaction(ctx, connector, "example.com", func(ctx context.Context, client LDAPClient) (struct{}, error) {
		_, err := ldapSearchContext(ctx, client, ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil, nil))
		return struct{}{}, err
	})
	require.ErrorIs(t, err, context.Canceled)
	assert.Less(t, time.Since(start), time.Second)
}

func TestLDAPServerCandidatesPreserveSRVOrder(t *testing.T) {
	t.Parallel()

	records := []*net.SRV{
		{Target: "dc1.example.com.", Port: 1389},
		{Target: "dc2.example.com.", Port: 2389},
	}
	candidates := ldapServerCandidatesFromRecords(records)
	require.Len(t, candidates, 2)
	assert.Equal(t, "dc1.example.com:1389", candidates[0].address)
	assert.Equal(t, "dc2.example.com:2389", candidates[1].address)
}

func TestRequestStartTLS(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		response []byte
		wantErr  bool
	}{
		"success": {
			response: []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00},
		},
		"LDAP failure": {
			response: []byte{0x30, 0x12, 0x02, 0x01, 0x01, 0x78, 0x0d, 0x0a, 0x01, 0x02, 0x04, 0x00, 0x04, 0x06, 'f', 'a', 'i', 'l', 'e', 'd'},
			wantErr:  true,
		},
		"wrong message ID tag": {
			response: []byte{0x30, 0x0c, 0x04, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00},
			wantErr:  true,
		},
		"malformed message ID integer": {
			response: []byte{0x30, 0x0b, 0x02, 0x00, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00},
			wantErr:  true,
		},
		"wrong message ID": {
			response: []byte{0x30, 0x0c, 0x02, 0x01, 0x02, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00},
			wantErr:  true,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client, server := net.Pipe()
			t.Cleanup(func() {
				_ = client.Close()
				_ = server.Close()
			})
			serverErr := make(chan error, 1)
			go func() {
				tag, _, err := readBERElement(server)
				if err == nil && tag != 0x30 {
					err = fmt.Errorf("unexpected request tag %x", tag)
				}
				if err == nil {
					err = writeAll(server, tc.response)
				}
				serverErr <- err
			}()

			err := requestStartTLS(client)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.NoError(t, <-serverErr)
		})
	}
}

func TestReadBERElementRejectsTruncation(t *testing.T) {
	t.Parallel()
	_, _, err := readBERElement(io.LimitReader(strings.NewReader("\x30\x05abc"), 5))
	require.Error(t, err)
}

func TestCandidateSetupCancellation(t *testing.T) {
	tests := map[string]bool{
		"stalled StartTLS response": true,
		"stalled GSSAPI bind":       false,
	}
	for name, stallStartTLS := range tests {
		t.Run(name, func(t *testing.T) {
			address, ready, serverErr := runStalledLDAPServer(t, stallStartTLS)
			connector := &kerberosLDAPConnector{
				allowBootstrap: true,
				bind: func(_ context.Context, conn *ldap.Conn, _, _ string, _ []byte, _ bool, _ *saslSecurityConn) error {
					return conn.GSSAPIBind(&stalledGSSAPIClient{}, "ldap/127.0.0.1", "")
				},
			}
			host, _, err := net.SplitHostPort(address)
			require.NoError(t, err)
			candidate := ldapServerCandidate{address: address, host: host}
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() {
				_, err := connector.connectCandidate(ctx, candidate)
				result <- err
			}()

			<-ready
			start := time.Now()
			cancel()
			require.ErrorIs(t, <-result, context.Canceled)
			assert.Less(t, time.Since(start), time.Second)
			require.NoError(t, <-serverErr)
		})
	}
}

type stalledGSSAPIClient struct{}

func (*stalledGSSAPIClient) InitSecContext(string, []byte) ([]byte, bool, error) {
	return []byte("token"), false, nil
}

func (*stalledGSSAPIClient) InitSecContextWithOptions(string, []byte, []int) ([]byte, bool, error) {
	return []byte("token"), false, nil
}

func (*stalledGSSAPIClient) NegotiateSaslAuth([]byte, string) ([]byte, error) {
	return nil, nil
}

func (*stalledGSSAPIClient) DeleteSecContext() error {
	return nil
}

func runStalledLDAPServer(t *testing.T, stallStartTLS bool) (address string, ready <-chan struct{}, result <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	serverReady := make(chan struct{})
	serverResult := make(chan error, 1)
	var serverCertificate tls.Certificate
	if !stallStartTLS {
		serverCertificate = generateLDAPServerCertificate(t)
	}
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer conn.Close()
		if _, _, err := readBERElement(conn); err != nil {
			serverResult <- err
			return
		}
		if stallStartTLS {
			close(serverReady)
			var b [1]byte
			for err == nil {
				_, err = conn.Read(b[:])
			}
			serverResult <- nil
			return
		}
		if err := writeAll(conn, []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}); err != nil {
			serverResult <- err
			return
		}
		tlsConn := tls.Server(conn, &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{serverCertificate},
		})
		if err := tlsConn.Handshake(); err != nil {
			serverResult <- err
			return
		}
		close(serverReady)
		var b [1]byte
		for err == nil {
			_, err = tlsConn.Read(b[:])
		}
		serverResult <- nil
	}()
	return listener.Addr().String(), serverReady, serverResult
}

func generateLDAPServerCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	return cert
}

func TestDcHostnameFromDomain(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "example.com", dcHostnameFromDomain("EXAMPLE.COM"))
	assert.Equal(t, "test.local", dcHostnameFromDomain("test.local"))
}

func TestTLSServerName(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		server string
		want   string
	}{
		"hostname":      {server: "dc.example.com", want: "dc.example.com"},
		"host and port": {server: "dc.example.com:389", want: "dc.example.com"},
		"IPv6 literal":  {server: "[2001:db8::1]", want: "2001:db8::1"},
		"IPv6 and port": {server: "[2001:db8::1]:389", want: "2001:db8::1"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, tlsServerName(tc.server))
		})
	}
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

func TestCertHashForChannelBinding(t *testing.T) {
	t.Parallel()

	sha256Hash := func(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

	tests := map[string]struct {
		sigAlg x509.SignatureAlgorithm
		hash   func([]byte) []byte
	}{
		"SHA256 signature hashes with SHA256": {
			sigAlg: x509.SHA256WithRSA,
			hash:   sha256Hash,
		},
		"SHA384 signature hashes with SHA384": {
			sigAlg: x509.SHA384WithRSA,
			hash:   func(b []byte) []byte { s := sha512.Sum384(b); return s[:] },
		},
		"SHA512 signature hashes with SHA512": {
			sigAlg: x509.SHA512WithRSA,
			hash:   func(b []byte) []byte { s := sha512.Sum512(b); return s[:] },
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cert := generateTestCert(t, tc.sigAlg)
			assert.Equal(t, tc.hash(cert.Raw), certHashForChannelBinding(cert))
		})
	}
}

func TestTLSServerEndPointChannelBinding(t *testing.T) {
	t.Parallel()

	cert := generateTestCert(t, x509.SHA256WithRSA)

	certHash := sha256.Sum256(cert.Raw)
	appData := append([]byte("tls-server-end-point:"), certHash[:]...)

	got := tlsServerEndPointChannelBinding(cert)
	require.Len(t, got, 16)
	assert.Equal(t, referenceChannelBindingHash(appData), got)
}

func TestGSSChannelBindingsHash(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		appData []byte
	}{
		"Typical tls-server-end-point app data": {appData: []byte("tls-server-end-point:abcdef")},
		"Empty app data":                        {appData: []byte{}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, referenceChannelBindingHash(tc.appData), gssChannelBindingsHash(tc.appData))
		})
	}
}

// generateTestCert creates a self-signed certificate with the given signature
// algorithm for channel-binding tests.
func generateTestCert(t *testing.T, sigAlg x509.SignatureAlgorithm) *x509.Certificate {
	t.Helper()
	return generateTestCertFull(t, "dc.example.com", nil, sigAlg)
}

// generateTestCertFull creates a self-signed certificate with the given Common
// Name, DNS SANs and signature algorithm.
func generateTestCertFull(t *testing.T, cn string, dnsNames []string, sigAlg x509.SignatureAlgorithm) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: cn},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		DNSNames:           dnsNames,
		SignatureAlgorithm: sigAlg,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// referenceChannelBindingHash independently serializes a
// gss_channel_bindings_struct with empty initiator/acceptor addresses and
// MD5-hashes it, mirroring RFC 4121 §4.1.1.2, to cross-check the production
// implementation.
func referenceChannelBindingHash(appData []byte) []byte {
	buf := make([]byte, 16) // four zero 32-bit fields: initiator/acceptor addrtype + length
	l := make([]byte, 4)
	binary.LittleEndian.PutUint32(l, uint32(len(appData))) //nolint:gosec // G115: appData is a fixed short prefix plus a hash digest, well within uint32.
	buf = append(buf, l...)
	buf = append(buf, appData...)
	sum := md5.Sum(buf) //nolint:gosec // G401: matches the protocol-defined transform under test.
	return sum[:]
}

// generateTestCertWithNames creates a self-signed SHA256 certificate with the
// given Common Name and DNS SANs for hostname-verification tests.
func generateTestCertWithNames(t *testing.T, cn string, dnsNames []string) *x509.Certificate {
	t.Helper()
	return generateTestCertFull(t, cn, dnsNames, x509.SHA256WithRSA)
}

// generateTestCAAndLeaf creates a self-signed CA and a leaf certificate signed
// by it. It returns the CA as PEM (to drop into a trust directory) and the leaf
// as DER (as presented on the wire). notBefore/notAfter bound the leaf validity
// so callers can exercise expiry handling.
func generateTestCAAndLeaf(t *testing.T, cn string, dnsNames []string, notBefore, notAfter time.Time) (caPEM []byte, leafDER []byte) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     dnsNames,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err = x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return caPEM, leafDER
}

func TestVerifyPeerCertificate(t *testing.T) {
	t.Parallel()

	const host = "dc.example.com"
	now := time.Now()

	tests := map[string]struct {
		// setup returns the DER chain the DC "presents" (leaf first), the
		// adsys-managed trust directory, and the host to verify against.
		setup          func(t *testing.T) (rawCerts [][]byte, trustDir, host string)
		allowBootstrap bool

		wantErr       bool
		wantBootstrap bool
	}{
		"strict rejects a certificate from an unknown authority": {
			setup: func(t *testing.T) ([][]byte, string, string) {
				t.Helper()
				return [][]byte{generateTestCertWithNames(t, host, nil).Raw}, t.TempDir(), host
			},
			allowBootstrap: false,
			wantErr:        true,
		},
		"bootstrap accepts an unknown authority when the hostname matches": {
			setup: func(t *testing.T) ([][]byte, string, string) {
				t.Helper()
				return [][]byte{generateTestCertWithNames(t, host, nil).Raw}, t.TempDir(), host
			},
			allowBootstrap: true,
			wantBootstrap:  true,
		},
		"bootstrap still rejects a mismatched hostname": {
			setup: func(t *testing.T) ([][]byte, string, string) {
				t.Helper()
				return [][]byte{generateTestCertWithNames(t, "other.example.com", nil).Raw}, t.TempDir(), host
			},
			allowBootstrap: true,
			wantErr:        true,
		},
		"bootstrap still rejects an expired certificate": {
			setup: func(t *testing.T) ([][]byte, string, string) {
				t.Helper()
				trustDir := t.TempDir()
				caPEM, leafDER := generateTestCAAndLeaf(t, host, []string{host}, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
				require.NoError(t, os.WriteFile(filepath.Join(trustDir, "root.crt"), caPEM, 0600))
				return [][]byte{leafDER}, trustDir, host
			},
			allowBootstrap: true,
			wantErr:        true,
		},
		"bootstrap rejects unknown authority once managed trust exists": {
			setup: func(t *testing.T) ([][]byte, string, string) {
				t.Helper()
				trustDir := t.TempDir()
				unrelatedCA, _ := generateTestCAAndLeaf(t, "unrelated.example.com", nil, now.Add(-time.Hour), now.Add(time.Hour))
				require.NoError(t, os.WriteFile(filepath.Join(trustDir, "configured-root.crt"), unrelatedCA, 0600))
				return [][]byte{generateTestCertWithNames(t, host, nil).Raw}, trustDir, host
			},
			allowBootstrap: true,
			wantErr:        true,
		},
		"strict accepts a certificate signed by an installed CA": {
			setup: func(t *testing.T) ([][]byte, string, string) {
				t.Helper()
				trustDir := t.TempDir()
				caPEM, leafDER := generateTestCAAndLeaf(t, host, []string{host}, now.Add(-time.Hour), now.Add(time.Hour))
				require.NoError(t, os.WriteFile(filepath.Join(trustDir, "root.crt"), caPEM, 0600))
				return [][]byte{leafDER}, trustDir, host
			},
			allowBootstrap: false,
			wantErr:        false,
		},
		"no certificate presented is rejected": {
			setup: func(t *testing.T) ([][]byte, string, string) {
				t.Helper()
				return nil, t.TempDir(), host
			},
			allowBootstrap: true,
			wantErr:        true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			rawCerts, trustDir, h := tc.setup(t)
			state := &ldapTLSTrustState{}
			err := verifyPeerCertificateWithTrustState(h, trustDir, tc.allowBootstrap, state)(rawCerts, nil)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantBootstrap, state.bootstrap.Load())
		})
	}
}

func TestVerifyHostnameWithCNFallback(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cert func(t *testing.T) *x509.Certificate
		host string

		wantErr bool
	}{
		"CN fallback matches when certificate has no SAN": {
			cert: func(t *testing.T) *x509.Certificate {
				t.Helper()
				return generateTestCertWithNames(t, "dc.example.com", nil)
			},
			host: "dc.example.com",
		},
		"CN fallback is case-insensitive": {
			cert: func(t *testing.T) *x509.Certificate {
				t.Helper()
				return generateTestCertWithNames(t, "DC.Example.COM", nil)
			},
			host: "dc.example.com",
		},
		"CN fallback wildcard matches": {
			cert: func(t *testing.T) *x509.Certificate {
				t.Helper()
				return generateTestCertWithNames(t, "*.example.com", nil)
			},
			host: "dc.example.com",
		},
		"CN mismatch fails": {
			cert: func(t *testing.T) *x509.Certificate {
				t.Helper()
				return generateTestCertWithNames(t, "other.example.com", nil)
			},
			host:    "dc.example.com",
			wantErr: true,
		},
		"SAN present and matches": {
			cert: func(t *testing.T) *x509.Certificate {
				t.Helper()
				return generateTestCertWithNames(t, "ignored.example.com", []string{"dc.example.com"})
			},
			host: "dc.example.com",
		},
		"SAN present but does not match fails (no CN fallback)": {
			cert: func(t *testing.T) *x509.Certificate {
				t.Helper()
				return generateTestCertWithNames(t, "dc.example.com", []string{"other.example.com"})
			},
			host:    "dc.example.com",
			wantErr: true,
		},
		"No SAN and no CN fails": {
			cert: func(t *testing.T) *x509.Certificate {
				t.Helper()
				return &x509.Certificate{}
			},
			host:    "dc.example.com",
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := verifyHostnameWithCNFallback(tc.cert(t), tc.host)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestMatchHostname(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		pattern string
		host    string

		want bool
	}{
		"Exact match":                             {pattern: "dc.example.com", host: "dc.example.com", want: true},
		"Case-insensitive match":                  {pattern: "DC.Example.COM", host: "dc.example.com", want: true},
		"Trailing dot is ignored":                 {pattern: "dc.example.com.", host: "dc.example.com", want: true},
		"Wildcard matches a single label":         {pattern: "*.example.com", host: "dc.example.com", want: true},
		"Wildcard does not match multiple labels": {pattern: "*.example.com", host: "a.b.example.com", want: false},
		"Different host fails":                    {pattern: "dc.example.com", host: "other.example.com", want: false},
		"Label count mismatch fails":              {pattern: "example.com", host: "dc.example.com", want: false},
		"Empty pattern fails":                     {pattern: "", host: "dc.example.com", want: false},
		"Empty host fails":                        {pattern: "dc.example.com", host: "", want: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, matchHostname(tc.pattern, tc.host))
		})
	}
}

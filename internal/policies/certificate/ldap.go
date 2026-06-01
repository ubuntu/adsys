package certificate

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	krbclient "github.com/oiweiwei/gokrb5.fork/v9/client"
	krbconfig "github.com/oiweiwei/gokrb5.fork/v9/config"
	"github.com/oiweiwei/gokrb5.fork/v9/credentials"

	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
)

// certAuthority represents a Certificate Authority discovered from AD via LDAP.
type certAuthority struct {
	Name             string   // CN of the CA
	Hostname         string   // DNS hostname of the CA server
	CACertificate    []byte   // DER-encoded CA certificate
	CACertificateB64 string   // Base64-encoded CA certificate (for convenience)
	Templates        []string // Certificate templates the CA is configured to issue
}

// templateAttrs represents attributes of a certificate template.
type templateAttrs struct {
	Name       string
	MinKeySize int
}

// LDAPClient abstracts LDAP operations for testing.
type LDAPClient interface {
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

// LDAPConnector abstracts LDAP connection establishment for testing.
type LDAPConnector func(server string) (LDAPClient, error)

// newKerberosLDAPConnector returns an LDAPConnector that performs GSSAPI bind
// using the machine's Kerberos credential cache from krb5CacheDir.
//
// The ccache is located by scanning krb5CacheDir for the machine credential
// cache file (the same location the AD backend copies it to).
func newKerberosLDAPConnector(krb5CacheDir string) LDAPConnector {
	return func(server string) (LDAPClient, error) {
		// Resolve the actual DC hostname so that the LDAP connection
		// and the Kerberos SPN target the same host.
		dcHost := resolveDCHostname(server)
		if dcHost == "" {
			dcHost = server
		}

		log.Debugf(context.Background(), "Connecting to LDAP server: %s", dcHost)
		conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s", dcHost))
		if err != nil {
			return nil, fmt.Errorf("failed to connect to LDAP server %s: %w", dcHost, err)
		}

		if err := gssapiBind(conn, dcHost, krb5CacheDir); err != nil {
			conn.Close()
			return nil, fmt.Errorf("GSSAPI bind to %s failed: %w", dcHost, err)
		}

		log.Debugf(context.Background(), "LDAP connection established and authenticated to %s", dcHost)
		return conn, nil
	}
}

// gssapiBind performs a GSSAPI/Kerberos bind on an LDAP connection.
// It locates the machine's Kerberos credential cache by checking:
//  1. KRB5CCNAME environment variable
//  2. The krb5CacheDir managed by the AD backend
//  3. Default /tmp/krb5cc_0
func gssapiBind(conn *ldap.Conn, server, krb5CacheDir string) error {
	ccachePath, err := findKrb5CCachePath(krb5CacheDir)
	if err != nil {
		return fmt.Errorf("locating Kerberos credential cache: %w", err)
	}

	ccache, err := credentials.LoadCCache(ccachePath)
	if err != nil {
		return fmt.Errorf("loading Kerberos credential cache %s: %w", ccachePath, err)
	}

	krb5Conf, err := krbconfig.Load("/etc/krb5.conf")
	if err != nil {
		// Use a minimal config if the file doesn't exist
		krb5Conf = krbconfig.New()
	}
	// Ensure DNS-based KDC discovery is enabled, as domain-joined machines
	// typically don't list KDCs explicitly in krb5.conf (sssd uses DNS SRV).
	krb5Conf.LibDefaults.DNSLookupKDC = true

	cl, err := krbclient.NewFromCCache(ccache, krb5Conf)
	if err != nil {
		return fmt.Errorf("creating Kerberos client from ccache: %w", err)
	}

	spn := fmt.Sprintf("ldap/%s", server)
	log.Debugf(context.Background(), "Performing GSSAPI bind using SPN: %s", spn)
	gssClient := newGSSAPIClient(cl)

	if err := conn.GSSAPIBind(gssClient, spn, ""); err != nil {
		return fmt.Errorf("GSSAPI bind failed for SPN %s: %w", spn, err)
	}

	log.Debugf(context.Background(), "GSSAPI bind successful for SPN: %s", spn)
	return nil
}

// findKrb5CCachePath locates the machine's Kerberos credential cache file.
func findKrb5CCachePath(krb5CacheDir string) (string, error) {
	// 1. Check KRB5CCNAME environment variable
	if envPath := os.Getenv("KRB5CCNAME"); envPath != "" {
		envPath = strings.TrimPrefix(envPath, "FILE:")
		if _, err := os.Stat(envPath); err == nil {
			log.Debugf(context.Background(), "Using Kerberos ccache from KRB5CCNAME: %s", envPath)
			return envPath, nil
		}
	}

	// 2. Look for a machine ccache in the AD backend's cache directory
	if krb5CacheDir != "" {
		entries, err := os.ReadDir(krb5CacheDir)
		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				path := filepath.Join(krb5CacheDir, entry.Name())
				log.Debugf(context.Background(), "Using Kerberos ccache from cache directory: %s", path)
				return path, nil
			}
		}
	}

	// 3. Default machine ccache location
	defaultPath := "/tmp/krb5cc_0"
	if _, err := os.Stat(defaultPath); err == nil {
		log.Debugf(context.Background(), "Using default Kerberos ccache: %s", defaultPath)
		return defaultPath, nil
	}

	return "", fmt.Errorf("no Kerberos credential cache found (checked KRB5CCNAME, %s, %s)", krb5CacheDir, defaultPath)
}

// fetchCertificationAuthorities queries LDAP for all enrollment services
// (pKIEnrollmentService objects) under the configuration naming context.
//
// This implements [MS-CAESO] 4.4.5.3.1.2 — Initialize CAs.
func fetchCertificationAuthorities(conn LDAPClient, configDN string) ([]certAuthority, error) {
	baseDN := fmt.Sprintf("CN=Enrollment Services,CN=Public Key Services,CN=Services,%s", configDN)
	log.Debugf(context.Background(), "Searching LDAP for enrollment services under: %s", baseDN)

	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=pKIEnrollmentService)",
		[]string{"cn", "dNSHostName", "cACertificate", "certificateTemplates"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("LDAP search for enrollment services failed: %w", err)
	}
	log.Debugf(context.Background(), "LDAP returned %d enrollment service entries", len(result.Entries))

	var cas []certAuthority
	for _, entry := range result.Entries {
		cn := entry.GetAttributeValue("cn")
		hostname := entry.GetAttributeValue("dNSHostName")
		caCertRaw := entry.GetRawAttributeValue("cACertificate")
		templates := entry.GetAttributeValues("certificateTemplates")

		if cn == "" || hostname == "" {
			continue
		}

		ca := certAuthority{
			Name:             cn,
			Hostname:         hostname,
			CACertificate:    caCertRaw,
			CACertificateB64: base64.StdEncoding.EncodeToString(caCertRaw),
			Templates:        templates,
		}
		log.Debugf(context.Background(), "Discovered CA: %s (host: %s, templates: %d)", cn, hostname, len(templates))
		cas = append(cas, ca)
	}

	return cas, nil
}

// fetchTemplateAttrs queries LDAP for a specific certificate template's
// attributes, particularly the minimum key size.
func fetchTemplateAttrs(conn LDAPClient, configDN, templateName string) (templateAttrs, error) {
	baseDN := fmt.Sprintf("CN=Certificate Templates,CN=Public Key Services,CN=Services,%s", configDN)
	log.Debugf(context.Background(), "Fetching LDAP attributes for certificate template: %s", templateName)

	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(cn=%s)", ldap.EscapeFilter(templateName)),
		[]string{"cn", "msPKI-Minimal-Key-Size"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return templateAttrs{Name: templateName, MinKeySize: 2048}, nil //nolint:nilerr // Default to 2048 if template lookup fails
	}

	if len(result.Entries) == 0 {
		log.Debugf(context.Background(), "Template %s not found in LDAP, defaulting to 2048-bit key size", templateName)
		return templateAttrs{Name: templateName, MinKeySize: 2048}, nil
	}

	entry := result.Entries[0]
	minKeySize := 2048
	if v := entry.GetAttributeValue("msPKI-Minimal-Key-Size"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			minKeySize = parsed
		}
	}

	return templateAttrs{
		Name:       templateName,
		MinKeySize: minKeySize,
	}, nil
}

// fetchConfigDN retrieves the configuration naming context from the LDAP
// root DSE of the given server.
func fetchConfigDN(conn LDAPClient) (string, error) {
	log.Debug(context.Background(), "Fetching configuration naming context from LDAP root DSE")
	searchReq := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"configurationNamingContext"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return "", fmt.Errorf("failed to query root DSE: %w", err)
	}

	if len(result.Entries) == 0 {
		return "", fmt.Errorf("root DSE returned no entries")
	}

	configDN := result.Entries[0].GetAttributeValue("configurationNamingContext")
	if configDN == "" {
		return "", fmt.Errorf("configurationNamingContext not found in root DSE")
	}

	log.Debugf(context.Background(), "Configuration naming context: %s", configDN)
	return configDN, nil
}

// discoverCAsAndTemplates connects to the DC via LDAP and discovers all
// CAs and their supported templates. This is the main entry point for
// LDAP-based discovery, replacing both the Samba LDAP queries and the
// CEPCES GET-SUPPORTED-TEMPLATES call.
func discoverCAsAndTemplates(connect LDAPConnector, server string) ([]certAuthority, error) {
	log.Debugf(context.Background(), "Discovering CAs and certificate templates from DC: %s", server)
	conn, err := connect(server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	configDN, err := fetchConfigDN(conn)
	if err != nil {
		return nil, err
	}

	cas, err := fetchCertificationAuthorities(conn, configDN)
	if err != nil {
		return nil, err
	}

	log.Debugf(context.Background(), "Discovery complete: found %d CAs on %s", len(cas), server)
	return cas, nil
}

// dcHostnameFromDomain derives the DC hostname from the domain name.
// AD DNS resolves the domain to a DC, so we use it directly for the LDAP
// connection (AD round-robins). The actual DC hostname is resolved
// separately for the Kerberos SPN.
func dcHostnameFromDomain(domain string) string {
	return strings.ToLower(domain)
}

// resolveDCHostname resolves the actual DC FQDN for a domain via DNS SRV.
// Returns empty string if resolution fails (caller should use the original server).
func resolveDCHostname(domain string) string {
	_, addrs, err := net.LookupSRV("ldap", "tcp", domain)
	if err != nil || len(addrs) == 0 {
		return ""
	}
	// Use the first (highest priority) DC and strip the trailing dot
	return strings.TrimSuffix(strings.ToLower(addrs[0].Target), ".")
}

package certificate

import (
	"context"
	"crypto/md5" //nolint:gosec // G501: MD5 is mandated by RFC 4121 §4.1.1.2 for the GSS-API channel bindings field; it is a protocol-defined transform, not a security primitive.
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	krbclient "github.com/oiweiwei/gokrb5.fork/v9/client"
	"github.com/oiweiwei/gokrb5.fork/v9/credentials"
	"github.com/ubuntu/adsys/internal/consts"
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
// cache file (the same location the AD backend copies it to). globalTrustDir
// is the adsys-managed trust directory whose CA certificates are accepted (in
// addition to the system trust store) when verifying the DC's StartTLS cert.
//
// allowBootstrap permits the StartTLS handshake to proceed when the DC
// certificate cannot yet be chained to a trusted root (see
// verifyPeerCertificate). This is required for the first enrollment, where the
// enterprise CA is only discovered and installed later in the same run; the DC
// is still authenticated by the Kerberos GSSAPI bind (with TLS channel binding)
// performed immediately after StartTLS.
func newKerberosLDAPConnector(krb5CacheDir, globalTrustDir string, allowBootstrap bool) LDAPConnector {
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

		if err := conn.StartTLS(ldapTLSConfig(dcHost, globalTrustDir, allowBootstrap)); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to start TLS on LDAP connection to %s: %w", dcHost, err)
		}

		if err := gssapiBind(conn, dcHost, krb5CacheDir); err != nil {
			conn.Close()
			return nil, fmt.Errorf("GSSAPI bind to %s failed: %w", dcHost, err)
		}

		log.Debugf(context.Background(), "LDAP connection established and authenticated to %s", dcHost)
		return conn, nil
	}
}

// NewKerberosLDAPConnector returns an LDAPConnector that performs a GSSAPI bind
// to a domain controller using the machine's Kerberos credential cache located
// in krb5CacheDir (typically filepath.Join(runDir, "krb5cc")), with StartTLS and
// channel binding. It is exported so other AD-facing managers — such as DFS
// namespace resolution for user mounts — can reuse the same authenticated LDAP
// path. It does not allow the StartTLS bootstrap exception used during first
// certificate enrollment; the DC certificate must already be trusted.
func NewKerberosLDAPConnector(krb5CacheDir, globalTrustDir string) LDAPConnector {
	return newKerberosLDAPConnector(krb5CacheDir, globalTrustDir, false)
}

func ldapTLSConfig(server, globalTrustDir string, allowBootstrap bool) *tls.Config {
	//nolint:gosec // G123: ClientSessionCache is a zero-capacity cache, so no
	// client-side session resumption occurs and VerifyPeerCertificate runs on
	// every handshake; InsecureSkipVerify is paired with manual verification.
	return &tls.Config{
		MinVersion:            tls.VersionTLS12,
		ServerName:            tlsServerName(server),
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: verifyPeerCertificate(server, globalTrustDir, allowBootstrap),
		// Disable session resumption to ensure certificate verification
		// is performed on every connection (gosec G123).
		ClientSessionCache: tls.NewLRUClientSessionCache(0),
	}
}

// verifyPeerCertificate returns a callback that validates the server's
// certificate chain against the system trust store and any adsys-managed
// CA certificates. This is necessary because the AD root CA may not yet be
// in the system trust store on first enrollment, and we want to accept
// certificates that chain to CAs already installed by adsys in addition
// to the system trust store.
//
// Hostname verification is performed separately from chain verification so that
// it can fall back to the certificate's Common Name: AD domain controller
// certificates issued from legacy templates frequently carry only a CN and no
// Subject Alternative Name, which crypto/x509 refuses to match (since Go 1.15)
// when DNSName is set on Verify.
//
// When allowBootstrap is true, a chain that cannot be built because the issuing
// CA is unknown (x509.UnknownAuthorityError, which also covers a missing
// intermediate in a multi-tier PKI) is tolerated: on the first enrollment the
// enterprise CA is only discovered and installed later in the same run, so the
// DC certificate provably cannot chain to a trusted root yet. In that case the
// DC is authenticated by the Kerberos GSSAPI bind (with tls-server-end-point
// channel binding) performed immediately after StartTLS — the same trust anchor
// Windows autoenrollment relies on. Hostname matching is still enforced, and any
// other verification failure (expired, not-yet-valid, bad constraints) remains
// fatal. Once adsys installs the CA, subsequent handshakes verify strictly.
func verifyPeerCertificate(server, globalTrustDir string, allowBootstrap bool) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no server certificate presented")
		}

		certs := make([]*x509.Certificate, 0, len(rawCerts))
		for _, rawCert := range rawCerts {
			cert, err := x509.ParseCertificate(rawCert)
			if err != nil {
				return fmt.Errorf("failed to parse server certificate: %w", err)
			}
			certs = append(certs, cert)
		}

		// Build the verification pool from the system roots plus any
		// adsys-managed CA certificates in the trust directory.
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}

		// Add any CA certificates already installed by adsys
		addAdsysCAsToPool(pool, globalTrustDir)

		// Verify the chain to a trusted root. DNSName is intentionally left
		// empty so crypto/x509 does not perform hostname matching here; we do
		// it below with a Common Name fallback.
		opts := x509.VerifyOptions{
			Roots:         pool,
			Intermediates: x509.NewCertPool(),
		}
		for i, cert := range certs {
			if i == 0 {
				continue // leaf
			}
			opts.Intermediates.AddCert(cert)
		}

		if _, err := certs[0].Verify(opts); err != nil {
			// On the first enrollment the enterprise CA is not in any trust
			// store yet (adsys installs it later in this same run), so the DC
			// certificate cannot chain to a trusted root. When bootstrapping is
			// allowed, tolerate only this "unknown authority" case and lean on
			// the Kerberos GSSAPI mutual authentication (with TLS channel
			// binding) that runs right after StartTLS to authenticate the DC.
			// Any other failure (expired, not-yet-valid, bad constraints) is
			// still fatal.
			var unknownAuthority x509.UnknownAuthorityError
			if !allowBootstrap || !errors.As(err, &unknownAuthority) {
				return fmt.Errorf("server certificate verification failed: %w", err)
			}
			if hostErr := verifyHostnameWithCNFallback(certs[0], tlsServerName(server)); hostErr != nil {
				return fmt.Errorf("server certificate verification failed: %w", hostErr)
			}
			log.Warningf(context.Background(),
				"Server certificate for %q is not signed by an installed CA yet; trusting it through the authenticated Kerberos channel for bootstrap enrollment (expected on first run): %v",
				tlsServerName(server), err)
			return nil
		}

		if err := verifyHostnameWithCNFallback(certs[0], tlsServerName(server)); err != nil {
			return fmt.Errorf("server certificate verification failed: %w", err)
		}
		return nil
	}
}

// verifyHostnameWithCNFallback checks that host matches the certificate's
// Subject Alternative Names, falling back to the Subject Common Name when the
// certificate carries no SAN entries. The chain itself must already have been
// verified against a trusted root by the caller.
//
// Modern certificates carry SANs and are matched strictly. The CN fallback
// exists solely for AD domain controller certificates issued from legacy
// templates, which often present only a CN; this mirrors what Windows and Samba
// accept when connecting to such DCs.
func verifyHostnameWithCNFallback(cert *x509.Certificate, host string) error {
	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 {
		return cert.VerifyHostname(host)
	}

	cn := cert.Subject.CommonName
	if cn == "" {
		return fmt.Errorf("certificate has no subject alternative names and no common name to match against %q", host)
	}
	if !matchHostname(cn, host) {
		return fmt.Errorf("certificate common name %q does not match server host %q", cn, host)
	}
	log.Debugf(context.Background(), "Server certificate for %q has no SAN; accepted legacy Common Name %q", host, cn)
	return nil
}

// matchHostname reports whether host matches the certificate name pattern. The
// comparison is case-insensitive, ignores a trailing dot, and supports a single
// leading "*" wildcard label, mirroring how crypto/x509 historically matched
// the Common Name.
func matchHostname(pattern, host string) bool {
	pattern = strings.TrimSuffix(strings.ToLower(pattern), ".")
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if pattern == "" || host == "" {
		return false
	}

	patternParts := strings.Split(pattern, ".")
	hostParts := strings.Split(host, ".")
	if len(patternParts) != len(hostParts) {
		return false
	}
	for i, p := range patternParts {
		if i == 0 && p == "*" {
			continue
		}
		if p != hostParts[i] {
			return false
		}
	}
	return true
}

// addAdsysCAsToPool adds CA certificates from the adsys-managed trust
// directories to the given cert pool, so AD root CAs already installed by
// adsys (but not necessarily rebuilt into the system bundle yet) are trusted.
// The default global trust directory is always included; any additional dirs
// (e.g. a non-default configured directory) are merged in and de-duplicated.
func addAdsysCAsToPool(pool *x509.CertPool, dirs ...string) {
	seen := make(map[string]bool, len(dirs)+1)
	for _, dir := range append([]string{consts.DefaultGlobalTrustDir}, dirs...) {
		if dir == "" || seen[dir] {
			continue
		}
		seen[dir] = true
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if !strings.HasSuffix(entry.Name(), ".crt") && !strings.HasSuffix(entry.Name(), ".pem") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				continue
			}
			pool.AppendCertsFromPEM(data)
		}
	}
}

func tlsServerName(server string) string {
	host, _, err := net.SplitHostPort(server)
	if err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(server, "[]")
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

	krb5Conf, err := newKerberosClientConfig(server, ccache.DefaultPrincipal.Realm)
	if err != nil {
		return fmt.Errorf("configuring Kerberos client for LDAP server %s: %w", server, err)
	}

	cl, err := krbclient.NewFromCCache(ccache, krb5Conf)
	if err != nil {
		return fmt.Errorf("creating Kerberos client from ccache: %w", err)
	}

	// Compute the TLS channel binding token (RFC 5929 tls-server-end-point) from
	// the StartTLS server certificate so the bind succeeds against DCs that
	// enforce LDAP channel binding (CBT/EPA). Without it such DCs reject the bind
	// with LDAP result code 49, data 80090346 (SEC_E_BAD_BINDINGS). The token is
	// ignored by DCs that do not enforce channel binding, so this is always safe.
	channelBinding := tlsChannelBindingToken(conn)

	spn := fmt.Sprintf("ldap/%s", server)
	log.Debugf(context.Background(), "Performing GSSAPI bind using SPN: %s", spn)
	gssClient := newGSSAPIClient(cl, channelBinding)

	if err := conn.GSSAPIBind(gssClient, spn, ""); err != nil {
		return fmt.Errorf("GSSAPI bind failed for SPN %s: %w", spn, err)
	}

	log.Debugf(context.Background(), "GSSAPI bind successful for SPN: %s", spn)
	return nil
}

// tlsChannelBindingToken returns the RFC 5929 tls-server-end-point channel
// binding token for the connection's TLS server certificate, or nil when the
// connection exposes no peer certificate (e.g. StartTLS was not performed). The
// returned value is the 16-byte MD5 hash embedded in the GSS-API authenticator
// checksum.
func tlsChannelBindingToken(conn *ldap.Conn) []byte {
	state, ok := conn.TLSConnectionState()
	if !ok || len(state.PeerCertificates) == 0 {
		log.Debug(context.Background(), "No TLS peer certificate available; binding without channel binding")
		return nil
	}
	token := tlsServerEndPointChannelBinding(state.PeerCertificates[0])
	log.Debugf(context.Background(), "Computed tls-server-end-point channel binding token (%d bytes)", len(token))
	return token
}

// tlsServerEndPointChannelBinding computes the GSS-API channel bindings hash for
// the "tls-server-end-point" channel binding type (RFC 5929 §4) from the given
// server certificate.
//
// The application data is "tls-server-end-point:" followed by the certificate
// hash; the GSS channel bindings structure (with empty addresses) is then
// MD5-hashed per RFC 4121 §4.1.1.2 to produce the 16-byte Bnd value.
func tlsServerEndPointChannelBinding(cert *x509.Certificate) []byte {
	appData := append([]byte("tls-server-end-point:"), certHashForChannelBinding(cert)...)
	return gssChannelBindingsHash(appData)
}

// certHashForChannelBinding hashes the certificate's DER encoding using the
// hash algorithm mandated by RFC 5929 §4.1: the certificate's own signature
// hash, but with MD5 and SHA-1 (and unknown/hashless algorithms such as
// Ed25519) upgraded to SHA-256.
func certHashForChannelBinding(cert *x509.Certificate) []byte {
	switch cert.SignatureAlgorithm {
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		sum := sha512.Sum384(cert.Raw)
		return sum[:]
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		sum := sha512.Sum512(cert.Raw)
		return sum[:]
	default:
		sum := sha256.Sum256(cert.Raw)
		return sum[:]
	}
}

// gssChannelBindingsHash serializes a gss_channel_bindings_struct with empty
// initiator/acceptor addresses and the given application data, then returns its
// MD5 hash (RFC 4121 §4.1.1.2 / RFC 1964 §1.1.1). All integer fields are
// little-endian.
func gssChannelBindingsHash(appData []byte) []byte {
	buf := make([]byte, 0, 20+len(appData))
	var zero [4]byte
	buf = append(buf, zero[:]...) // initiator_addrtype = 0
	buf = append(buf, zero[:]...) // initiator_address length = 0
	buf = append(buf, zero[:]...) // acceptor_addrtype = 0
	buf = append(buf, zero[:]...) // acceptor_address length = 0
	var l [4]byte
	binary.LittleEndian.PutUint32(l[:], uint32(len(appData))) //nolint:gosec // G115: appData is a fixed short prefix plus a hash digest, well within uint32.
	buf = append(buf, l[:]...)                                // application_data length
	buf = append(buf, appData...)

	sum := md5.Sum(buf) //nolint:gosec // G401: MD5 required by RFC 4121 §4.1.1.2 for the channel bindings field.
	return sum[:]
}

// findKrb5CCachePath locates the machine's Kerberos credential cache file.
func findKrb5CCachePath(krb5CacheDir string) (string, error) {
	// 1. Check KRB5CCNAME environment variable
	if envPath := os.Getenv("KRB5CCNAME"); envPath != "" {
		envPath = strings.TrimPrefix(envPath, "FILE:")
		if _, err := os.Stat(envPath); err == nil { //nolint:gosec // G703: envPath is from KRB5CCNAME, a system-controlled env var
			log.Debugf(context.Background(), "Using Kerberos ccache from KRB5CCNAME: %s", envPath)
			return envPath, nil
		}
	}

	// 2. Look for a machine ccache in the AD backend's cache directory.
	// The directory can hold several tickets (e.g. user@DOMAIN alongside the
	// machine ticket); prefer the machine cache (filenames without '@') so
	// LDAP/RPC operations bind with the correct principal, and only fall back
	// to another regular file if no machine cache is present.
	if krb5CacheDir != "" {
		if entries, err := os.ReadDir(krb5CacheDir); err == nil {
			var fallback string
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				path := filepath.Join(krb5CacheDir, entry.Name())
				if !strings.Contains(entry.Name(), "@") {
					log.Debugf(context.Background(), "Using machine Kerberos ccache from cache directory: %s", path)
					return path, nil
				}
				if fallback == "" {
					fallback = path
				}
			}
			if fallback != "" {
				log.Debugf(context.Background(), "Using Kerberos ccache from cache directory: %s", fallback)
				return fallback, nil
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
		// Surface the LDAP failure so callers can log it, while still returning a
		// safe default key size to let enrollment proceed.
		return templateAttrs{Name: templateName, MinKeySize: 2048}, fmt.Errorf("LDAP search for certificate template %s failed: %w", templateName, err)
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

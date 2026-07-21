package certificate

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wcce"
	epmpkg "github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	icertpassage "github.com/oiweiwei/go-msrpc/msrpc/icpr/icertpassage/v0"
	"github.com/oiweiwei/go-msrpc/ssp"
	sspcredential "github.com/oiweiwei/go-msrpc/ssp/credential"
	krbcredentials "github.com/oiweiwei/gokrb5.fork/v9/credentials"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
)

// MS-ICPR request flags.
const (
	crInBinary = 0x2
	crInPKCS10 = 0x100
)

// MS-ICPR disposition values.
const (
	crDispIssued          = 3
	crDispUnderSubmission = 5
)

// maxIssuedCertBytes bounds the size of the DER certificate accepted from AD CS
// over RPC, to avoid unbounded memory use from a malicious or buggy CA.
const maxIssuedCertBytes = 1 << 20 // 1 MiB

// CSRSubmitter submits a CSR to AD CS and returns the issued PEM certificate.
type CSRSubmitter func(ctx context.Context, server, caName, template, csrPEM string) (string, error)

// EnrollmentRequest describes a single direct certificate enrollment.
type EnrollmentRequest struct {
	Server     string
	CAName     string
	Template   string
	CommonName string
	KeyFile    string
	CertFile   string
	KeySize    int
	// ExpectedChain is ordered from the selected issuing CA to the
	// self-signed trust anchor discovered from Active Directory.
	ExpectedChain []*x509.Certificate
}

// SubmitCSR submits a certificate signing request to an AD CS server using
// the MS-ICPR protocol (ICertPassage::CertServerRequest) via DCE/RPC.
//
// It discovers the Kerberos credential cache from the KRB5CCNAME environment
// variable or /tmp/krb5cc_0. For production use via the Manager, prefer
// newSubmitCSR which also searches the adsys krb5 cache directory.
func SubmitCSR(ctx context.Context, server, caName, template, csrPEM string) (string, error) {
	return submitCSRImpl(ctx, server, caName, template, csrPEM, "")
}

// newSubmitCSR creates a CSRSubmitter that uses the specified Kerberos
// credential cache directory for authentication against the AD CS server.
func newSubmitCSR(krb5CacheDir string) CSRSubmitter {
	return func(ctx context.Context, server, caName, template, csrPEM string) (string, error) {
		return submitCSRImpl(ctx, server, caName, template, csrPEM, krb5CacheDir)
	}
}

// submitCSRImpl is the core CSR submission implementation. It configures
// Kerberos authentication (SPN + credential cache) and connects to the
// AD CS server via the MS-ICPR DCE/RPC interface.
func submitCSRImpl(ctx context.Context, server, caName, template, csrPEM, krb5CacheDir string) (string, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM CSR")
	}
	csrDER := block.Bytes

	// Locate the Kerberos credential cache for RPC authentication.
	ccachePath, err := findKrb5CCachePath(krb5CacheDir)
	if err != nil {
		return "", fmt.Errorf("locating Kerberos credential cache for CSR submission: %w", err)
	}
	log.Debugf(ctx, "Using Kerberos ccache %s for CSR submission", ccachePath)

	// The Kerberos SPN for the AD CS RPC endpoint (MS-ICPR) is "host/<fqdn>".
	targetName := "host/" + server
	rpcCredential, err := rpcCredentialFromCCachePath(ccachePath)
	if err != nil {
		return "", fmt.Errorf("loading Kerberos credential cache %s: %w", ccachePath, err)
	}

	// MS-ICPR runs over authenticated RPC, so the credential cache has to be
	// wired into the DCE/RPC security options used by both the endpoint mapper
	// and the final ICertPassage bind.
	krb5Conf, err := newRPCKrb5Config(ccachePath, server, rpcCredential.DomainName())
	if err != nil {
		return "", fmt.Errorf("configuring Kerberos for CSR submission to %s: %w", server, err)
	}
	securityOpts := []dcerpc.Option{
		dcerpc.WithMechanism(ssp.KRB5, krb5Conf),
		dcerpc.WithCredentials(rpcCredential),
		dcerpc.WithSeal(),
		dcerpc.WithTargetName(targetName),
	}

	log.Debugf(ctx, "Connecting to AD CS server %s (SPN: %s)", server, targetName)
	dialOpts := make([]dcerpc.Option, 0, len(securityOpts)+1)
	dialOpts = append(dialOpts, epmpkg.EndpointMapper(ctx, server, securityOpts...))
	dialOpts = append(dialOpts, securityOpts...)
	conn, err := dcerpc.Dial(ctx, server, dialOpts...)
	if err != nil {
		return "", fmt.Errorf("connecting to %s: %w", server, err)
	}
	defer conn.Close(ctx)

	cli, err := icertpassage.NewCertPassageClient(ctx, conn)
	if err != nil {
		return "", rpcClientError(server, targetName, err)
	}

	attribs := buildAttributes(template)

	log.Debugf(ctx, "Submitting CSR to CA %q on server %s using template %q", caName, server, template)
	resp, err := cli.CertServerRequest(ctx, &icertpassage.CertServerRequestRequest{
		Flags:     crInPKCS10 | crInBinary,
		Authority: caName,
		RequestID: 0,
		Attributes: &wcce.CertTransportBlob{
			Length: uint32(len(attribs)), //nolint:gosec // G115: attribute blob length is bounded well below math.MaxUint32
			Buffer: attribs,
		},
		Request: &wcce.CertTransportBlob{
			Length: uint32(len(csrDER)), //nolint:gosec // G115: CSR DER length is bounded well below math.MaxUint32
			Buffer: csrDER,
		},
	})
	if err != nil {
		return "", fmt.Errorf("CertServerRequest RPC call failed: %w", err)
	}

	switch resp.Disposition {
	case crDispIssued:
		log.Debugf(ctx, "Certificate issued by CA %q (request ID: %d)", caName, resp.RequestID)
	case crDispUnderSubmission:
		return "", fmt.Errorf("certificate request is pending (request ID: %d) - manual approval required", resp.RequestID)
	default:
		msg := ""
		if resp.DispositionMessage != nil && len(resp.DispositionMessage.Buffer) > 0 {
			msg = decodeUTF16(resp.DispositionMessage.Buffer)
		}
		return "", fmt.Errorf("certificate request denied (disposition=%d): %s", resp.Disposition, msg)
	}

	if resp.EncodedCert == nil || len(resp.EncodedCert.Buffer) == 0 {
		return "", fmt.Errorf("server returned empty certificate")
	}
	if len(resp.EncodedCert.Buffer) > maxIssuedCertBytes {
		return "", fmt.Errorf("server returned oversized certificate (%d bytes, max %d)", len(resp.EncodedCert.Buffer), maxIssuedCertBytes)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: resp.EncodedCert.Buffer,
	})

	return string(certPEM), nil
}

func rpcClientError(server, targetName string, err error) error {
	if strings.Contains(err.Error(), "bind: invalid checksum") {
		return fmt.Errorf("creating ICertPassage client on %s: Kerberos RPC bind for SPN %s was rejected with invalid checksum; verify that %s is registered on the CA server account, is not duplicated on another AD object, and that Kerberos realm mapping for %s points to the CA server's realm: %w", server, targetName, targetName, tlsServerName(server), err)
	}
	return fmt.Errorf("creating ICertPassage client on %s: %w", server, err)
}

func rpcCredentialFromCCachePath(ccachePath string) (sspcredential.CCache, error) {
	ccache, err := krbcredentials.LoadCCache(ccachePath)
	if err != nil {
		return nil, err
	}

	return rpcCredentialFromCCache(ccache)
}

func rpcCredentialFromCCache(ccache *krbcredentials.CCache) (sspcredential.CCache, error) {
	if ccache == nil {
		return nil, fmt.Errorf("no Kerberos credential cache provided")
	}

	principal := ccache.GetClientCredentials()
	if principal == nil || principal.UserName() == "" {
		return nil, fmt.Errorf("missing client principal in Kerberos credential cache")
	}
	if len(ccache.Credentials) == 0 {
		return nil, fmt.Errorf("no credentials in Kerberos credential cache")
	}

	var opts []sspcredential.Option
	if realm := principal.Realm(); realm != "" {
		opts = append(opts, sspcredential.Domain(realm))
	}

	return sspcredential.NewFromCCache(principal.UserName(), ccache, opts...), nil
}

// EnrollCertificate creates a keypair and CSR, submits the request to AD CS,
// and writes the resulting key and certificate to disk.
func EnrollCertificate(ctx context.Context, submitCSR CSRSubmitter, request EnrollmentRequest) error {
	if submitCSR == nil {
		submitCSR = SubmitCSR
	}
	if normalizeMachineIdentity(request.CommonName) == "" {
		return fmt.Errorf("expected machine identity is required")
	}
	if len(request.ExpectedChain) == 0 {
		return fmt.Errorf("expected directory CA chain is required")
	}
	if request.KeySize == 0 {
		request.KeySize = 2048
	}

	log.Debugf(ctx, "Generating %d-bit RSA key and CSR for CN=%s", request.KeySize, request.CommonName)
	key, csrPEM, err := generateKeyAndCSR(request.CommonName, request.KeySize)
	if err != nil {
		return err
	}

	log.Debugf(ctx, "Submitting CSR to server %s (CA: %s, template: %s)", request.Server, request.CAName, request.Template)
	certPEM, err := submitCSR(ctx, request.Server, request.CAName, request.Template, csrPEM)
	if err != nil {
		return err
	}

	// Verify the returned certificate's public key matches the generated
	// private key. This prevents a compromised or malicious CA from returning
	// a certificate for a different subject or key.
	cert, err := verifyIssuedCertificate(certPEM, key, request.CommonName, request.ExpectedChain, time.Now())
	if err != nil {
		return fmt.Errorf("issued certificate verification failed: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(request.KeyFile), 0700); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(request.CertFile), 0750); err != nil {
		return fmt.Errorf("failed to create cert directory: %w", err)
	}

	// Write key and certificate atomically to avoid partial files on crash.
	if err := safeWriteFile(request.KeyFile, key, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}
	if err := safeWriteFile(request.CertFile, []byte(certPEM), 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	log.Debugf(ctx, "Certificate enrollment complete: key=%s, cert=%s, fingerprint=%s", request.KeyFile, request.CertFile, certificateFingerprint(cert))
	return nil
}

// verifyIssuedCertificate binds an issued or reused leaf to its private key,
// expected machine identity, selected issuing certificate and exact
// directory-discovered root path.
func verifyIssuedCertificate(certPEM string, keyPEM []byte, identity string, expectedChain []*x509.Certificate, now time.Time) (*x509.Certificate, error) {
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode issued certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse issued certificate: %w", err)
	}
	if cert.IsCA {
		return nil, fmt.Errorf("issued certificate is a CA certificate")
	}
	if now.Before(cert.NotBefore) {
		return nil, fmt.Errorf("issued certificate is not yet valid (NotBefore: %s)", cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return nil, fmt.Errorf("issued certificate has already expired (NotAfter: %s)", cert.NotAfter)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Compare public keys based on key type
	switch privKey := key.(type) {
	case *rsa.PrivateKey:
		certPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("certificate contains %T public key, expected *rsa.PublicKey", cert.PublicKey)
		}
		if certPubKey.N.Cmp(privKey.N) != 0 || certPubKey.E != privKey.E {
			return nil, fmt.Errorf("certificate public key does not match generated private key")
		}
	case *ecdsa.PrivateKey:
		certPubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("certificate contains %T public key, expected *ecdsa.PublicKey", cert.PublicKey)
		}
		if certPubKey.X.Cmp(privKey.X) != 0 || certPubKey.Y.Cmp(privKey.Y) != 0 {
			return nil, fmt.Errorf("certificate public key does not match generated private key")
		}
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", key)
	}

	if err := verifyCertificateIdentity(cert, identity); err != nil {
		return nil, err
	}

	if err := verifyLeafAgainstExactChain(cert, expectedChain, now); err != nil {
		return nil, err
	}
	return cert, nil
}

func verifyCertificateIdentity(cert *x509.Certificate, identity string) error {
	identity = normalizeMachineIdentity(identity)
	if identity == "" {
		return fmt.Errorf("expected machine identity is empty")
	}
	if len(cert.DNSNames) > 0 {
		for _, dnsName := range cert.DNSNames {
			if normalizeMachineIdentity(dnsName) == identity {
				return nil
			}
		}
		return fmt.Errorf("issued certificate DNS names do not contain expected machine identity %q", identity)
	}
	if normalizeMachineIdentity(cert.Subject.CommonName) != identity {
		return fmt.Errorf("issued certificate common name %q does not match expected machine identity %q", cert.Subject.CommonName, identity)
	}
	return nil
}

func verifyLeafAgainstExactChain(cert *x509.Certificate, expectedChain []*x509.Certificate, now time.Time) error {
	if cert.IsCA {
		return fmt.Errorf("issued certificate is a CA certificate")
	}
	if len(expectedChain) == 0 {
		return fmt.Errorf("no expected CA chain was provided")
	}
	if err := verifyExactCAPath(expectedChain, now); err != nil {
		return fmt.Errorf("expected CA chain is invalid: %w", err)
	}
	issuer := expectedChain[0]
	if err := cert.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("issued certificate was not signed by selected issuing CA %s: %w", certificateFingerprint(issuer), err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(expectedChain[len(expectedChain)-1])
	intermediates := x509.NewCertPool()
	for _, chainCert := range expectedChain[:len(expectedChain)-1] {
		intermediates.AddCert(chainCert)
	}
	chains, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("issued certificate does not chain through the selected CA: %w", err)
	}
	matchedIssuer := false
	for _, chain := range chains {
		if len(chain) > 1 && certificateFingerprint(chain[1]) == certificateFingerprint(issuer) {
			matchedIssuer = true
			break
		}
	}
	if !matchedIssuer {
		return fmt.Errorf("issued certificate verification did not use selected issuing CA %s", certificateFingerprint(issuer))
	}
	return nil
}

// safeWriteFile writes data to dst atomically by first writing to a uniquely
// named temporary file in the same directory and then renaming. Using
// os.CreateTemp (O_CREATE|O_EXCL with a random suffix) avoids a predictable
// temp path and refuses to follow a pre-existing symlink, and the temp file is
// cleaned up if anything before the rename fails.
func safeWriteFile(dst string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".tmp.*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	// Best-effort cleanup; the Remove is a no-op once the rename succeeds.
	defer func() { _ = os.Remove(tmp) }()

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// GetSupportedTemplates discovers templates for the CA server via LDAP.
// It uses the KRB5CCNAME environment variable for Kerberos authentication.
func GetSupportedTemplates(server string) ([]string, error) {
	return GetSupportedTemplatesContext(context.Background(), server)
}

// GetSupportedTemplatesContext discovers templates while honoring caller cancellation.
func GetSupportedTemplatesContext(ctx context.Context, server string) ([]string, error) {
	// allowBootstrap: the DC certificate may not chain to an installed CA on a
	// freshly joined machine; GSSAPI protects LDAP with Kerberos confidentiality.
	connector := newKerberosLDAPConnector("", "", true)
	return GetSupportedTemplatesWithConnector(ctx, connector, server)
}

// GetSupportedTemplatesWithConnector discovers templates for the CA server via LDAP.
func GetSupportedTemplatesWithConnector(ctx context.Context, connect LDAPConnector, server string) ([]string, error) {
	discoveryServer := server
	if strings.Contains(server, ".") {
		discoveryServer = dcHostnameFromDomain(domainFromServer(server))
	}

	log.Debugf(ctx, "Discovering supported templates for server %s (discovery server: %s)", server, discoveryServer)
	cas, err := discoverCAsAndTemplates(ctx, connect, discoveryServer)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	var templates []string
	for _, ca := range cas {
		if !strings.EqualFold(ca.Hostname, server) && !strings.EqualFold(ca.Name, server) {
			continue
		}
		for _, template := range ca.Templates {
			if _, ok := seen[template]; ok {
				continue
			}
			seen[template] = struct{}{}
			templates = append(templates, template)
		}
	}

	if len(templates) == 0 {
		return nil, fmt.Errorf("no templates found for server %s", server)
	}

	log.Debugf(ctx, "Found %d supported templates for server %s: %s", len(templates), server, strings.Join(templates, ", "))
	return templates, nil
}

func generateKeyAndCSR(commonName string, keySize int) ([]byte, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate private key: %w", err)
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}, key)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create CSR: %w", err)
	}

	keyPEM, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal private key: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyPEM}), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})), nil
}

func buildAttributes(template string) []byte {
	if template == "" {
		return nil
	}

	attrs := "CertificateTemplate:" + template
	return encodeUTF16(attrs)
}

func encodeUTF16(s string) []byte {
	runes := utf16.Encode([]rune(s))
	buf := make([]byte, (len(runes)+1)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	return buf
}

func decodeUTF16(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	if len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	return string(utf16.Decode(u16))
}

func domainFromServer(server string) string {
	parts := strings.SplitN(server, ".", 2)
	if len(parts) != 2 {
		return server
	}
	return parts[1]
}

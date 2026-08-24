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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	sspcredential "github.com/oiweiwei/go-msrpc/ssp/credential"
	krbcredentials "github.com/oiweiwei/gokrb5.fork/v9/credentials"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
)

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
func safeWriteFile(dst string, data []byte, mode os.FileMode) (err error) {
	if info, statErr := os.Lstat(dst); statErr == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("refusing to replace non-regular file %s", dst)
		}
	} else if !os.IsNotExist(statErr) {
		return statErr
	}
	f, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".tmp.*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if removeErr := os.Remove(tmp); removeErr != nil && !os.IsNotExist(removeErr) {
			err = errors.Join(err, fmt.Errorf("removing temporary file %s: %w", tmp, removeErr))
		}
	}()

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(dst)); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(dst))
}

// GetSupportedTemplatesWithConnector discovers templates for the given CA
// server via LDAP. Discovery runs against the domain controllers of
// discoveryDomain; server only selects among the discovered CAs and is never
// dialed, so its value cannot steer the caller toward arbitrary endpoints.
func GetSupportedTemplatesWithConnector(ctx context.Context, connect LDAPConnector, discoveryDomain, server string) ([]string, error) {
	discoveryServer := dcHostnameFromDomain(discoveryDomain)

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

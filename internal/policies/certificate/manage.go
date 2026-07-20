package certificate

// This file implements the admin-facing management API for the native LDAP
// certificate enrollment method: listing, inspecting, renewing, removing and
// verifying the machine certificates adsys enrolls from AD CS. All operations
// are backed by the persisted enrollment state (see state.go) rather than
// certmonger, and are only available when the active enrollment method is
// "ldap".

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/leonelquinteros/gotext"
	"github.com/ubuntu/adsys/internal/consts"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
)

// CertHealth is the derived health of an enrolled certificate.
type CertHealth string

const (
	// CertHealthy indicates the certificate is present, valid and not near expiry.
	CertHealthy CertHealth = "healthy"
	// CertDueRenewal indicates the certificate is within certRenewalWindow of expiry.
	CertDueRenewal CertHealth = "due_renewal"
	// CertExpired indicates the certificate is past its NotAfter.
	CertExpired CertHealth = "expired"
	// CertMissing indicates the certificate is referenced by state but its key/cert is absent on disk.
	CertMissing CertHealth = "missing"
	// CertKeyMismatch indicates the on-disk private key does not match the certificate.
	CertKeyMismatch CertHealth = "key_mismatch"
	// CertUnparseable indicates the certificate file is present but could not be parsed.
	CertUnparseable CertHealth = "unparseable"
)

// CertInfo describes a single enrolled certificate and its derived health.
type CertInfo struct {
	Nickname, Template, CAName, CAHostname string
	Subject, Issuer, Serial                string
	NotBefore, NotAfter                    time.Time
	DaysUntilExpiry                        int
	SANs, EKU                              []string
	KeyAlgo                                string
	KeySize                                int
	KeyFile, CertFile                      string
	RootCertFiles, TrustSymlinks           []string
	OnDisk, KeyMatchesCert                 bool
	Health                                 CertHealth
	LastEnrolled                           time.Time // state.UpdatedAt
}

// CAInfo describes a certificate authority discovered from AD, cross-referenced
// with the local enrollment state.
type CAInfo struct {
	Name, Hostname   string
	Templates        []string
	RootFingerprints []string // hex SHA-256 of discovered CA cert(s)
	InstalledInTrust bool
	Enrolled         bool
}

// VerifyResult is the outcome of verifying a single enrolled certificate.
type VerifyResult struct {
	Nickname                        string
	ChainOK, ValidityOK, KeyMatchOK bool
	RevocationChecked, Revoked      bool
	Messages                        []string
}

// ErrNotLDAPMethod is returned by all management methods when the active
// enrollment method is not "ldap".
var ErrNotLDAPMethod = errors.New("certificate management is only available with the ldap enrollment method")

// ListCertificates returns information about all certificates enrolled for the
// given object, derived from the persisted enrollment state.
func (m *Manager) ListCertificates(ctx context.Context, objectName string) ([]CertInfo, error) {
	if m.enrollmentMethod != consts.CertEnrollmentLDAP {
		return nil, ErrNotLDAPMethod
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.listCertificatesLocked(ctx, objectName)
}

// listCertificatesLocked builds the CertInfo slice for objectName. The caller
// must hold m.mu.
func (m *Manager) listCertificatesLocked(ctx context.Context, objectName string) ([]CertInfo, error) {
	state, err := loadState(m.stateDir, objectName)
	if err != nil {
		return nil, fmt.Errorf("failed to load enrollment state: %w", err)
	}
	if state == nil {
		log.Debugf(ctx, "No enrollment state for %s, no certificates to list", objectName)
		return []CertInfo{}, nil
	}

	infos := make([]CertInfo, 0)
	for _, ca := range state.CAs {
		for _, tmpl := range ca.Templates {
			infos = append(infos, certInfoFor(ca, tmpl, state.UpdatedAt))
		}
	}
	return infos, nil
}

// CertificateStatus returns the CertInfo for a single enrolled certificate. If
// nickname is empty and exactly one certificate is enrolled, that certificate
// is returned; if several are enrolled the returned error lists their
// nicknames.
func (m *Manager) CertificateStatus(ctx context.Context, objectName, nickname string) (CertInfo, error) {
	if m.enrollmentMethod != consts.CertEnrollmentLDAP {
		return CertInfo{}, ErrNotLDAPMethod
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	certs, err := m.listCertificatesLocked(ctx, objectName)
	if err != nil {
		return CertInfo{}, err
	}
	if len(certs) == 0 {
		return CertInfo{}, errors.New(gotext.Get("no enrolled certificates found for %q", objectName))
	}

	if nickname == "" {
		if len(certs) == 1 {
			return certs[0], nil
		}
		return CertInfo{}, errors.New(gotext.Get("multiple certificates enrolled, specify a nickname (one of: %s)", strings.Join(nicknamesOf(certs), ", ")))
	}

	for _, c := range certs {
		if c.Nickname == nickname {
			return c, nil
		}
	}
	return CertInfo{}, errors.New(gotext.Get("certificate %q not found (valid nicknames: %s)", nickname, strings.Join(nicknamesOf(certs), ", ")))
}

// RenewCertificates re-enrolls certificates from AD CS. If all is true every
// enrolled template is renewed; otherwise only the template matching nickname
// is. A failure to renew one template is logged and reported through progress
// but does not abort the others; an aggregated error is returned at the end if
// any renewal failed.
func (m *Manager) RenewCertificates(ctx context.Context, objectName, nickname string, all bool, progress func(string)) error {
	if m.enrollmentMethod != consts.CertEnrollmentLDAP {
		return ErrNotLDAPMethod
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := loadState(m.stateDir, objectName)
	if err != nil {
		return fmt.Errorf("failed to load enrollment state: %w", err)
	}
	if state == nil || len(state.CAs) == 0 {
		return errors.New(gotext.Get("no enrolled certificates found for %q", objectName))
	}
	if !all && nickname == "" {
		return errors.New(gotext.Get("a certificate nickname is required unless renewing all certificates"))
	}

	var failures []string
	found := false
	for i := range state.CAs {
		ca := &state.CAs[i]
		for _, tmpl := range ca.Templates {
			if !all && tmpl.Nickname != nickname {
				continue
			}
			found = true

			keySize := m.templateKeySize(ctx, tmpl.Template)
			report(progress, gotext.Get("Renewing %s…", tmpl.Nickname))
			log.Debugf(ctx, "Renewing certificate %s (template %s) from CA %s", tmpl.Nickname, tmpl.Template, ca.Name)

			if err := EnrollCertificate(ctx, m.submitCSR, EnrollmentRequest{
				Server:     ca.Hostname,
				CAName:     ca.Name,
				Template:   tmpl.Template,
				CommonName: certificateCommonName(objectName, m.domain),
				KeyFile:    tmpl.KeyFile,
				CertFile:   tmpl.CertFile,
				KeySize:    keySize,
			}); err != nil {
				log.Warningf(ctx, "Failed to renew certificate %s: %v", tmpl.Nickname, err)
				report(progress, gotext.Get("Failed to renew %s: %v", tmpl.Nickname, err))
				failures = append(failures, fmt.Sprintf("%s: %v", tmpl.Nickname, err))
				continue
			}
			report(progress, gotext.Get("Renewed %s", tmpl.Nickname))
		}
	}

	if !all && !found {
		return errors.New(gotext.Get("certificate %q not found (valid nicknames: %s)", nickname, strings.Join(nicknamesOfState(state), ", ")))
	}

	if err := saveState(m.stateDir, state); err != nil {
		return fmt.Errorf("failed to save enrollment state: %w", err)
	}

	if len(failures) > 0 {
		return errors.New(gotext.Get("failed to renew %d certificate(s): %s", len(failures), strings.Join(failures, "; ")))
	}
	return nil
}

// RemoveCertificates removes enrolled certificates. force must be true or the
// call is refused. If all is true the machine is fully unenrolled; otherwise
// only the certificate matching nickname is removed, pruning its CA (and the
// root from the trust store) if it becomes empty.
func (m *Manager) RemoveCertificates(ctx context.Context, objectName, nickname string, all, force bool, progress func(string)) error {
	if m.enrollmentMethod != consts.CertEnrollmentLDAP {
		return ErrNotLDAPMethod
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if !force {
		return errors.New(gotext.Get("refusing to remove certificates without confirmation, pass force to proceed"))
	}

	if all {
		report(progress, gotext.Get("Removing all certificates for %s", objectName))
		if err := m.unenroll(ctx, objectName); err != nil {
			return err
		}
		report(progress, gotext.Get("Removed all certificates for %s", objectName))
		return nil
	}

	state, err := loadState(m.stateDir, objectName)
	if err != nil {
		return fmt.Errorf("failed to load enrollment state: %w", err)
	}
	if state == nil || len(state.CAs) == 0 {
		return errors.New(gotext.Get("no enrolled certificates found for %q", objectName))
	}

	found := false
	for ci := range state.CAs {
		ca := &state.CAs[ci]
		for ti, tmpl := range ca.Templates {
			if tmpl.Nickname != nickname {
				continue
			}
			found = true
			report(progress, gotext.Get("Removing certificate %s", nickname))
			log.Debugf(ctx, "Removing certificate files for %s", nickname)
			os.Remove(tmpl.CertFile)
			os.Remove(tmpl.KeyFile)
			ca.Templates = append(ca.Templates[:ti], ca.Templates[ti+1:]...)
			break
		}
		if !found {
			continue
		}
		if len(ca.Templates) == 0 {
			report(progress, gotext.Get("Removing root CA %s from the trust store", ca.Name))
			removeRootCACerts(ca.RootCerts, ca.Symlinks)
			state.CAs = append(state.CAs[:ci], state.CAs[ci+1:]...)
		}
		break
	}

	if !found {
		return errors.New(gotext.Get("certificate %q not found (valid nicknames: %s)", nickname, strings.Join(nicknamesOfState(state), ", ")))
	}

	if len(state.CAs) == 0 {
		if err := removeState(m.stateDir, objectName); err != nil {
			return fmt.Errorf("failed to remove enrollment state: %w", err)
		}
	} else if err := saveState(m.stateDir, state); err != nil {
		return fmt.Errorf("failed to save enrollment state: %w", err)
	}

	if err := updateCATrustStore(); err != nil {
		log.Warningf(ctx, "Failed to update CA trust store: %v", err)
	}
	report(progress, gotext.Get("Removed certificate %s", nickname))
	return nil
}

// VerifyCertificates verifies the enrolled certificates. If nickname is empty
// every certificate is verified, otherwise only the matching one. When online
// is true a best-effort CRL revocation check is attempted; revocation errors
// never fail the call.
func (m *Manager) VerifyCertificates(ctx context.Context, objectName, nickname string, online bool) ([]VerifyResult, error) {
	if m.enrollmentMethod != consts.CertEnrollmentLDAP {
		return nil, ErrNotLDAPMethod
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	state, err := loadState(m.stateDir, objectName)
	if err != nil {
		return nil, fmt.Errorf("failed to load enrollment state: %w", err)
	}
	if state == nil || len(state.CAs) == 0 {
		if nickname != "" {
			return nil, errors.New(gotext.Get("no enrolled certificates found for %q", objectName))
		}
		return []VerifyResult{}, nil
	}

	roots := rootPoolFromState(state)

	results := make([]VerifyResult, 0)
	found := false
	for _, ca := range state.CAs {
		for _, tmpl := range ca.Templates {
			if nickname != "" && tmpl.Nickname != nickname {
				continue
			}
			found = true
			results = append(results, verifyCertificate(ctx, tmpl, roots, online))
		}
	}

	if nickname != "" && !found {
		return nil, errors.New(gotext.Get("certificate %q not found (valid nicknames: %s)", nickname, strings.Join(nicknamesOfState(state), ", ")))
	}
	return results, nil
}

// DiscoverCAsInfo discovers the CAs and templates available in AD via LDAP and
// cross-references them against the local enrollment state.
func (m *Manager) DiscoverCAsInfo(ctx context.Context, objectName string) ([]CAInfo, error) {
	if m.enrollmentMethod != consts.CertEnrollmentLDAP {
		return nil, ErrNotLDAPMethod
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	cas, err := discoverCAsAndTemplates(m.ldapConnect, dcHostnameFromDomain(m.domain))
	if err != nil {
		return nil, fmt.Errorf("failed to discover certificate authorities: %w", err)
	}

	state, err := loadState(m.stateDir, objectName)
	if err != nil {
		log.Warningf(ctx, "Failed to load enrollment state for cross-reference: %v", err)
	}

	trustDir := filepath.Join(m.stateDir, "certs")
	infos := make([]CAInfo, 0, len(cas))
	for _, ca := range cas {
		info := CAInfo{
			Name:      ca.Name,
			Hostname:  ca.Hostname,
			Templates: ca.Templates,
		}
		if len(ca.CACertificate) > 0 {
			sum := sha256.Sum256(ca.CACertificate)
			info.RootFingerprints = []string{hex.EncodeToString(sum[:])}
		}
		info.InstalledInTrust = caInstalledInTrust(ca, state, trustDir, m.globalTrustDir)
		info.Enrolled = caEnrolled(ca.Name, state)
		infos = append(infos, info)
	}
	return infos, nil
}

// SupportedTemplates returns the certificate templates the given CA server is
// configured to issue, discovered via LDAP.
func (m *Manager) SupportedTemplates(ctx context.Context, server string) ([]string, error) {
	if m.enrollmentMethod != consts.CertEnrollmentLDAP {
		return nil, ErrNotLDAPMethod
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Debugf(ctx, "Discovering supported templates for server %s", server)
	connector := newKerberosLDAPConnector(m.krb5CacheDir, m.globalTrustDir, true)
	return GetSupportedTemplatesWithConnector(connector, server)
}

// certInfoFor builds a CertInfo from a persisted CA/template pair, parsing the
// on-disk certificate and deriving its health.
func certInfoFor(ca enrolledCA, tmpl enrolledTemplate, updatedAt time.Time) CertInfo {
	info := CertInfo{
		Nickname:      tmpl.Nickname,
		Template:      tmpl.Template,
		CAName:        ca.Name,
		CAHostname:    ca.Hostname,
		KeyFile:       tmpl.KeyFile,
		CertFile:      tmpl.CertFile,
		RootCertFiles: ca.RootCerts,
		TrustSymlinks: ca.Symlinks,
		LastEnrolled:  updatedAt,
	}
	info.OnDisk = filesExist(tmpl.KeyFile, tmpl.CertFile)

	cert := parseCertFile(tmpl.CertFile)
	if cert != nil {
		info.Subject = cert.Subject.String()
		info.Issuer = cert.Issuer.String()
		info.Serial = fmt.Sprintf("%x", cert.SerialNumber)
		info.NotBefore = cert.NotBefore
		info.NotAfter = cert.NotAfter
		info.DaysUntilExpiry = int(time.Until(cert.NotAfter).Hours() / 24)
		info.SANs = certSANs(cert)
		info.EKU = certEKU(cert)
		info.KeyAlgo = cert.PublicKeyAlgorithm.String()
		info.KeySize = publicKeySize(cert.PublicKey)

		if filesExist(tmpl.KeyFile) {
			if match, err := publicKeysMatch(cert, tmpl.KeyFile); err == nil {
				info.KeyMatchesCert = match
			}
		}
	}

	info.Health = deriveHealth(info, cert, time.Now())
	return info
}

// deriveHealth returns the health of a certificate following the documented
// precedence: missing, unparseable, key mismatch, expired, due for renewal,
// then healthy.
func deriveHealth(info CertInfo, cert *x509.Certificate, now time.Time) CertHealth {
	switch {
	case !info.OnDisk:
		return CertMissing
	case cert == nil:
		return CertUnparseable
	case !info.KeyMatchesCert:
		return CertKeyMismatch
	case now.After(cert.NotAfter):
		return CertExpired
	case now.Add(certRenewalWindow).After(cert.NotAfter):
		return CertDueRenewal
	default:
		return CertHealthy
	}
}

// verifyCertificate performs the chain, validity, key-match and (optionally)
// revocation checks for a single enrolled template.
func verifyCertificate(ctx context.Context, tmpl enrolledTemplate, roots *x509.CertPool, online bool) VerifyResult {
	res := VerifyResult{Nickname: tmpl.Nickname}

	cert := parseCertFile(tmpl.CertFile)
	if cert == nil {
		res.Messages = append(res.Messages, gotext.Get("certificate file is missing or unparseable: %s", tmpl.CertFile))
		return res
	}

	now := time.Now()
	res.ValidityOK = now.After(cert.NotBefore) && now.Before(cert.NotAfter)
	if !res.ValidityOK {
		res.Messages = append(res.Messages, gotext.Get("certificate is outside its validity window (%s - %s)", cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339)))
	}

	if match, err := publicKeysMatch(cert, tmpl.KeyFile); err != nil {
		res.Messages = append(res.Messages, gotext.Get("could not compare private key: %v", err))
	} else if match {
		res.KeyMatchOK = true
	} else {
		res.Messages = append(res.Messages, gotext.Get("private key does not match the certificate"))
	}

	// Accept any extended key usage: adsys-enrolled machine certificates
	// commonly carry client-auth (VPN, 802.1x) rather than server-auth, and
	// the goal here is to confirm the chain builds to a trusted root, not to
	// restrict the certificate to a particular usage.
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediatePool(tmpl.CertFile),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		res.Messages = append(res.Messages, gotext.Get("chain verification failed: %v", err))
	} else {
		res.ChainOK = true
	}

	if online {
		checkRevocation(ctx, cert, &res)
	}
	return res
}

// checkRevocation attempts a best-effort CRL revocation check against the
// certificate's first CRL distribution point. Any failure leaves
// RevocationChecked false and records a message; it never fails verification.
func checkRevocation(ctx context.Context, cert *x509.Certificate, res *VerifyResult) {
	if len(cert.CRLDistributionPoints) == 0 {
		res.Messages = append(res.Messages, gotext.Get("no CRL distribution point in certificate, skipping revocation check"))
		return
	}

	url := cert.CRLDistributionPoints[0]
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		res.Messages = append(res.Messages, gotext.Get("could not build CRL request for %s: %v", url, err))
		return
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		res.Messages = append(res.Messages, gotext.Get("could not fetch CRL from %s: %v", url, err))
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIssuedCertBytes))
	if err != nil {
		res.Messages = append(res.Messages, gotext.Get("could not read CRL from %s: %v", url, err))
		return
	}

	der := body
	if block, _ := pem.Decode(body); block != nil {
		der = block.Bytes
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		res.Messages = append(res.Messages, gotext.Get("could not parse CRL from %s: %v", url, err))
		return
	}

	res.RevocationChecked = true
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber != nil && entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			res.Revoked = true
			res.Messages = append(res.Messages, gotext.Get("certificate is listed as revoked"))
			return
		}
	}
}

// templateKeySize returns the minimum key size configured for a template,
// discovered best-effort via LDAP. Any failure falls back to 2048 bits.
func (m *Manager) templateKeySize(ctx context.Context, template string) int {
	const defaultKeySize = 2048

	conn, err := m.ldapConnect(dcHostnameFromDomain(m.domain))
	if err != nil || conn == nil {
		log.Debugf(ctx, "Could not connect to LDAP to determine key size for template %s, using %d bits", template, defaultKeySize)
		return defaultKeySize
	}
	defer conn.Close()

	configDN, err := fetchConfigDN(conn)
	if err != nil {
		return defaultKeySize
	}
	attrs, _ := fetchTemplateAttrs(conn, configDN, template)
	if attrs.MinKeySize > 0 {
		return attrs.MinKeySize
	}
	return defaultKeySize
}

// publicKeysMatch reports whether the certificate's public key matches the
// private key stored at keyPEMPath. It returns false (with an error) when the
// key is missing or unreadable, and false without error on a genuine mismatch.
func publicKeysMatch(cert *x509.Certificate, keyPEMPath string) (bool, error) {
	data, err := os.ReadFile(keyPEMPath)
	if err != nil {
		return false, fmt.Errorf("could not read private key %s: %w", keyPEMPath, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return false, fmt.Errorf("could not decode private key PEM in %s", keyPEMPath)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("could not parse private key %s: %w", keyPEMPath, err)
	}

	switch privKey := key.(type) {
	case *rsa.PrivateKey:
		certPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return false, nil
		}
		return certPubKey.N.Cmp(privKey.N) == 0 && certPubKey.E == privKey.E, nil
	case *ecdsa.PrivateKey:
		certPubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return false, nil
		}
		return certPubKey.X.Cmp(privKey.X) == 0 && certPubKey.Y.Cmp(privKey.Y) == 0, nil
	default:
		return false, fmt.Errorf("unsupported private key type: %T", key)
	}
}

// rootPoolFromState builds a certificate pool from the system trust store plus
// every root certificate referenced by the enrollment state.
func rootPoolFromState(state *enrollmentState) *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	for _, ca := range state.CAs {
		for _, rootFile := range ca.RootCerts {
			if data, err := os.ReadFile(rootFile); err == nil {
				pool.AppendCertsFromPEM(data)
			}
		}
	}
	return pool
}

// intermediatePool returns a pool built from any CERTIFICATE blocks in certFile
// after the first (leaf) one, treating them as intermediates.
func intermediatePool(certFile string) *x509.CertPool {
	pool := x509.NewCertPool()
	data, err := os.ReadFile(certFile)
	if err != nil {
		return pool
	}
	var seenLeaf bool
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if !seenLeaf {
			seenLeaf = true
			continue
		}
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			pool.AddCert(c)
		}
	}
	return pool
}

// caInstalledInTrust reports whether the discovered CA's root is trusted, either
// because the discovered certificate verifies against the trust store or
// because the enrollment state records installed root files for it.
func caInstalledInTrust(ca certAuthority, state *enrollmentState, trustDir, globalTrustDir string) bool {
	if len(ca.CACertificate) > 0 {
		if cert, err := x509.ParseCertificate(ca.CACertificate); err == nil {
			if verifyCACertificate(cert, trustDir, globalTrustDir) == nil {
				return true
			}
		}
	}
	if state != nil {
		for _, sca := range state.CAs {
			if sca.Name == ca.Name && len(sca.RootCerts) > 0 && filesExist(sca.RootCerts...) {
				return true
			}
		}
	}
	return false
}

// caEnrolled reports whether the state records at least one enrolled template
// with an on-disk certificate for the named CA.
func caEnrolled(name string, state *enrollmentState) bool {
	if state == nil {
		return false
	}
	for _, sca := range state.CAs {
		if sca.Name != name {
			continue
		}
		for _, tmpl := range sca.Templates {
			if filesExist(tmpl.CertFile) {
				return true
			}
		}
	}
	return false
}

// publicKeySize returns the key size in bits for supported public key types.
func publicKeySize(pub any) int {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	case *ecdsa.PublicKey:
		return key.Curve.Params().BitSize
	default:
		return 0
	}
}

// certSANs collects all subject alternative names from a certificate.
func certSANs(cert *x509.Certificate) []string {
	var sans []string
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, uri := range cert.URIs {
		sans = append(sans, uri.String())
	}
	sans = append(sans, cert.EmailAddresses...)
	return sans
}

// extKeyUsageNames maps the well-known extended key usages to their id-kp-*
// names (or dotted OID for the vendor-specific ones).
var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "anyExtendedKeyUsage",
	x509.ExtKeyUsageServerAuth:                     "id-kp-serverAuth",
	x509.ExtKeyUsageClientAuth:                     "id-kp-clientAuth",
	x509.ExtKeyUsageCodeSigning:                    "id-kp-codeSigning",
	x509.ExtKeyUsageEmailProtection:                "id-kp-emailProtection",
	x509.ExtKeyUsageIPSECEndSystem:                 "id-kp-ipsecEndSystem",
	x509.ExtKeyUsageIPSECTunnel:                    "id-kp-ipsecTunnel",
	x509.ExtKeyUsageIPSECUser:                      "id-kp-ipsecUser",
	x509.ExtKeyUsageTimeStamping:                   "id-kp-timeStamping",
	x509.ExtKeyUsageOCSPSigning:                    "id-kp-OCSPSigning",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "1.3.6.1.4.1.311.10.3.3",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "2.16.840.1.113730.4.1",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "1.3.6.1.4.1.311.2.1.22",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "1.3.6.1.4.1.311.61.1.1",
}

// certEKU returns the extended key usages of a certificate as id-kp-* names,
// with unrecognised usages rendered as their dotted OID.
func certEKU(cert *x509.Certificate) []string {
	var eku []string
	for _, u := range cert.ExtKeyUsage {
		if name, ok := extKeyUsageNames[u]; ok {
			eku = append(eku, name)
		} else {
			eku = append(eku, fmt.Sprintf("unknown-eku-%d", int(u)))
		}
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		eku = append(eku, oid.String())
	}
	return eku
}

// nicknamesOf returns the sorted nicknames of the given certificates.
func nicknamesOf(certs []CertInfo) []string {
	names := make([]string, 0, len(certs))
	for _, c := range certs {
		names = append(names, c.Nickname)
	}
	sort.Strings(names)
	return names
}

// nicknamesOfState returns the sorted nicknames recorded in the enrollment state.
func nicknamesOfState(state *enrollmentState) []string {
	var names []string
	for _, ca := range state.CAs {
		for _, tmpl := range ca.Templates {
			names = append(names, tmpl.Nickname)
		}
	}
	sort.Strings(names)
	return names
}

// report calls progress with msg when a progress callback was provided.
func report(progress func(string), msg string) {
	if progress != nil {
		progress(msg)
	}
}

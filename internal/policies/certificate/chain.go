package certificate

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// expectedCertificateChain is ordered from the active enterprise issuing CA
// to its self-signed directory trust anchor. Keeping one exact path prevents
// verification from drifting to an older renewed CA with the same subject.
type expectedCertificateChain struct {
	Certificates []*x509.Certificate
	Fingerprints []string
}

func (c *expectedCertificateChain) issuer() *x509.Certificate {
	if c == nil || len(c.Certificates) == 0 {
		return nil
	}
	return c.Certificates[0]
}

func (c *expectedCertificateChain) root() *x509.Certificate {
	if c == nil || len(c.Certificates) == 0 {
		return nil
	}
	return c.Certificates[len(c.Certificates)-1]
}

func (c *expectedCertificateChain) issuerFingerprint() string {
	if c == nil || len(c.Fingerprints) == 0 {
		return ""
	}
	return c.Fingerprints[0]
}

func certificateFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func rawCertificateFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// resolveCAChains parses and deduplicates every certificate obtained from the
// Enrollment Services, Certification Authorities and AIA containers, then
// deterministically selects a currently usable issuing certificate for each
// enrollment service. Renewal values are ordered by newest NotBefore, newest
// NotAfter, then ascending SHA-256 fingerprint.
func resolveCAChains(cas []certAuthority, directoryCertificates [][]byte, now time.Time) ([]certAuthority, error) {
	allByFingerprint := make(map[string]*x509.Certificate)
	addCertificate := func(der []byte, source string) (*x509.Certificate, error) {
		if len(der) == 0 {
			return nil, fmt.Errorf("%s contains an empty cACertificate value", source)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%s contains an invalid cACertificate value: %w", source, err)
		}
		if err := validateCACapabilities(cert); err != nil {
			return nil, fmt.Errorf("%s contains an unusable CA certificate: %w", source, err)
		}
		fp := certificateFingerprint(cert)
		if existing, ok := allByFingerprint[fp]; ok {
			return existing, nil
		}
		allByFingerprint[fp] = cert
		return cert, nil
	}

	for i, der := range directoryCertificates {
		if _, err := addCertificate(der, fmt.Sprintf("directory CA store value %d", i)); err != nil {
			return nil, err
		}
	}

	type authorityCandidates struct {
		authority  certAuthority
		candidates []*x509.Certificate
	}
	authorities := make([]authorityCandidates, 0, len(cas))
	for _, ca := range cas {
		if len(ca.CACertificates) == 0 {
			return nil, fmt.Errorf("enrollment service %q has no cACertificate values", ca.Name)
		}
		entry := authorityCandidates{authority: ca}
		seen := make(map[string]struct{})
		for valueIndex, der := range ca.CACertificates {
			cert, err := addCertificate(der, fmt.Sprintf("enrollment service %q value %d", ca.Name, valueIndex))
			if err != nil {
				return nil, err
			}
			fp := certificateFingerprint(cert)
			if _, ok := seen[fp]; ok {
				continue
			}
			seen[fp] = struct{}{}
			entry.candidates = append(entry.candidates, cert)
		}
		authorities = append(authorities, entry)
	}

	all := make([]*x509.Certificate, 0, len(allByFingerprint))
	for _, cert := range allByFingerprint {
		all = append(all, cert)
	}
	sortCertificatesForRenewal(all)

	resolved := make([]certAuthority, 0, len(authorities))
	for _, entry := range authorities {
		ca := entry.authority
		candidates := entry.candidates
		sortCertificatesForRenewal(candidates)

		var selected []*x509.Certificate
		var candidateErrors []string
		for _, candidate := range candidates {
			if err := validateCATime(candidate, now); err != nil {
				candidateErrors = append(candidateErrors, fmt.Sprintf("%s: %v", certificateFingerprint(candidate), err))
				continue
			}
			path, err := buildDirectoryCAPath(candidate, all, now, map[string]bool{})
			if err != nil {
				candidateErrors = append(candidateErrors, fmt.Sprintf("%s: %v", certificateFingerprint(candidate), err))
				continue
			}
			selected = path
			break
		}
		if len(selected) == 0 {
			return nil, fmt.Errorf("enrollment service %q has no currently usable issuing CA certificate (%s)", ca.Name, strings.Join(candidateErrors, "; "))
		}

		fingerprints := make([]string, 0, len(selected))
		for _, cert := range selected {
			fingerprints = append(fingerprints, certificateFingerprint(cert))
		}
		ca.CACertificate = append([]byte(nil), selected[0].Raw...)
		ca.Chain = &expectedCertificateChain{
			Certificates: selected,
			Fingerprints: fingerprints,
		}
		resolved = append(resolved, ca)
	}

	return resolved, nil
}

func validateCACapabilities(cert *x509.Certificate) error {
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return fmt.Errorf("BasicConstraints does not identify a CA")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("KeyUsage does not permit certificate signing")
	}
	return nil
}

func validateCATime(cert *x509.Certificate, now time.Time) error {
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("not valid before %s", cert.NotBefore.Format(time.RFC3339))
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("expired at %s", cert.NotAfter.Format(time.RFC3339))
	}
	return nil
}

func sortCertificatesForRenewal(certs []*x509.Certificate) {
	sort.SliceStable(certs, func(i, j int) bool {
		if !certs[i].NotBefore.Equal(certs[j].NotBefore) {
			return certs[i].NotBefore.After(certs[j].NotBefore)
		}
		if !certs[i].NotAfter.Equal(certs[j].NotAfter) {
			return certs[i].NotAfter.After(certs[j].NotAfter)
		}
		return certificateFingerprint(certs[i]) < certificateFingerprint(certs[j])
	})
}

func buildDirectoryCAPath(cert *x509.Certificate, all []*x509.Certificate, now time.Time, visiting map[string]bool) ([]*x509.Certificate, error) {
	fp := certificateFingerprint(cert)
	if visiting[fp] {
		return nil, fmt.Errorf("certificate chain contains a cycle")
	}
	if err := validateCACapabilities(cert); err != nil {
		return nil, err
	}
	if err := validateCATime(cert, now); err != nil {
		return nil, err
	}

	if bytes.Equal(cert.RawSubject, cert.RawIssuer) && cert.CheckSignatureFrom(cert) == nil {
		path := []*x509.Certificate{cert}
		if err := verifyExactCAPath(path, now); err != nil {
			return nil, err
		}
		return path, nil
	}

	parents := make([]*x509.Certificate, 0)
	for _, candidate := range all {
		if certificateFingerprint(candidate) == fp || !bytes.Equal(candidate.RawSubject, cert.RawIssuer) {
			continue
		}
		if cert.CheckSignatureFrom(candidate) == nil {
			parents = append(parents, candidate)
		}
	}
	sortCertificatesForRenewal(parents)
	if len(parents) == 0 {
		return nil, fmt.Errorf("does not chain to a discovered self-signed trust anchor")
	}

	visiting[fp] = true
	defer delete(visiting, fp)
	var pathErrors []string
	for _, parent := range parents {
		parentPath, err := buildDirectoryCAPath(parent, all, now, visiting)
		if err != nil {
			pathErrors = append(pathErrors, err.Error())
			continue
		}
		path := append([]*x509.Certificate{cert}, parentPath...)
		if err := verifyExactCAPath(path, now); err != nil {
			pathErrors = append(pathErrors, err.Error())
			continue
		}
		return path, nil
	}
	return nil, fmt.Errorf("does not have a valid directory chain: %s", strings.Join(pathErrors, "; "))
}

func verifyExactCAPath(path []*x509.Certificate, now time.Time) error {
	if len(path) == 0 {
		return fmt.Errorf("empty CA chain")
	}
	for _, cert := range path {
		if err := validateCACapabilities(cert); err != nil {
			return err
		}
		if err := validateCATime(cert, now); err != nil {
			return err
		}
	}
	for i := 0; i+1 < len(path); i++ {
		if err := path[i].CheckSignatureFrom(path[i+1]); err != nil {
			return fmt.Errorf("CA chain certificate %d is not signed by certificate %d: %w", i, i+1, err)
		}
	}
	root := path[len(path)-1]
	if !bytes.Equal(root.RawSubject, root.RawIssuer) || root.CheckSignatureFrom(root) != nil {
		return fmt.Errorf("chain does not end at a self-signed trust anchor")
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	if len(path) > 2 {
		for _, cert := range path[1 : len(path)-1] {
			intermediates.AddCert(cert)
		}
	}
	if _, err := path[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("CA path verification failed: %w", err)
	}
	return nil
}

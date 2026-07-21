package certificate

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
)

type templateChainBinding struct {
	IssuerFingerprint  string
	Fingerprints       []string
	Files              []string
	TrustAnchorSymlink string
}

func chainBindingFromInstallation(chain *expectedCertificateChain, installation *caChainInstallation) (templateChainBinding, error) {
	if chain == nil || installation == nil {
		return templateChainBinding{}, fmt.Errorf("certificate chain installation is missing")
	}
	if len(chain.Certificates) == 0 || len(chain.Fingerprints) != len(chain.Certificates) {
		return templateChainBinding{}, fmt.Errorf("certificate chain fingerprints are incomplete")
	}
	if len(installation.ChainFiles) != len(chain.Certificates) || len(installation.SymlinkFiles) != 1 {
		return templateChainBinding{}, fmt.Errorf("installed certificate chain paths are incomplete")
	}
	return templateChainBinding{
		IssuerFingerprint:  chain.Fingerprints[0],
		Fingerprints:       append([]string(nil), chain.Fingerprints...),
		Files:              append([]string(nil), installation.ChainFiles...),
		TrustAnchorSymlink: installation.SymlinkFiles[0],
	}, nil
}

func templateHasChainBinding(tmpl enrolledTemplate) bool {
	return tmpl.IssuerFingerprint != "" ||
		len(tmpl.ChainFingerprints) != 0 ||
		len(tmpl.ChainFiles) != 0 ||
		tmpl.TrustAnchorSymlink != ""
}

func bindTemplateToChain(tmpl *enrolledTemplate, binding templateChainBinding) {
	tmpl.IssuerFingerprint = binding.IssuerFingerprint
	tmpl.ChainFingerprints = append([]string(nil), binding.Fingerprints...)
	tmpl.ChainFiles = append([]string(nil), binding.Files...)
	tmpl.TrustAnchorSymlink = binding.TrustAnchorSymlink
}

func templateBinding(ca enrolledCA, tmpl enrolledTemplate) (templateChainBinding, bool, error) {
	if templateHasChainBinding(tmpl) {
		binding := templateChainBinding{
			IssuerFingerprint:  tmpl.IssuerFingerprint,
			Fingerprints:       append([]string(nil), tmpl.ChainFingerprints...),
			Files:              append([]string(nil), tmpl.ChainFiles...),
			TrustAnchorSymlink: tmpl.TrustAnchorSymlink,
		}
		if err := validateBindingShape(binding); err != nil {
			return templateChainBinding{}, false, fmt.Errorf("template %s chain binding is incomplete: %w", tmpl.Nickname, err)
		}
		return binding, false, nil
	}

	binding, err := legacyCABinding(ca)
	if err != nil {
		return templateChainBinding{}, true, fmt.Errorf("template %s has no usable legacy CA chain binding: %w", tmpl.Nickname, err)
	}
	return binding, true, nil
}

func validateBindingShape(binding templateChainBinding) error {
	if binding.IssuerFingerprint == "" {
		return fmt.Errorf("issuer fingerprint is missing")
	}
	if len(binding.Fingerprints) == 0 {
		return fmt.Errorf("chain fingerprints are missing")
	}
	if len(binding.Files) != len(binding.Fingerprints) {
		return fmt.Errorf("chain has %d fingerprints and %d files", len(binding.Fingerprints), len(binding.Files))
	}
	if !strings.EqualFold(binding.IssuerFingerprint, binding.Fingerprints[0]) {
		return fmt.Errorf("issuer fingerprint does not match the first chain certificate")
	}
	for i := range binding.Fingerprints {
		if binding.Fingerprints[i] == "" || binding.Files[i] == "" {
			return fmt.Errorf("chain entry %d is incomplete", i)
		}
	}
	return nil
}

func legacyCABinding(ca enrolledCA) (templateChainBinding, error) {
	candidateFiles := uniqueStrings(append(append([]string(nil), ca.IntermediateCerts...), ca.RootCerts...))
	if len(candidateFiles) == 0 {
		return templateChainBinding{}, fmt.Errorf("CA certificate files are missing")
	}

	certsByFingerprint := make(map[string][]string)
	for _, path := range candidateFiles {
		cert, err := readSingleCertificateFile(path)
		if err != nil {
			return templateChainBinding{}, fmt.Errorf("reading legacy CA certificate %s: %w", path, err)
		}
		fp := certificateFingerprint(cert)
		certsByFingerprint[strings.ToLower(fp)] = append(certsByFingerprint[strings.ToLower(fp)], path)
	}
	for fp := range certsByFingerprint {
		sort.Strings(certsByFingerprint[fp])
	}

	fingerprints := append([]string(nil), ca.ChainFingerprints...)
	files := make([]string, 0, len(fingerprints))
	if len(fingerprints) != 0 {
		for _, fp := range fingerprints {
			paths := certsByFingerprint[strings.ToLower(fp)]
			if len(paths) == 0 {
				return templateChainBinding{}, fmt.Errorf("CA chain certificate %s has no persisted file", fp)
			}
			files = append(files, paths[0])
		}
	} else {
		files = append(files, ca.IntermediateCerts...)
		files = append(files, ca.RootCerts...)
		fingerprints = make([]string, 0, len(files))
		for _, path := range files {
			cert, err := readSingleCertificateFile(path)
			if err != nil {
				return templateChainBinding{}, err
			}
			fingerprints = append(fingerprints, certificateFingerprint(cert))
		}
	}

	issuerFingerprint := ca.IssuerFingerprint
	if issuerFingerprint == "" && len(fingerprints) != 0 {
		issuerFingerprint = fingerprints[0]
	}
	binding := templateChainBinding{
		IssuerFingerprint: issuerFingerprint,
		Fingerprints:      fingerprints,
		Files:             files,
	}
	if len(files) != 0 {
		binding.TrustAnchorSymlink = matchingTrustSymlink(ca.Symlinks, files[len(files)-1])
	}
	if err := validateBindingShape(binding); err != nil {
		return templateChainBinding{}, err
	}
	return binding, nil
}

func matchingTrustSymlink(symlinks []string, rootFile string) string {
	rootAbs, err := filepath.Abs(rootFile)
	if err != nil {
		return ""
	}
	for _, path := range symlinks {
		target, err := os.Readlink(path)
		if err != nil {
			continue
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(path), target)
		}
		targetAbs, err := filepath.Abs(target)
		if err == nil && filepath.Clean(targetAbs) == filepath.Clean(rootAbs) {
			return path
		}
	}
	return ""
}

func loadTemplateChain(ca enrolledCA, tmpl enrolledTemplate, now time.Time) (templateChainBinding, []*x509.Certificate, bool, error) {
	binding, legacy, err := templateBinding(ca, tmpl)
	if err != nil {
		return templateChainBinding{}, nil, legacy, err
	}
	certificates := make([]*x509.Certificate, 0, len(binding.Files))
	for i, path := range binding.Files {
		cert, err := readSingleCertificateFile(path)
		if err != nil {
			return templateChainBinding{}, nil, legacy, fmt.Errorf("chain file %d (%s): %w", i, path, err)
		}
		got := certificateFingerprint(cert)
		if !strings.EqualFold(got, binding.Fingerprints[i]) {
			return templateChainBinding{}, nil, legacy, fmt.Errorf("chain file %d (%s) fingerprint %s does not match persisted fingerprint %s", i, path, got, binding.Fingerprints[i])
		}
		certificates = append(certificates, cert)
	}
	if !strings.EqualFold(certificateFingerprint(certificates[0]), binding.IssuerFingerprint) {
		return templateChainBinding{}, nil, legacy, fmt.Errorf("persisted issuer fingerprint does not match the first chain certificate")
	}
	if err := verifyExactCAPath(certificates, now); err != nil {
		return templateChainBinding{}, nil, legacy, fmt.Errorf("persisted exact CA chain is invalid: %w", err)
	}
	return binding, certificates, legacy, nil
}

func readSingleCertificateFile(path string) (*x509.Certificate, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular certificate file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("does not contain a PEM certificate")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("contains unexpected data after the certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}
	return cert, nil
}

func validatePersistedTemplate(ca enrolledCA, tmpl enrolledTemplate, identity string, now time.Time) (enrolledTemplate, error) {
	binding, chain, _, err := loadTemplateChain(ca, tmpl, now)
	if err != nil {
		return enrolledTemplate{}, err
	}
	certPEM, err := os.ReadFile(tmpl.CertFile)
	if err != nil {
		return enrolledTemplate{}, fmt.Errorf("reading existing certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(tmpl.KeyFile)
	if err != nil {
		return enrolledTemplate{}, fmt.Errorf("reading existing private key: %w", err)
	}
	cert, err := verifyIssuedCertificate(string(certPEM), keyPEM, identity, chain, now)
	if err != nil {
		return enrolledTemplate{}, err
	}
	leafFingerprint := certificateFingerprint(cert)
	if tmpl.LeafFingerprint != "" && !strings.EqualFold(tmpl.LeafFingerprint, leafFingerprint) {
		return enrolledTemplate{}, fmt.Errorf("state leaf fingerprint %s does not match certificate %s", tmpl.LeafFingerprint, leafFingerprint)
	}
	tmpl.LeafFingerprint = leafFingerprint
	bindTemplateToChain(&tmpl, binding)
	return tmpl, nil
}

func rebuildCAArtifacts(ca *enrolledCA) error {
	oldSymlinks := append([]string(nil), ca.Symlinks...)
	rootSet := make(map[string]struct{})
	intermediateSet := make(map[string]struct{})
	symlinkSet := make(map[string]struct{})
	preserveOldSymlinks := false
	var commonFingerprints []string
	var commonIssuer string
	for i, tmpl := range ca.Templates {
		binding, legacy, err := templateBinding(*ca, tmpl)
		if err != nil {
			return err
		}
		if legacy {
			bindTemplateToChain(&ca.Templates[i], binding)
		}
		for j, path := range binding.Files {
			if j == len(binding.Files)-1 {
				rootSet[path] = struct{}{}
			} else {
				intermediateSet[path] = struct{}{}
			}
		}
		if binding.TrustAnchorSymlink != "" {
			symlinkSet[binding.TrustAnchorSymlink] = struct{}{}
		} else {
			preserveOldSymlinks = true
		}
		if i == 0 {
			commonIssuer = binding.IssuerFingerprint
			commonFingerprints = append([]string(nil), binding.Fingerprints...)
		} else if !equalFoldStrings(commonFingerprints, binding.Fingerprints) {
			commonIssuer = ""
			commonFingerprints = nil
		}
	}
	if preserveOldSymlinks {
		for _, path := range oldSymlinks {
			symlinkSet[path] = struct{}{}
		}
	}
	ca.RootCerts = sortedSet(rootSet)
	ca.IntermediateCerts = sortedSet(intermediateSet)
	ca.Symlinks = sortedSet(symlinkSet)
	ca.IssuerFingerprint = commonIssuer
	ca.ChainFingerprints = commonFingerprints
	return nil
}

func equalFoldStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !strings.EqualFold(a[i], b[i]) {
			return false
		}
	}
	return true
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func sortedSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func stateReferencedPaths(state *enrollmentState) map[string]struct{} {
	paths := make(map[string]struct{})
	if state == nil {
		return paths
	}
	for _, ca := range state.CAs {
		for _, path := range append(append(append([]string(nil), ca.RootCerts...), ca.IntermediateCerts...), ca.Symlinks...) {
			if path != "" {
				paths[path] = struct{}{}
			}
		}
		for _, tmpl := range ca.Templates {
			for _, path := range append([]string{tmpl.KeyFile, tmpl.CertFile, tmpl.TrustAnchorSymlink}, tmpl.ChainFiles...) {
				if path != "" {
					paths[path] = struct{}{}
				}
			}
		}
	}
	return paths
}

func removeUnreferencedPaths(ctx context.Context, stateDir, objectName string, replacement *enrollmentState, candidates ...[]string) error {
	referenced := stateReferencedPaths(replacement)
	stateFiles, err := filepath.Glob(filepath.Join(stateDir, "certs", "state_*.json"))
	if err != nil {
		return fmt.Errorf("listing enrollment state files: %w", err)
	}
	excluded := stateFilePath(stateDir, objectName)
	for _, path := range stateFiles {
		if path == excluded {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading enrollment state %s before cleanup: %w", path, err)
		}
		var state enrollmentState
		if err := json.Unmarshal(data, &state); err != nil {
			return fmt.Errorf("parsing enrollment state %s before cleanup: %w", path, err)
		}
		for referencedPath := range stateReferencedPaths(&state) {
			referenced[referencedPath] = struct{}{}
		}
	}

	for _, path := range uniqueStrings(flattenStrings(candidates...)) {
		if _, keep := referenced[path]; keep {
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("removing unreferenced enrollment path %s: %w", path, err)
		}
		log.Debugf(ctx, "Removed unreferenced enrollment path: %s", path)
	}
	return nil
}

func flattenStrings(groups ...[]string) []string {
	var values []string
	for _, group := range groups {
		values = append(values, group...)
	}
	return values
}

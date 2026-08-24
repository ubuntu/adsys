package certificate

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
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
	keyPath, certPath, err := templateGenerationReadPaths(tmpl)
	if err != nil {
		return enrolledTemplate{}, fmt.Errorf("validating certificate generation: %w", err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return enrolledTemplate{}, fmt.Errorf("reading existing certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
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
			templatePaths := []string{
				tmpl.KeyFile,
				tmpl.CertFile,
				tmpl.GenerationRoot,
				tmpl.GenerationPointer,
				tmpl.GenerationDir,
				tmpl.TrustAnchorSymlink,
			}
			templatePaths = append(templatePaths, generationArtifactPaths(tmpl)...)
			templatePaths = append(templatePaths, tmpl.ChainFiles...)
			for _, path := range templatePaths {
				if path != "" {
					paths[path] = struct{}{}
				}
			}
		}
	}
	for _, pending := range state.Pending {
		for _, path := range pendingReferencedPaths(pending) {
			if path != "" {
				paths[path] = struct{}{}
			}
		}
	}
	return paths
}

func removeUnreferencedPaths(ctx context.Context, stateDir, globalTrustDir, objectName, domain string, replacement *enrollmentState, candidates ...[]string) error {
	stateFileMu.Lock()
	defer stateFileMu.Unlock()

	referenced := stateReferencedPaths(replacement)
	stateFiles, err := filepath.Glob(filepath.Join(stateDir, "certs", "state_*.json"))
	if err != nil {
		return fmt.Errorf("listing enrollment state files: %w", err)
	}

	type enumeratedState struct {
		state     *enrollmentState
		canonical bool
	}
	states := make(map[string]enumeratedState)
	for _, path := range stateFiles {
		state, _, err := readStateFile(path)
		if err != nil {
			return fmt.Errorf("reading enrollment state %s before cleanup: %w", path, err)
		}
		if err := validateEnumeratedState(state); err != nil {
			return fmt.Errorf("validating enrollment state %s before cleanup: %w", path, err)
		}
		if err := validateStateArtifactOwnership(stateDir, globalTrustDir, state); err != nil {
			return fmt.Errorf("validating enrollment artifact ownership in %s before cleanup: %w", path, err)
		}
		canonical := isCanonicalStatePath(stateDir, path, state)
		if !canonical && !isLegacyStatePath(stateDir, path, state) {
			return fmt.Errorf("enrollment state %s does not match its embedded object name %q", path, state.ObjectName)
		}
		key := stateOwnerKey(state)
		current, found := states[key]
		if !found || canonical && !current.canonical {
			states[key] = enumeratedState{state: state, canonical: canonical}
		}
	}

	requestedDomain := normalizeDomainIdentity(domain)
	for _, entry := range states {
		state := entry.state
		if state.ObjectName == objectName && normalizeDomainIdentity(state.Domain) == requestedDomain {
			continue
		}
		for referencedPath := range stateReferencedPaths(state) {
			referenced[referencedPath] = struct{}{}
		}
	}

	var cleanupErrs []error
	for _, path := range uniqueStrings(flattenStrings(candidates...)) {
		if _, keep := referenced[path]; keep {
			continue
		}
		if err := removeOwnedEnrollmentPath(stateDir, globalTrustDir, path); err != nil && !os.IsNotExist(err) {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("removing unreferenced enrollment path %s: %w", path, err))
			continue
		}
		log.Debugf(ctx, "Removed unreferenced enrollment path: %s", path)
	}
	return errors.Join(cleanupErrs...)
}

func removeOwnedEnrollmentPath(stateDir, globalTrustDir, path string) error {
	if path == "" {
		return nil
	}
	privateRoot, err := filepath.Abs(filepath.Join(stateDir, "private"))
	if err != nil {
		return err
	}
	certRoot, err := filepath.Abs(filepath.Join(stateDir, "certs"))
	if err != nil {
		return err
	}
	trustRoot, err := filepath.Abs(globalTrustDir)
	if err != nil {
		return err
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	switch {
	case pathWithin(privateRoot, pathAbs) && filepath.Clean(pathAbs) != filepath.Clean(privateRoot):
		info, exists, err := inspectOwnedPath(privateRoot, pathAbs)
		if err != nil {
			return err
		}
		if exists && info.Mode()&os.ModeSymlink != 0 {
			if err := validateGenerationPointerSymlink(pathAbs); err != nil {
				return err
			}
		} else if exists && !info.Mode().IsRegular() && !info.IsDir() {
			return fmt.Errorf("refusing to remove unsupported private-state file type")
		}
	case pathWithin(certRoot, pathAbs) && filepath.Clean(pathAbs) != filepath.Clean(certRoot):
		info, exists, err := inspectOwnedPath(certRoot, pathAbs)
		if err != nil {
			return err
		}
		if exists && !info.Mode().IsRegular() {
			return fmt.Errorf("refusing to remove non-regular certificate-state path %s", path)
		}
	case globalTrustDir != "" && pathWithin(trustRoot, pathAbs) && filepath.Clean(pathAbs) != filepath.Clean(trustRoot):
		if err := validateTrustSymlink(trustRoot, certRoot, pathAbs); err != nil {
			return err
		}
	default:
		return fmt.Errorf("refusing to remove path outside ADSys-owned enrollment roots: %s", path)
	}
	if err := os.Remove(pathAbs); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if _, statErr := os.Lstat(filepath.Dir(pathAbs)); statErr != nil {
			if os.IsNotExist(statErr) {
				return nil
			}
			return statErr
		}
	}
	if err := syncDirectory(filepath.Dir(pathAbs)); err != nil {
		return fmt.Errorf("syncing parent after removing %s: %w", pathAbs, err)
	}
	return nil
}

func inspectOwnedPath(root, path string) (os.FileInfo, bool, error) {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	if !pathWithin(root, path) || path == root {
		return nil, false, fmt.Errorf("%s is outside owned root %s", path, root)
	}
	if err := validateExistingDirectoryPrefix(root); err != nil {
		return nil, false, err
	}
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return nil, false, err
	}
	current := root
	components := strings.Split(relative, string(filepath.Separator))
	for index, component := range components {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		if index != len(components)-1 {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return nil, false, fmt.Errorf("owned path component %s is not a regular directory", current)
			}
			continue
		}
		return info, true, nil
	}
	return nil, false, nil
}

func validateExistingDirectoryPrefix(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	volume := filepath.VolumeName(absolute)
	current := volume + string(filepath.Separator)
	relative := strings.TrimPrefix(absolute, current)
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("owned root component %s is not a regular directory", current)
		}
	}
	return nil
}

func validateGenerationPointerSymlink(path string) error {
	if filepath.Base(path) != "current" {
		return fmt.Errorf("refusing to remove unexpected private-state symlink %s", path)
	}
	root := filepath.Dir(path)
	generations := filepath.Join(root, "generations")
	info, exists, err := inspectOwnedPath(root, generations)
	if err != nil {
		return err
	}
	if !exists || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("generation pointer %s has no regular generations directory", path)
	}
	target, err := os.Readlink(path)
	if err != nil {
		return err
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(root, target)
	}
	target, err = filepath.Abs(target)
	if err != nil {
		return err
	}
	if !pathWithin(generations, target) || filepath.Clean(target) == filepath.Clean(generations) {
		return fmt.Errorf("generation pointer %s targets a path outside its owned generations", path)
	}
	_, _, err = inspectOwnedPath(generations, target)
	return err
}

func validateTrustSymlink(trustRoot, certRoot, path string) error {
	info, exists, err := inspectOwnedPath(trustRoot, path)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("trust artifact %s is not an ADSys-owned symlink", path)
	}
	target, err := os.Readlink(path)
	if err != nil {
		return err
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(path), target)
	}
	target, err = filepath.Abs(target)
	if err != nil {
		return err
	}
	if !pathWithin(certRoot, target) || filepath.Clean(target) == filepath.Clean(certRoot) {
		return fmt.Errorf("trust symlink %s targets a path outside ADSys certificate state", path)
	}
	targetInfo, targetExists, err := inspectOwnedPath(certRoot, target)
	if err != nil {
		return err
	}
	if targetExists && !targetInfo.Mode().IsRegular() {
		return fmt.Errorf("trust symlink %s does not target a regular certificate", path)
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

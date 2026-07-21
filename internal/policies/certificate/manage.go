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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
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
	trustLifecycleMu.RLock()
	defer trustLifecycleMu.RUnlock()

	return m.listCertificatesLocked(ctx, objectName)
}

// listCertificatesLocked builds the CertInfo slice for objectName. The caller
// must hold m.mu.
func (m *Manager) listCertificatesLocked(ctx context.Context, objectName string) ([]CertInfo, error) {
	state, err := loadState(m.stateDir, objectName, m.domain)
	if err != nil {
		return nil, fmt.Errorf("failed to load enrollment state: %w", err)
	}
	if state == nil {
		log.Debugf(ctx, "No enrollment state for %s, no certificates to list", objectName)
		return []CertInfo{}, nil
	}

	return certInfosForState(state), nil
}

func certInfosForState(state *enrollmentState) []CertInfo {
	infos := make([]CertInfo, 0)
	for _, ca := range state.CAs {
		for _, tmpl := range ca.Templates {
			infos = append(infos, certInfoFor(ca, tmpl, state.UpdatedAt))
		}
	}
	return infos
}

// CertificateStatus returns the CertInfo for a single enrolled certificate. If
// nickname is empty and exactly one certificate is enrolled, that certificate
// is returned; if several are enrolled the returned error lists their
// nicknames.
func (m *Manager) CertificateStatus(_ context.Context, objectName, nickname string) (CertInfo, error) {
	if m.enrollmentMethod != consts.CertEnrollmentLDAP {
		return CertInfo{}, ErrNotLDAPMethod
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	trustLifecycleMu.RLock()
	defer trustLifecycleMu.RUnlock()

	state, err := loadState(m.stateDir, objectName, m.domain)
	if err != nil {
		return CertInfo{}, err
	}
	if state == nil {
		return CertInfo{}, errors.New(gotext.Get("no enrolled certificates found for %q", objectName))
	}
	certs := certInfosForState(state)
	if len(certs) == 0 {
		return CertInfo{}, errors.New(gotext.Get("no enrolled certificates found for %q", objectName))
	}

	if nickname == "" {
		if len(certs) == 1 {
			return certs[0], nil
		}
		return CertInfo{}, errors.New(gotext.Get("multiple certificates enrolled, specify a nickname (one of: %s)", strings.Join(nicknamesOf(certs), ", ")))
	}

	target, err := resolveNickname(state, nickname)
	if err != nil {
		return CertInfo{}, err
	}
	return certInfoFor(state.CAs[target.ca], state.CAs[target.ca].Templates[target.template], state.UpdatedAt), nil
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
	trustLifecycleMu.Lock()
	defer trustLifecycleMu.Unlock()

	state, err := loadState(m.stateDir, objectName, m.domain)
	if err != nil {
		return fmt.Errorf("failed to load enrollment state: %w", err)
	}
	if state == nil || len(state.CAs) == 0 && len(state.Pending) == 0 {
		return errors.New(gotext.Get("no enrolled certificates found for %q", objectName))
	}
	if !all && nickname == "" {
		return errors.New(gotext.Get("a certificate nickname is required unless renewing all certificates"))
	}

	polledTargets := make(map[string]struct{})
	var selectedPending bool
	var requestedCA, requestedServer, requestedTemplate string
	var target templateStateRef
	if !all {
		if pending, ok := pendingByNickname(state, nickname); ok {
			selectedPending = true
			requestedCA, requestedServer, requestedTemplate = pending.CAName, pending.Server, pending.Template
		} else {
			target, err = resolveNickname(state, nickname)
			if err != nil {
				return err
			}
			requestedCA = state.CAs[target.ca].Name
			requestedServer = state.CAs[target.ca].Hostname
			requestedTemplate = state.CAs[target.ca].Templates[target.template].Template
		}
	}
	pollSelector := func(pending pendingEnrollment) bool {
		if all {
			polledTargets[pendingTargetKey(pending.CAName, pending.Server, pending.Template)] = struct{}{}
			return true
		}
		selected := strings.EqualFold(pending.CAName, requestedCA) &&
			strings.EqualFold(pending.Server, requestedServer) &&
			strings.EqualFold(pending.Template, requestedTemplate)
		if selected {
			selectedPending = true
			polledTargets[pendingTargetKey(pending.CAName, pending.Server, pending.Template)] = struct{}{}
		}
		return selected
	}
	pollSummary := m.pollPendingEnrollments(ctx, state, pollSelector, progress)
	if !all && selectedPending {
		if _, stillPending := pendingForTarget(state, requestedCA, requestedServer, requestedTemplate); stillPending {
			return errors.Join(append(pollSummary.Errors, ErrEnrollmentPending)...)
		}
		return errors.Join(pollSummary.Errors...)
	}
	if len(state.CAs) == 0 {
		if len(state.Pending) != 0 {
			return errors.Join(append(pollSummary.Errors, ErrEnrollmentPending)...)
		}
		return errors.Join(pollSummary.Errors...)
	}
	if !all {
		target, err = resolveNickname(state, nickname)
		if err != nil {
			return errors.Join(append(pollSummary.Errors, err)...)
		}
	}
	for _, dir := range []string{filepath.Join(m.stateDir, "certs"), m.globalTrustDir} {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("creating CA trust directory %s: %w", dir, err)
		}
	}

	identity, err := enrollmentMachineIdentity(objectName, m.domain)
	if err != nil {
		return fmt.Errorf("could not determine machine identity: %w", err)
	}
	directoryData, err := discoverEnrollmentDirectoryData(ctx, m.ldapConnect, dcHostnameFromDomain(m.domain), objectName, m.domain)
	if err != nil {
		return fmt.Errorf("failed to discover current enrollment configuration: %w", err)
	}
	discoveredCAs := directoryData.CAs
	findDiscoveredCA := func(enrolled enrolledCA) (certAuthority, bool) {
		for _, discovered := range discoveredCAs {
			if strings.EqualFold(discovered.Name, enrolled.Name) && strings.EqualFold(discovered.Hostname, enrolled.Hostname) {
				return discovered, true
			}
		}
		return certAuthority{}, false
	}

	var failures []string
	var rollbackErrs []error
	trustChanged := false
	anyRenewed := false
	var obsoletePaths []string
	var activeInstallations []*caChainInstallation
	var publications []generationPaths
	pendingAdded := 0
	now := time.Now()
	requestedDomain := normalizeDomainIdentity(m.domain)
	isTarget := func(caIndex, templateIndex int) bool {
		if !all {
			return target == (templateStateRef{ca: caIndex, template: templateIndex})
		}
		ca := state.CAs[caIndex]
		tmpl := ca.Templates[templateIndex]
		_, wasPolled := polledTargets[pendingTargetKey(ca.Name, ca.Hostname, tmpl.Template)]
		return !wasPolled
	}
	// retainOldTemplate keeps a failed target's previous entry only when it
	// still validates exactly and currently against its own persisted chain.
	retainOldTemplate := func(ca enrolledCA, tmpl enrolledTemplate) (enrolledTemplate, bool) {
		validated, err := validatePersistedTemplate(ca, tmpl, identity.dnsName, now)
		if err != nil {
			return enrolledTemplate{}, false
		}
		return validated, true
	}

	for i := range state.CAs {
		ca := &state.CAs[i]
		hasTarget := false
		for ti := range ca.Templates {
			if isTarget(i, ti) {
				hasTarget = true
				break
			}
		}
		if !hasTarget {
			continue
		}

		// Envelope integrity is validated independently of any single leaf's
		// current validity, so a targeted (or --all) renewal can still replace
		// an expired, missing or mismatched target leaf, or a target whose old
		// issuer chain has expired, as long as the state it belongs to is safe.
		if err := validateStateEnvelope(state, identity.dnsName, requestedDomain); err != nil {
			for ti, tmpl := range ca.Templates {
				if isTarget(i, ti) {
					failures = append(failures, fmt.Sprintf("%s: persisted enrollment is invalid: %v", tmpl.Nickname, err))
				}
			}
			continue
		}

		// Untouched (non-target) templates that would be retained in state must
		// validate exactly and currently before we mutate this CA. If any is
		// broken we fail safely without touching state, never migrating around
		// or persisting a broken unrelated entry.
		retained := make(map[int]enrolledTemplate, len(ca.Templates))
		retainErr := ""
		for ti := range ca.Templates {
			tmpl := ca.Templates[ti]
			if isTarget(i, ti) {
				continue
			}
			validated, err := validatePersistedTemplate(*ca, tmpl, identity.dnsName, now)
			if err != nil {
				retainErr = fmt.Sprintf("retained template %s is invalid: %v", tmpl.Nickname, err)
				break
			}
			retained[ti] = validated
		}
		if retainErr != "" {
			for ti, tmpl := range ca.Templates {
				if isTarget(i, ti) {
					failures = append(failures, fmt.Sprintf("%s: %s", tmpl.Nickname, retainErr))
				}
			}
			continue
		}

		discoveredCA, caFound := findDiscoveredCA(*ca)
		var installation *caChainInstallation
		var currentBinding templateChainBinding
		var chainInstallErr error
		if caFound && discoveredCA.Chain != nil {
			installation, chainInstallErr = m.installChain(
				discoveredCA,
				filepath.Join(m.stateDir, "certs"),
				m.globalTrustDir,
			)
			if chainInstallErr == nil {
				currentBinding, chainInstallErr = chainBindingFromInstallation(discoveredCA.Chain, installation)
				if chainInstallErr != nil {
					if rbErr := installation.rollback(); rbErr != nil {
						chainInstallErr = errors.Join(chainInstallErr, rbErr)
					}
					installation = nil
				}
			}
		}

		oldRootFiles := append([]string(nil), ca.RootCerts...)
		oldIntermediateFiles := append([]string(nil), ca.IntermediateCerts...)
		oldSymlinkFiles := append([]string(nil), ca.Symlinks...)

		// Build the CA's templates in a working copy; the persisted state is
		// only replaced once at least one target renews successfully, so target
		// state is never mutated or migrated until renewal succeeds.
		workingTemplates := make([]enrolledTemplate, 0, len(ca.Templates))
		renewedOnCA := false
		pendingOnCA := false
		for ti := range ca.Templates {
			tmpl := ca.Templates[ti]
			if !isTarget(i, ti) {
				workingTemplates = append(workingTemplates, retained[ti])
				continue
			}
			retainFailed := func(msg string) {
				failures = append(failures, fmt.Sprintf("%s: %s", tmpl.Nickname, msg))
				if kept, ok := retainOldTemplate(*ca, tmpl); ok {
					workingTemplates = append(workingTemplates, kept)
				}
			}
			if !caFound || discoveredCA.Chain == nil {
				retainFailed("current CA chain was not discovered")
				continue
			}
			if chainInstallErr != nil {
				retainFailed(fmt.Sprintf("installing current CA chain: %v", chainInstallErr))
				continue
			}
			publishedTemplate := ""
			for _, published := range discoveredCA.Templates {
				if strings.EqualFold(published, tmpl.Template) {
					publishedTemplate = published
					break
				}
			}
			if publishedTemplate == "" {
				retainFailed("template is no longer published by CA")
				continue
			}

			keySize := 2048
			if attrs, ok := directoryData.TemplateAttrs[publishedTemplate]; ok && attrs.MinKeySize > 0 {
				keySize = attrs.MinKeySize
			}
			report(progress, gotext.Get("Renewing %s…", tmpl.Nickname))
			log.Debugf(ctx, "Renewing certificate %s (template %s) from CA %s", tmpl.Nickname, tmpl.Template, ca.Name)

			artifactBase := leafArtifactBase(objectName, discoveredCA, publishedTemplate)
			targetSpec := enrollmentTarget{
				ObjectName:        objectName,
				Domain:            normalizeDomainIdentity(m.domain),
				Identity:          identity.dnsName,
				CAName:            discoveredCA.Name,
				Server:            discoveredCA.Hostname,
				Template:          publishedTemplate,
				Nickname:          tmpl.Nickname,
				GenerationRoot:    filepath.Join(m.stateDir, "private", "certs", artifactBase),
				Binding:           currentBinding,
				RootCerts:         append([]string(nil), installation.RootFiles...),
				IntermediateCerts: append([]string(nil), installation.IntermediateFiles...),
				Symlinks:          append([]string(nil), installation.SymlinkFiles...),
				Renewal:           true,
			}
			result, requestErr := m.requestNewCertificate(ctx, targetSpec, keySize, discoveredCA.Chain.Certificates)
			if requestErr != nil {
				log.Warningf(ctx, "Failed to renew certificate %s: %v", tmpl.Nickname, requestErr)
				report(progress, gotext.Get("Failed to renew %s: %v", tmpl.Nickname, requestErr))
				retainFailed(fmt.Sprintf("%v", requestErr))
				continue
			}
			if result.Pending != nil {
				workingState := cloneEnrollmentState(state)
				if err := addPendingEnrollment(workingState, *result.Pending); err != nil {
					cleanupErr := removePendingMaterial(m.stateDir, *result.Pending)
					retainFailed(fmt.Sprintf("tracking pending request: %v", errors.Join(err, cleanupErr)))
					continue
				}
				if err := m.saveEnrollmentState(m.stateDir, workingState); err != nil {
					cleanupErr := removePendingMaterial(m.stateDir, *result.Pending)
					retainFailed(fmt.Sprintf("saving pending request: %v", errors.Join(err, cleanupErr)))
					continue
				}
				state.Pending = workingState.Pending
				state.UpdatedAt = workingState.UpdatedAt
				workingTemplates = append(workingTemplates, tmpl)
				pendingOnCA = true
				pendingAdded++
				report(progress, gotext.Get("Request %d for %s is pending CA approval", result.Pending.RequestID, tmpl.Nickname))
				continue
			}
			renewed := result.Template
			if result.PublishErr != nil {
				failures = append(failures, fmt.Sprintf("%s: publishing generation: %v", tmpl.Nickname, result.PublishErr))
			} else {
				publications = append(publications, result.Publication)
			}
			if tmpl.GenerationDir != "" {
				obsoletePaths = append(obsoletePaths, generationArtifactPaths(tmpl)...)
			} else {
				obsoletePaths = append(obsoletePaths, tmpl.KeyFile, tmpl.CertFile)
			}
			workingTemplates = append(workingTemplates, renewed)
			renewedOnCA = true
			report(progress, gotext.Get("Renewed %s", tmpl.Nickname))
		}

		if renewedOnCA {
			workingCA := *ca
			workingCA.Templates = workingTemplates
			if err := rebuildCAArtifacts(&workingCA); err != nil {
				var cleanupErrs []error
				if !pendingOnCA {
					if rbErr := installation.rollback(); rbErr != nil {
						cleanupErrs = append(cleanupErrs, fmt.Errorf("rolling back installed CA chain: %w", rbErr))
					}
				}
				for _, active := range activeInstallations {
					if rbErr := active.rollback(); rbErr != nil {
						cleanupErrs = append(cleanupErrs, fmt.Errorf("rolling back previously renewed CA chain: %w", rbErr))
					}
				}
				rebuildErrs := []error{
					fmt.Errorf("rebuilding CA chain state after renewal of %s: %w", ca.Name, err),
				}
				rebuildErrs = append(rebuildErrs, cleanupErrs...)
				rebuildErrs = append(rebuildErrs, rollbackErrs...)
				return errors.Join(rebuildErrs...)
			}
			*ca = workingCA
			obsoletePaths = append(obsoletePaths, pathsNotRetained(oldRootFiles, oldIntermediateFiles, oldSymlinkFiles, *ca)...)
			if !pendingOnCA {
				activeInstallations = append(activeInstallations, installation)
			}
			trustChanged = true
			anyRenewed = true
		} else if installation != nil && !pendingOnCA {
			if err := installation.rollback(); err != nil {
				rollbackErrs = append(rollbackErrs, fmt.Errorf("rolling back unused CA chain for %s: %w", ca.Name, err))
			}
		}
	}

	if !anyRenewed {
		rollbackErrs = append(rollbackErrs, pollSummary.Errors...)
		if pendingAdded != 0 || pollSummary.Pending != 0 {
			rollbackErrs = append(rollbackErrs, ErrEnrollmentPending)
		}
		if len(failures) != 0 {
			renewErr := errors.New(gotext.Get("failed to renew %d certificate(s): %s", len(failures), strings.Join(failures, "; ")))
			return errors.Join(append([]error{renewErr}, rollbackErrs...)...)
		}
		return errors.Join(rollbackErrs...)
	}

	state.Domain = normalizeDomainIdentity(m.domain)
	state.Identity = identity.dnsName
	if err := m.saveEnrollmentState(m.stateDir, state); err != nil {
		var cleanupErrs []error
		for _, installation := range activeInstallations {
			if rbErr := installation.rollback(); rbErr != nil {
				cleanupErrs = append(cleanupErrs, fmt.Errorf("rolling back renewed CA chain: %w", rbErr))
			}
		}
		saveErrs := []error{fmt.Errorf("failed to save enrollment state: %w", err)}
		saveErrs = append(saveErrs, cleanupErrs...)
		saveErrs = append(saveErrs, rollbackErrs...)
		return errors.Join(saveErrs...)
	}
	for _, publication := range publications {
		if err := finalizeGenerationPublication(publication); err != nil {
			rollbackErrs = append(rollbackErrs, err)
		}
	}
	if err := removeUnreferencedPaths(ctx, m.stateDir, state.ObjectName, m.domain, state, obsoletePaths); err != nil {
		rollbackErrs = append(rollbackErrs, fmt.Errorf("pruning obsolete CA chain paths after renewal: %w", err))
	}
	if trustChanged {
		if err := updateCATrustStore(); err != nil {
			log.Warningf(ctx, "Failed to update CA trust store after renewal: %v", err)
		}
	}

	if len(failures) > 0 {
		renewErr := errors.New(gotext.Get("failed to renew %d certificate(s): %s", len(failures), strings.Join(failures, "; ")))
		return errors.Join(append(append([]error{renewErr}, rollbackErrs...), pollSummary.Errors...)...)
	}
	rollbackErrs = append(rollbackErrs, pollSummary.Errors...)
	if pendingAdded != 0 || pollSummary.Pending != 0 {
		rollbackErrs = append(rollbackErrs, ErrEnrollmentPending)
	}
	if len(rollbackErrs) > 0 {
		return errors.Join(rollbackErrs...)
	}
	return nil
}

func pathsNotRetained(rootFiles, intermediateFiles, symlinkFiles []string, retained enrolledCA) []string {
	keep := make(map[string]struct{})
	for _, paths := range [][]string{retained.RootCerts, retained.IntermediateCerts, retained.Symlinks} {
		for _, path := range paths {
			keep[path] = struct{}{}
		}
	}
	var obsolete []string
	add := func(paths []string) {
		for _, path := range paths {
			if _, ok := keep[path]; ok {
				continue
			}
			obsolete = append(obsolete, path)
		}
	}
	add(symlinkFiles)
	add(intermediateFiles)
	add(rootFiles)
	return obsolete
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
	trustLifecycleMu.Lock()
	defer trustLifecycleMu.Unlock()

	if !force {
		return errors.New(gotext.Get("refusing to remove certificates without confirmation, pass force to proceed"))
	}

	if all {
		report(progress, gotext.Get("Removing all certificates for %s", objectName))
		if err := m.unenrollLocked(ctx, objectName); err != nil {
			return err
		}
		report(progress, gotext.Get("Removed all certificates for %s", objectName))
		return nil
	}

	state, err := loadState(m.stateDir, objectName, m.domain)
	if err != nil {
		return fmt.Errorf("failed to load enrollment state: %w", err)
	}
	if state == nil || len(state.CAs) == 0 && len(state.Pending) == 0 {
		return errors.New(gotext.Get("no enrolled certificates found for %q", objectName))
	}

	var obsoletePaths []string
	var pendingPathErrs []error
	pendingRemoved := false
	for index := 0; index < len(state.Pending); {
		if state.Pending[index].Nickname != nickname {
			index++
			continue
		}
		pending := state.Pending[index]
		pendingPaths, pathErr := pendingArtifactRemovalPaths(m.stateDir, m.globalTrustDir, pending)
		if pathErr != nil {
			pendingPathErrs = append(pendingPathErrs, fmt.Errorf("validating pending request %d artifacts before removal: %w", pending.RequestID, pathErr))
		} else {
			obsoletePaths = append(obsoletePaths, pendingPaths...)
		}
		state.Pending = append(state.Pending[:index], state.Pending[index+1:]...)
		pendingRemoved = true
	}
	var target templateStateRef
	hasIssuedTarget := false
	if len(state.CAs) != 0 {
		target, err = resolveNickname(state, nickname)
		if err == nil {
			hasIssuedTarget = true
		} else if !pendingRemoved {
			return err
		}
	}
	if !pendingRemoved && !hasIssuedTarget {
		return errors.New(gotext.Get("certificate %q not found", nickname))
	}
	if hasIssuedTarget {
		for ci := range state.CAs {
			if ci != target.ca {
				continue
			}
			ca := &state.CAs[ci]
			for ti, tmpl := range ca.Templates {
				if ti != target.template {
					continue
				}
				report(progress, gotext.Get("Removing certificate %s", tmpl.Nickname))
				log.Debugf(ctx, "Removing certificate files for %s", tmpl.Nickname)
				obsoletePaths = append(obsoletePaths, tmpl.CertFile, tmpl.KeyFile)
				obsoletePaths = append(obsoletePaths, generationArtifactPaths(tmpl)...)
				obsoletePaths = append(obsoletePaths, tmpl.ChainFiles...)
				obsoletePaths = append(obsoletePaths, tmpl.TrustAnchorSymlink)
				ca.Templates = append(ca.Templates[:ti], ca.Templates[ti+1:]...)
				break
			}
			if len(ca.Templates) == 0 {
				report(progress, gotext.Get("Removing root CA %s from the trust store", ca.Name))
				obsoletePaths = append(obsoletePaths, ca.RootCerts...)
				obsoletePaths = append(obsoletePaths, ca.IntermediateCerts...)
				obsoletePaths = append(obsoletePaths, ca.Symlinks...)
				state.CAs = append(state.CAs[:ci], state.CAs[ci+1:]...)
			} else {
				allBound := true
				for _, remaining := range ca.Templates {
					if !templateHasChainBinding(remaining) {
						allBound = false
						break
					}
				}
				if allBound {
					oldRoots := append([]string(nil), ca.RootCerts...)
					oldIntermediates := append([]string(nil), ca.IntermediateCerts...)
					oldSymlinks := append([]string(nil), ca.Symlinks...)
					if err := rebuildCAArtifacts(ca); err != nil {
						return fmt.Errorf("rebuilding CA chain state after removal: %w", err)
					}
					obsoletePaths = append(obsoletePaths, pathsNotRetained(oldRoots, oldIntermediates, oldSymlinks, *ca)...)
				}
			}
			break
		}
	}

	if len(state.CAs) == 0 && len(state.Pending) == 0 {
		if err := removeState(m.stateDir, objectName, m.domain); err != nil {
			return fmt.Errorf("failed to remove enrollment state: %w", err)
		}
	} else if err := m.saveEnrollmentState(m.stateDir, state); err != nil {
		return fmt.Errorf("failed to save enrollment state: %w", err)
	}
	var replacement *enrollmentState
	if len(state.CAs) != 0 || len(state.Pending) != 0 {
		replacement = state
	}
	if err := removeUnreferencedPaths(ctx, m.stateDir, state.ObjectName, m.domain, replacement, obsoletePaths); err != nil {
		pendingPathErrs = append(pendingPathErrs, fmt.Errorf("failed to prune unreferenced CA chain paths after removal: %w", err))
	}

	if err := updateCATrustStore(); err != nil {
		log.Warningf(ctx, "Failed to update CA trust store after removal: %v", err)
	}
	report(progress, gotext.Get("Removed certificate %s", nickname))
	return errors.Join(pendingPathErrs...)
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
	trustLifecycleMu.RLock()
	defer trustLifecycleMu.RUnlock()

	state, err := loadState(m.stateDir, objectName, m.domain)
	if err != nil {
		return nil, fmt.Errorf("failed to load enrollment state: %w", err)
	}
	if state == nil || len(state.CAs) == 0 {
		if nickname != "" {
			return nil, errors.New(gotext.Get("no enrolled certificates found for %q", objectName))
		}
		return []VerifyResult{}, nil
	}

	// The verification identity is always derived from the request. loadState
	// has already proved that the state envelope belongs to this object/domain.
	requested, err := enrollmentMachineIdentity(objectName, m.domain)
	if err != nil {
		return nil, fmt.Errorf("could not determine requested machine identity: %w", err)
	}
	identity := requested.dnsName

	var target templateStateRef
	if nickname != "" {
		target, err = resolveNickname(state, nickname)
		if err != nil {
			return nil, err
		}
	}
	results := make([]VerifyResult, 0)
	for ci, ca := range state.CAs {
		for ti, tmpl := range ca.Templates {
			if nickname != "" && target != (templateStateRef{ca: ci, template: ti}) {
				continue
			}
			results = append(results, verifyCertificate(ctx, ca, tmpl, identity, online))
		}
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
	trustLifecycleMu.RLock()
	defer trustLifecycleMu.RUnlock()

	cas, err := discoverCAsAndTemplates(ctx, m.ldapConnect, dcHostnameFromDomain(m.domain))
	if err != nil {
		return nil, fmt.Errorf("failed to discover certificate authorities: %w", err)
	}

	state, err := loadState(m.stateDir, objectName, m.domain)
	if err != nil {
		return nil, fmt.Errorf("failed to load enrollment state for cross-reference: %w", err)
	}

	trustDir := filepath.Join(m.stateDir, "certs")
	infos := make([]CAInfo, 0, len(cas))
	for _, ca := range cas {
		info := CAInfo{
			Name:      ca.Name,
			Hostname:  ca.Hostname,
			Templates: ca.Templates,
		}
		if ca.Chain != nil {
			info.RootFingerprints = append([]string(nil), ca.Chain.Fingerprints...)
		}
		info.InstalledInTrust = caInstalledInTrust(ca, state, trustDir, m.globalTrustDir)
		info.Enrolled = caEnrolled(ca, state)
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
	trustLifecycleMu.RLock()
	defer trustLifecycleMu.RUnlock()

	log.Debugf(ctx, "Discovering supported templates for server %s", server)
	connector := newKerberosLDAPConnector(m.krb5CacheDir, m.globalTrustDir, true)
	return GetSupportedTemplatesWithConnector(ctx, connector, server)
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
	keyPath, certPath, generationErr := templateGenerationReadPaths(tmpl)
	info.OnDisk = generationErr == nil && filesExist(keyPath, certPath)

	cert := parseCertFile(certPath)
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

		if filesExist(keyPath) {
			if match, err := publicKeysMatch(cert, tmpl); err == nil {
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
func verifyCertificate(ctx context.Context, ca enrolledCA, tmpl enrolledTemplate, identity string, online bool) VerifyResult {
	res := VerifyResult{Nickname: tmpl.Nickname}

	_, certPath, generationErr := templateGenerationReadPaths(tmpl)
	if generationErr != nil {
		res.Messages = append(res.Messages, gotext.Get("certificate generation is invalid: %v", generationErr))
		return res
	}
	cert := parseCertFile(certPath)
	if cert == nil {
		res.Messages = append(res.Messages, gotext.Get("certificate file is missing or unparseable: %s", tmpl.CertFile))
		return res
	}

	now := time.Now()
	res.ValidityOK = now.After(cert.NotBefore) && now.Before(cert.NotAfter)
	if !res.ValidityOK {
		res.Messages = append(res.Messages, gotext.Get("certificate is outside its validity window (%s - %s)", cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339)))
	}

	if match, err := publicKeysMatch(cert, tmpl); err != nil {
		res.Messages = append(res.Messages, gotext.Get("could not compare private key: %v", err))
	} else if match {
		res.KeyMatchOK = true
	} else {
		res.Messages = append(res.Messages, gotext.Get("private key does not match the certificate"))
	}

	identityOK := true
	if err := verifyCertificateIdentity(cert, identity); err != nil {
		identityOK = false
		res.Messages = append(res.Messages, gotext.Get("machine identity verification failed: %v", err))
	}

	binding, chain, legacy, err := loadTemplateChain(ca, tmpl, now)
	if err != nil {
		res.Messages = append(res.Messages, gotext.Get("persisted exact chain is unavailable or invalid: %v", err))
	} else {
		leafBindingOK := true
		leafFingerprint := certificateFingerprint(cert)
		if tmpl.LeafFingerprint == "" {
			if !legacy {
				leafBindingOK = false
				res.Messages = append(res.Messages, gotext.Get("persisted leaf fingerprint is missing"))
			}
		} else if !strings.EqualFold(tmpl.LeafFingerprint, leafFingerprint) {
			leafBindingOK = false
			res.Messages = append(res.Messages, gotext.Get("certificate fingerprint %s does not match persisted fingerprint %s", leafFingerprint, tmpl.LeafFingerprint))
		}
		if !strings.EqualFold(binding.IssuerFingerprint, certificateFingerprint(chain[0])) {
			leafBindingOK = false
			res.Messages = append(res.Messages, gotext.Get("persisted issuer fingerprint does not match the exact chain"))
		}
		if err := verifyLeafAgainstExactChain(cert, chain, now); err != nil {
			res.Messages = append(res.Messages, gotext.Get("chain verification failed: %v", err))
		} else if leafBindingOK && identityOK {
			res.ChainOK = true
		}
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

// publicKeysMatch reports whether the certificate's public key matches the
// private key selected by tmpl's atomic generation. It returns false (with an error) when the
// key is missing or unreadable, and false without error on a genuine mismatch.
func publicKeysMatch(cert *x509.Certificate, tmpl enrolledTemplate) (bool, error) {
	keyPEMPath, _, err := templateGenerationReadPaths(tmpl)
	if err != nil {
		return false, fmt.Errorf("could not resolve private key generation: %w", err)
	}
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

// caInstalledInTrust reports whether the discovered CA's root is trusted, either
// because the discovered certificate verifies against the trust store or
// because the enrollment state records installed root files for it.
func caInstalledInTrust(ca certAuthority, state *enrollmentState, trustDir, globalTrustDir string) bool {
	if ca.Chain != nil && ca.Chain.root() != nil {
		rootFingerprint := certificateFingerprint(ca.Chain.root())
		for _, dir := range []string{trustDir, globalTrustDir} {
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				cert := parseCertFile(filepath.Join(dir, entry.Name()))
				if cert != nil && certificateFingerprint(cert) == rootFingerprint {
					return true
				}
			}
		}
	}
	if state != nil {
		for _, sca := range state.CAs {
			if strings.EqualFold(sca.Name, ca.Name) &&
				strings.EqualFold(sca.Hostname, ca.Hostname) &&
				len(sca.RootCerts) > 0 &&
				filesExist(sca.RootCerts...) {
				return true
			}
		}
	}
	return false
}

// caEnrolled reports whether the state records at least one enrolled template
// with an on-disk certificate for the named CA.
func caEnrolled(authority certAuthority, state *enrollmentState) bool {
	if state == nil {
		return false
	}
	for _, sca := range state.CAs {
		if !strings.EqualFold(sca.Name, authority.Name) || !strings.EqualFold(sca.Hostname, authority.Hostname) {
			continue
		}
		for _, tmpl := range sca.Templates {
			_, certPath, err := templateGenerationReadPaths(tmpl)
			if err == nil && filesExist(certPath) {
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

type templateStateRef struct {
	ca       int
	template int
}

// resolveNickname accepts the persisted identifier, the current
// raw-identity-disambiguated identifier, or a historical sanitized alias. A
// historical alias is safe only when it identifies exactly one template.
func resolveNickname(state *enrollmentState, nickname string) (templateStateRef, error) {
	var matches []templateStateRef
	for ci, ca := range state.CAs {
		for ti, tmpl := range ca.Templates {
			aliases := []string{
				tmpl.Nickname,
				managementNickname(ca.Name, ca.Hostname, tmpl.Template),
				legacyManagementNickname(ca.Name, tmpl.Template),
			}
			if slices.Contains(aliases, nickname) {
				matches = append(matches, templateStateRef{ca: ci, template: ti})
			}
		}
	}
	valid := strings.Join(nicknamesOfState(state), ", ")
	switch len(matches) {
	case 0:
		return templateStateRef{}, errors.New(gotext.Get("certificate %q not found (valid nicknames: %s)", nickname, valid))
	case 1:
		return matches[0], nil
	default:
		return templateStateRef{}, errors.New(gotext.Get("certificate nickname %q is ambiguous (valid nicknames: %s)", nickname, valid))
	}
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

package certificate

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ErrEnrollmentPending indicates that at least one durable request still
// requires CA approval. It is not a rollback condition.
var ErrEnrollmentPending = errors.New("certificate enrollment is pending CA approval")

type enrollmentAttemptResult struct {
	Pending     *pendingEnrollment
	Template    enrolledTemplate
	Certificate *x509.Certificate
	Publication generationPaths
}

func (m *Manager) requestNewCertificate(ctx context.Context, target enrollmentTarget, keySize int, expectedChain []*x509.Certificate) (result enrollmentAttemptResult, err error) {
	if m.requestCertificate == nil {
		return enrollmentAttemptResult{}, fmt.Errorf("certificate requester is unavailable")
	}
	if normalizeMachineIdentity(target.Identity) == "" {
		return enrollmentAttemptResult{}, fmt.Errorf("expected machine identity is required")
	}
	if len(expectedChain) == 0 {
		return enrollmentAttemptResult{}, fmt.Errorf("expected directory CA chain is required")
	}

	draft, err := createEnrollmentDraft(m.stateDir, target, keySize)
	if err != nil {
		return enrollmentAttemptResult{}, err
	}
	keepDraft := false
	defer func() {
		if keepDraft {
			return
		}
		if cleanupErr := removeDraftPaths(draft); cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
	}()

	response, err := m.requestCertificate.Submit(ctx, SubmitRequest{
		Server: target.Server, CAName: target.CAName, Template: target.Template, CSRPEM: draft.CSRPEM,
	})
	if err != nil {
		return enrollmentAttemptResult{}, err
	}
	if err := validateDispositionResponse(response, 0, false); err != nil {
		return enrollmentAttemptResult{}, err
	}
	switch response.Disposition {
	case DispositionDenied, DispositionRevoked:
		return enrollmentAttemptResult{}, terminalDispositionError(response, nil)
	case DispositionPending:
		pending := newPendingEnrollment(target, draft, response.RequestID)
		keepDraft = true
		return enrollmentAttemptResult{Pending: &pending}, nil
	case DispositionIssued, DispositionIssuedOutOfBand:
		// "Issued out of band" normally has no retrievable leaf. Treat it as
		// terminal unless this response itself carries a leaf that passes every
		// ordinary key, identity, exact-chain, and validity check.
		result, err = m.finishIssuedResponse(target, draft.KeyPEM, expectedChain, response)
		if err != nil {
			if response.Disposition == DispositionIssuedOutOfBand {
				return enrollmentAttemptResult{}, terminalDispositionError(response, err)
			}
			return enrollmentAttemptResult{}, err
		}
		return result, nil
	default:
		return enrollmentAttemptResult{}, fmt.Errorf("unsupported certificate disposition %d", response.Disposition)
	}
}

func (m *Manager) finishIssuedResponse(target enrollmentTarget, keyPEM []byte, expectedChain []*x509.Certificate, response Response) (enrollmentAttemptResult, error) {
	if _, err := validateSingleDERCertificate(response.CertificateDER); err != nil {
		return enrollmentAttemptResult{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: response.CertificateDER})
	cert, err := verifyIssuedCertificate(string(certPEM), keyPEM, target.Identity, expectedChain, time.Now())
	if err != nil {
		return enrollmentAttemptResult{}, fmt.Errorf("issued certificate verification failed: %w", err)
	}
	publication, publishErr := m.publishGeneration(target.GenerationRoot, keyPEM, certPEM, m.generationOps)
	if publishErr != nil {
		if publication.Switched {
			publishErr = errors.Join(
				publishErr,
				rollbackContext("published certificate generation", rollbackGenerationPublication(publication, m.generationOps)),
			)
		}
		return enrollmentAttemptResult{}, publishErr
	}
	if !publication.Switched {
		return enrollmentAttemptResult{}, fmt.Errorf("certificate generation publisher returned without a durable pointer switch")
	}
	enrolled := enrolledTemplate{
		Nickname:          target.Nickname,
		Template:          target.Template,
		KeyFile:           publication.KeyFile,
		CertFile:          publication.CertFile,
		GenerationRoot:    publication.Root,
		GenerationPointer: publication.Pointer,
		GenerationDir:     publication.Directory,
		LeafFingerprint:   certificateFingerprint(cert),
	}
	bindTemplateToChain(&enrolled, target.Binding)
	return enrollmentAttemptResult{
		Template:    enrolled,
		Certificate: cert,
		Publication: publication,
	}, nil
}

func validateDispositionResponse(response Response, requestID uint32, polling bool) error {
	switch response.Disposition {
	case DispositionDenied, DispositionIssued, DispositionIssuedOutOfBand, DispositionPending, DispositionRevoked:
	default:
		return fmt.Errorf("certificate server returned unknown disposition %d", response.Disposition)
	}
	if response.Disposition == DispositionPending && response.RequestID == 0 {
		return fmt.Errorf("certificate server returned pending disposition with request ID 0")
	}
	if polling && response.RequestID != 0 && response.RequestID != requestID {
		return fmt.Errorf("certificate poll returned request ID %d instead of %d", response.RequestID, requestID)
	}
	return nil
}

type pendingPollSummary struct {
	Pending int
	Issued  int
	Errors  []error
}

func (m *Manager) pollPendingEnrollments(ctx context.Context, state *enrollmentState, selected func(pendingEnrollment) bool, progress func(string)) pendingPollSummary {
	var summary pendingPollSummary
	if state == nil {
		return summary
	}
	for index := 0; index < len(state.Pending); {
		pending := state.Pending[index]
		if selected != nil && !selected(pending) {
			index++
			continue
		}
		report(progress, fmt.Sprintf("Polling pending certificate request %s (ID %d)", pending.Nickname, pending.RequestID))
		keyPEM, _, chain, err := validatePendingEnrollment(m.stateDir, m.globalTrustDir, state, pending, time.Now())
		if err != nil {
			err = fmt.Errorf("%s: validating pending request %d: %w", pending.Nickname, pending.RequestID, err)
			summary.Errors = append(summary.Errors, err)
			logPendingRetention(ctx, pending, err)
			index++
			continue
		}
		response, err := m.requestCertificate.Poll(ctx, PollRequest{
			Server: pending.Server, CAName: pending.CAName, RequestID: pending.RequestID,
		})
		if err != nil {
			err = fmt.Errorf("%s: polling request %d: %w", pending.Nickname, pending.RequestID, err)
			summary.Errors = append(summary.Errors, err)
			logPendingRetention(ctx, pending, err)
			index++
			continue
		}
		if err := validateDispositionResponse(response, pending.RequestID, true); err != nil {
			err = fmt.Errorf("%s: %w", pending.Nickname, err)
			summary.Errors = append(summary.Errors, err)
			logPendingRetention(ctx, pending, err)
			index++
			continue
		}

		switch response.Disposition {
		case DispositionPending:
			working := cloneEnrollmentState(state)
			working.Pending[index].LastPolledAt = time.Now().UTC()
			if err := m.saveEnrollmentState(m.stateDir, working); err != nil {
				err = fmt.Errorf("%s: saving pending poll timestamp: %w", pending.Nickname, err)
				summary.Errors = append(summary.Errors, err)
				logPendingRetention(ctx, pending, err)
				index++
				continue
			}
			*state = *working
			summary.Pending++
			index++
		case DispositionDenied, DispositionRevoked:
			terminal := terminalDispositionError(response, nil)
			removed, cleanupErr := m.removeTerminalPending(ctx, state, index, pending)
			summary.Errors = append(summary.Errors, errors.Join(terminal, cleanupErr))
			if !removed {
				index++
			}
		case DispositionIssued, DispositionIssuedOutOfBand:
			target := targetFromPending(pending)
			result, issuedErr := m.finishIssuedResponse(target, keyPEM, chain, response)
			if issuedErr != nil {
				if response.Disposition == DispositionIssuedOutOfBand {
					terminal := terminalDispositionError(response, issuedErr)
					removed, cleanupErr := m.removeTerminalPending(ctx, state, index, pending)
					summary.Errors = append(summary.Errors, errors.Join(terminal, cleanupErr))
					if !removed {
						index++
					}
					continue
				}
				issuedErr = fmt.Errorf("%s: validating issued response for request %d: %w", pending.Nickname, pending.RequestID, issuedErr)
				summary.Errors = append(summary.Errors, issuedErr)
				logPendingRetention(ctx, pending, issuedErr)
				index++
				continue
			}
			working := cloneEnrollmentState(state)
			working.Pending = append(working.Pending[:index], working.Pending[index+1:]...)
			oldTemplate, err := upsertIssuedTemplate(working, pending, result.Template)
			if err != nil {
				stateErr := fmt.Errorf("%s: building issued certificate state: %w", pending.Nickname, err)
				rollbackErr := rollbackGenerationPublication(result.Publication, m.generationOps)
				summary.Errors = append(summary.Errors, errors.Join(stateErr, rollbackContext("issued certificate generation", rollbackErr)))
				logPendingRetention(ctx, pending, stateErr)
				index++
				continue
			}
			if err := m.saveEnrollmentState(m.stateDir, working); err != nil {
				saveErr := fmt.Errorf("%s: saving issued certificate state: %w", pending.Nickname, err)
				rollbackErr := rollbackGenerationPublication(result.Publication, m.generationOps)
				summary.Errors = append(summary.Errors, errors.Join(saveErr, rollbackContext("issued certificate generation", rollbackErr)))
				logPendingRetention(ctx, pending, saveErr)
				index++
				continue
			}
			*state = *working
			summary.Issued++
			var cleanupErrs []error
			finalizeErr := finalizeGenerationPublicationWithOps(result.Publication, m.generationOps)
			if finalizeErr != nil {
				cleanupErrs = append(cleanupErrs, finalizeErr)
			}
			if err := m.removePending(m.stateDir, pending); err != nil {
				cleanupErrs = append(cleanupErrs, err)
			}
			if finalizeErr != nil {
				summary.Errors = append(summary.Errors, fmt.Errorf("%s: finalizing issued request: %w", pending.Nickname, errors.Join(cleanupErrs...)))
				report(progress, fmt.Sprintf("Certificate issued for %s", pending.Nickname))
				continue
			}
			obsolete := pendingReferencedPaths(pending)
			obsolete = append(obsolete, templateArtifactRemovalPaths(oldTemplate)...)
			if err := removeUnreferencedPaths(ctx, m.stateDir, m.globalTrustDir, state.ObjectName, state.Domain, state, obsolete); err != nil {
				cleanupErrs = append(cleanupErrs, err)
			}
			if cleanupErr := errors.Join(cleanupErrs...); cleanupErr != nil {
				summary.Errors = append(summary.Errors, fmt.Errorf("%s: finalizing issued request: %w", pending.Nickname, cleanupErr))
			}
			report(progress, fmt.Sprintf("Certificate issued for %s", pending.Nickname))
		}
	}
	return summary
}

func (m *Manager) removeTerminalPending(ctx context.Context, state *enrollmentState, index int, pending pendingEnrollment) (bool, error) {
	working := cloneEnrollmentState(state)
	working.Pending = append(working.Pending[:index], working.Pending[index+1:]...)
	if err := m.saveEnrollmentState(m.stateDir, working); err != nil {
		return false, fmt.Errorf("saving terminal pending-request removal: %w", err)
	}
	*state = *working
	var errs []error
	if err := m.removePending(m.stateDir, pending); err != nil {
		errs = append(errs, err)
	}
	if err := removeUnreferencedPaths(ctx, m.stateDir, m.globalTrustDir, state.ObjectName, state.Domain, state, pendingReferencedPaths(pending)); err != nil {
		errs = append(errs, err)
	}
	return true, errors.Join(errs...)
}

func targetFromPending(pending pendingEnrollment) enrollmentTarget {
	return enrollmentTarget{
		ObjectName:     pending.ObjectName,
		Domain:         pending.Domain,
		Identity:       pending.Identity,
		CAName:         pending.CAName,
		Server:         pending.Server,
		Template:       pending.Template,
		Nickname:       pending.Nickname,
		GenerationRoot: pending.GenerationRoot,
		Binding: templateChainBinding{
			IssuerFingerprint:  pending.IssuerFingerprint,
			Fingerprints:       append([]string(nil), pending.ChainFingerprints...),
			Files:              append([]string(nil), pending.ChainFiles...),
			TrustAnchorSymlink: pending.TrustAnchorSymlink,
		},
		RootCerts:         append([]string(nil), pending.RootCerts...),
		IntermediateCerts: append([]string(nil), pending.IntermediateCerts...),
		Symlinks:          append([]string(nil), pending.Symlinks...),
		Renewal:           pending.Renewal,
	}
}

func upsertIssuedTemplate(state *enrollmentState, pending pendingEnrollment, issued enrolledTemplate) (enrolledTemplate, error) {
	for caIndex := range state.CAs {
		ca := &state.CAs[caIndex]
		if !strings.EqualFold(ca.Name, pending.CAName) || !strings.EqualFold(ca.Hostname, pending.Server) {
			continue
		}
		for templateIndex := range ca.Templates {
			if strings.EqualFold(ca.Templates[templateIndex].Template, pending.Template) {
				old := ca.Templates[templateIndex]
				ca.Templates[templateIndex] = issued
				if err := rebuildCAArtifacts(ca); err != nil {
					return enrolledTemplate{}, err
				}
				return old, nil
			}
		}
		ca.Templates = append(ca.Templates, issued)
		if err := rebuildCAArtifacts(ca); err != nil {
			return enrolledTemplate{}, err
		}
		return enrolledTemplate{}, nil
	}
	ca := enrolledCA{
		Name:              pending.CAName,
		Hostname:          pending.Server,
		IssuerFingerprint: pending.IssuerFingerprint,
		ChainFingerprints: append([]string(nil), pending.ChainFingerprints...),
		RootCerts:         append([]string(nil), pending.RootCerts...),
		IntermediateCerts: append([]string(nil), pending.IntermediateCerts...),
		Symlinks:          append([]string(nil), pending.Symlinks...),
		Templates:         []enrolledTemplate{issued},
	}
	if err := rebuildCAArtifacts(&ca); err != nil {
		return enrolledTemplate{}, err
	}
	state.CAs = append(state.CAs, ca)
	return enrolledTemplate{}, nil
}

func generationArtifactPaths(template enrolledTemplate) []string {
	if template.GenerationDir == "" {
		return nil
	}
	paths := []string{
		filepath.Join(template.GenerationDir, generationMarker),
		filepath.Join(template.GenerationDir, generationMarkerTemp),
		filepath.Join(template.GenerationDir, generationCertName),
		filepath.Join(template.GenerationDir, generationKeyName),
		template.GenerationDir,
	}
	if template.GenerationPointer != "" {
		paths = append(paths, template.GenerationPointer)
	}
	if template.GenerationRoot != "" {
		paths = append(paths, filepath.Join(template.GenerationRoot, "generations"), template.GenerationRoot)
	}
	return paths
}

func templateArtifactRemovalPaths(template enrolledTemplate) []string {
	if template.GenerationDir != "" {
		return generationArtifactPaths(template)
	}
	return []string{template.CertFile, template.KeyFile}
}

func pendingForTarget(state *enrollmentState, caName, server, template string) (pendingEnrollment, bool) {
	if state == nil {
		return pendingEnrollment{}, false
	}
	for _, pending := range state.Pending {
		if strings.EqualFold(pending.CAName, caName) &&
			strings.EqualFold(pending.Server, server) &&
			strings.EqualFold(pending.Template, template) {
			return pending, true
		}
	}
	return pendingEnrollment{}, false
}

func pendingByNickname(state *enrollmentState, nickname string) (pendingEnrollment, bool) {
	if state == nil {
		return pendingEnrollment{}, false
	}
	for _, pending := range state.Pending {
		if pending.Nickname == nickname {
			return pending, true
		}
	}
	return pendingEnrollment{}, false
}

func pendingTargetKey(caName, server, template string) string {
	return strings.ToLower(caName) + "\x00" + strings.ToLower(server) + "\x00" + strings.ToLower(template)
}

func pendingMatchesTarget(pending pendingEnrollment, target enrollmentTarget) error {
	if pending.ObjectName != target.ObjectName ||
		normalizeDomainIdentity(pending.Domain) != normalizeDomainIdentity(target.Domain) ||
		normalizeMachineIdentity(pending.Identity) != normalizeMachineIdentity(target.Identity) {
		return fmt.Errorf("object, domain, or machine identity changed")
	}
	if !strings.EqualFold(pending.CAName, target.CAName) ||
		!strings.EqualFold(pending.Server, target.Server) ||
		!strings.EqualFold(pending.Template, target.Template) ||
		pending.Nickname != target.Nickname {
		return fmt.Errorf("CA, server, template, or nickname changed")
	}
	if filepath.Clean(pending.GenerationRoot) != filepath.Clean(target.GenerationRoot) {
		return fmt.Errorf("generation root changed")
	}
	if !strings.EqualFold(pending.IssuerFingerprint, target.Binding.IssuerFingerprint) ||
		!equalFoldStrings(pending.ChainFingerprints, target.Binding.Fingerprints) ||
		!slicesEqualPaths(pending.ChainFiles, target.Binding.Files) ||
		filepath.Clean(pending.TrustAnchorSymlink) != filepath.Clean(target.Binding.TrustAnchorSymlink) {
		return fmt.Errorf("exact CA chain binding changed")
	}
	return nil
}

func slicesEqualPaths(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if filepath.Clean(a[index]) != filepath.Clean(b[index]) { //nolint:gosec // Equal lengths are checked above.
			return false
		}
	}
	return true
}

func addPendingEnrollment(state *enrollmentState, pending pendingEnrollment) error {
	if _, exists := pendingForTarget(state, pending.CAName, pending.Server, pending.Template); exists {
		return fmt.Errorf("a pending request already exists for CA %s template %s", pending.CAName, pending.Template)
	}
	for _, existing := range state.Pending {
		if existing.RequestID == pending.RequestID &&
			strings.EqualFold(existing.Server, pending.Server) &&
			strings.EqualFold(existing.CAName, pending.CAName) {
			return fmt.Errorf("pending request ID %d is already tracked for CA %s", pending.RequestID, pending.CAName)
		}
	}
	state.Pending = append(state.Pending, pending)
	return nil
}

func templateGenerationReadPaths(template enrolledTemplate) (string, string, error) {
	if template.GenerationDir == "" && template.GenerationPointer == "" && template.GenerationRoot == "" {
		return template.KeyFile, template.CertFile, nil
	}
	if template.GenerationDir == "" || template.GenerationPointer == "" || template.GenerationRoot == "" {
		return "", "", fmt.Errorf("certificate generation metadata is incomplete")
	}
	expectedPointer := filepath.Join(template.GenerationRoot, "current")
	expectedKey := filepath.Join(expectedPointer, generationKeyName)
	expectedCert := filepath.Join(expectedPointer, generationCertName)
	if filepath.Clean(template.GenerationPointer) != filepath.Clean(expectedPointer) ||
		filepath.Clean(template.KeyFile) != filepath.Clean(expectedKey) ||
		filepath.Clean(template.CertFile) != filepath.Clean(expectedCert) {
		return "", "", fmt.Errorf("stable certificate generation paths do not match state")
	}
	current, err := inspectGenerationPointer(template.GenerationRoot)
	if err != nil {
		return "", "", err
	}
	if filepath.Clean(current) != filepath.Clean(template.GenerationDir) {
		return "", "", fmt.Errorf("certificate generation pointer does not select persisted generation")
	}
	keyPath := filepath.Join(template.GenerationDir, generationKeyName)
	certPath := filepath.Join(template.GenerationDir, generationCertName)
	for _, path := range []string{keyPath, certPath} {
		info, err := os.Lstat(path)
		if err != nil {
			return "", "", err
		}
		if !info.Mode().IsRegular() {
			return "", "", fmt.Errorf("generation artifact %s is not a regular file", path)
		}
	}
	return keyPath, certPath, nil
}

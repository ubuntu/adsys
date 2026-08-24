package certificate

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type lifecycleFake struct {
	mu             sync.Mutex
	t              *testing.T
	caCert         *x509.Certificate
	caKey          *ecdsa.PrivateKey
	submitResponse Response
	pollResponse   Response
	submitErr      error
	pollErr        error
	autoIssue      bool
	csrPEM         string
	submits        int
	polls          int
}

func (fake *lifecycleFake) requester() Requester {
	return RequesterFunc(func(_ context.Context, request Request) (Response, error) {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		if request.Submit != nil {
			fake.submits++
			fake.csrPEM = request.Submit.CSRPEM
			return cloneResponse(fake.submitResponse), fake.submitErr
		}
		fake.polls++
		response := cloneResponse(fake.pollResponse)
		if fake.autoIssue && response.Disposition == DispositionIssued && len(response.CertificateDER) == 0 {
			certificatePEM := mgrIssueFromCSR(fake.t, fake.csrPEM, time.Now().Add(365*24*time.Hour), fake.caCert, fake.caKey)
			response.CertificateDER = certificateDER(fake.t, certificatePEM)
		}
		return response, fake.pollErr
	})
}

func cloneResponse(response Response) Response {
	response.CertificateDER = append([]byte(nil), response.CertificateDER...)
	return response
}

func certificateDER(t *testing.T, certificatePEM string) []byte {
	t.Helper()
	block, rest := pem.Decode([]byte(certificatePEM))
	require.NotNil(t, block)
	require.Empty(t, rest)
	return block.Bytes
}

func lifecycleManager(t *testing.T, stateDir, trustDir string, caDER []byte, requester Requester) *Manager {
	t.Helper()
	return mgrManager(t, stateDir, trustDir,
		WithLDAPConnector(mgrConnector("CN=Configuration,DC=example,DC=com", []string{"Machine"}, caDER)),
		WithCertificateRequester(requester),
	)
}

func TestPendingSubmitPollAndIssueAcrossRestart(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	trustDir := filepath.Join(t.TempDir(), "trust")
	caCert, caKey, caDER := mgrTestCA(t)
	fake := &lifecycleFake{
		t:      t,
		caCert: caCert,
		caKey:  caKey,
		submitResponse: Response{
			Disposition: DispositionPending,
			RequestID:   41,
		},
		pollResponse: Response{
			Disposition: DispositionPending,
			RequestID:   41,
		},
		autoIssue: true,
	}

	manager := lifecycleManager(t, stateDir, trustDir, caDER, fake.requester())
	err := manager.enroll(context.Background(), mgrTestObject)
	require.ErrorIs(t, err, ErrEnrollmentPending)

	state, err := loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	require.Empty(t, state.CAs)
	require.Len(t, state.Pending, 1)
	first := state.Pending[0]
	assert.Equal(t, uint32(41), first.RequestID)
	assert.Equal(t, "ca.example.com", first.Server)
	assert.Equal(t, "TestCA", first.CAName)
	assert.Equal(t, "Machine", first.Template)
	assert.False(t, first.CreatedAt.IsZero())
	assert.True(t, first.LastPolledAt.IsZero())
	keyBefore, err := os.ReadFile(first.KeyFile)
	require.NoError(t, err)
	csrBefore, err := os.ReadFile(first.CSRFile)
	require.NoError(t, err)
	for _, path := range []string{first.KeyFile, first.CSRFile} {
		info, err := os.Lstat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	}
	info, err := os.Lstat(filepath.Dir(first.KeyFile))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), info.Mode().Perm())
	stateInfo, err := os.Lstat(stateFilePath(stateDir, mgrTestObject))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), stateInfo.Mode().Perm())

	// A new Manager instance polls the exact persisted request and does not
	// submit or generate another key while the CA still reports pending.
	manager = lifecycleManager(t, stateDir, trustDir, caDER, fake.requester())
	err = manager.enroll(context.Background(), mgrTestObject)
	require.ErrorIs(t, err, ErrEnrollmentPending)
	state, err = loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	require.Len(t, state.Pending, 1)
	second := state.Pending[0]
	assert.Equal(t, first.RequestID, second.RequestID)
	assert.Equal(t, first.KeyFile, second.KeyFile)
	assert.Equal(t, first.CSRFile, second.CSRFile)
	assert.Equal(t, first.CreatedAt, second.CreatedAt)
	assert.False(t, second.LastPolledAt.IsZero())
	assert.Equal(t, keyBefore, mustReadFile(t, second.KeyFile))
	assert.Equal(t, csrBefore, mustReadFile(t, second.CSRFile))
	assert.Equal(t, 1, fake.submits)
	assert.Equal(t, 1, fake.polls)

	fake.mu.Lock()
	fake.pollResponse = Response{Disposition: DispositionIssued, RequestID: 41}
	fake.mu.Unlock()
	manager = lifecycleManager(t, stateDir, trustDir, caDER, fake.requester())
	require.NoError(t, manager.enroll(context.Background(), mgrTestObject))

	state, err = loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	require.Empty(t, state.Pending)
	require.Len(t, state.CAs, 1)
	require.Len(t, state.CAs[0].Templates, 1)
	issued := state.CAs[0].Templates[0]
	assert.Equal(t, filepath.Join(issued.GenerationRoot, "current", generationKeyName), issued.KeyFile)
	assert.Equal(t, filepath.Join(issued.GenerationRoot, "current", generationCertName), issued.CertFile)
	assert.FileExists(t, issued.KeyFile)
	assert.FileExists(t, issued.CertFile)
	assert.NoFileExists(t, first.KeyFile)
	assert.NoFileExists(t, first.CSRFile)
	certificate := parseTemplateCert(issued)
	require.NotNil(t, certificate)
	match, err := publicKeysMatch(certificate, issued)
	require.NoError(t, err)
	assert.True(t, match)
	assert.Equal(t, 1, fake.submits)
	assert.Equal(t, 2, fake.polls)
}

func TestTerminalPendingCleanupErrorDoesNotSkipAdjacentRequest(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	trustDir := filepath.Join(t.TempDir(), "trust")
	caCert, _, caDER := mgrTestCA(t)
	rootFile := mgrWriteCACertificate(t, stateDir, "pending-root.crt", caDER)
	fingerprint := certificateFingerprint(caCert)
	identity, err := enrollmentMachineIdentity(mgrTestObject, mgrTestDomain)
	require.NoError(t, err)

	makePending := func(template, nickname string, requestID uint32) pendingEnrollment {
		target := enrollmentTarget{
			ObjectName:     mgrTestObject,
			Domain:         mgrTestDomain,
			Identity:       identity.dnsName,
			CAName:         "TestCA",
			Server:         "ca.example.com",
			Template:       template,
			Nickname:       nickname,
			GenerationRoot: filepath.Join(stateDir, "private", "certs", nickname),
			Binding: templateChainBinding{
				IssuerFingerprint: fingerprint,
				Fingerprints:      []string{fingerprint},
				Files:             []string{rootFile},
			},
			RootCerts: []string{rootFile},
		}
		draft, err := createEnrollmentDraft(stateDir, target, 2048)
		require.NoError(t, err)
		return newPendingEnrollment(target, draft, requestID)
	}
	first := makePending("Machine", "TestCA.Machine", 301)
	second := makePending("WebServer", "TestCA.WebServer", 302)
	state := &enrollmentState{
		ObjectName: mgrTestObject,
		Identity:   identity.dnsName,
		Domain:     mgrTestDomain,
		Pending:    []pendingEnrollment{first, second},
	}
	require.NoError(t, saveState(stateDir, state))

	var polled []uint32
	requester := RequesterFunc(func(_ context.Context, request Request) (Response, error) {
		require.NotNil(t, request.Poll)
		polled = append(polled, request.Poll.RequestID)
		if request.Poll.RequestID == first.RequestID {
			return Response{Disposition: DispositionDenied, RequestID: first.RequestID}, nil
		}
		return Response{Disposition: DispositionPending, RequestID: second.RequestID}, nil
	})
	manager := lifecycleManager(t, stateDir, trustDir, caDER, requester)
	removePending := manager.removePending
	manager.removePending = func(stateDir string, pending pendingEnrollment) error {
		if pending.RequestID == first.RequestID {
			return errors.New("injected post-save pending cleanup failure")
		}
		return removePending(stateDir, pending)
	}

	summary := manager.pollPendingEnrollments(context.Background(), state, nil, nil)
	assert.Equal(t, []uint32{first.RequestID, second.RequestID}, polled)
	assert.Equal(t, 1, summary.Pending)
	require.Len(t, state.Pending, 1)
	assert.Equal(t, second.RequestID, state.Pending[0].RequestID)
	assert.False(t, state.Pending[0].LastPolledAt.IsZero())
	assert.ErrorContains(t, errors.Join(summary.Errors...), "injected post-save pending cleanup failure")

	persisted, err := loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	require.Len(t, persisted.Pending, 1)
	assert.Equal(t, second.RequestID, persisted.Pending[0].RequestID)
	assert.False(t, persisted.Pending[0].LastPolledAt.IsZero())
}

func TestPendingRenewalPreservesOldGenerationUntilIssued(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	trustDir := filepath.Join(t.TempDir(), "trust")
	caCert, caKey, caDER := mgrTestCA(t)
	var csr string
	requester := RequesterFunc(func(_ context.Context, request Request) (Response, error) {
		if request.Submit != nil {
			csr = request.Submit.CSRPEM
			certificatePEM := mgrIssueFromCSR(t, csr, time.Now().Add(365*24*time.Hour), caCert, caKey)
			return Response{Disposition: DispositionIssued, RequestID: 9, CertificateDER: certificateDER(t, certificatePEM)}, nil
		}
		return Response{}, errors.New("unexpected poll")
	})
	manager := lifecycleManager(t, stateDir, trustDir, caDER, requester)
	require.NoError(t, manager.enroll(context.Background(), mgrTestObject))
	state, err := loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	old := state.CAs[0].Templates[0]
	oldKey := mustReadFile(t, old.KeyFile)
	oldCert := mustReadFile(t, old.CertFile)

	pollMalformed := false
	requester = RequesterFunc(func(_ context.Context, request Request) (Response, error) {
		if request.Submit != nil {
			csr = request.Submit.CSRPEM
			return Response{Disposition: DispositionPending, RequestID: 77}, nil
		}
		if pollMalformed {
			return Response{Disposition: DispositionIssued, RequestID: 77}, nil
		}
		certificatePEM := mgrIssueFromCSR(t, csr, time.Now().Add(365*24*time.Hour), caCert, caKey)
		return Response{Disposition: DispositionIssued, RequestID: 77, CertificateDER: certificateDER(t, certificatePEM)}, nil
	})
	manager = lifecycleManager(t, stateDir, trustDir, caDER, requester)
	err = manager.RenewCertificates(context.Background(), mgrTestObject, old.Nickname, false, nil)
	require.ErrorIs(t, err, ErrEnrollmentPending)
	state, err = loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	require.Len(t, state.Pending, 1)
	assert.Equal(t, oldKey, mustReadFile(t, old.KeyFile))
	assert.Equal(t, oldCert, mustReadFile(t, old.CertFile))

	pollMalformed = true
	manager = lifecycleManager(t, stateDir, trustDir, caDER, requester)
	require.ErrorContains(t, manager.RenewCertificates(context.Background(), mgrTestObject, old.Nickname, false, nil), "empty certificate")
	state, err = loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	require.Len(t, state.Pending, 1)
	assert.Equal(t, oldKey, mustReadFile(t, old.KeyFile))
	assert.Equal(t, oldCert, mustReadFile(t, old.CertFile))

	pollMalformed = false
	manager = lifecycleManager(t, stateDir, trustDir, caDER, requester)
	require.NoError(t, manager.RenewCertificates(context.Background(), mgrTestObject, old.Nickname, false, nil))
	state, err = loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	require.Empty(t, state.Pending)
	renewed := state.CAs[0].Templates[0]
	assert.Equal(t, old.KeyFile, renewed.KeyFile)
	assert.Equal(t, old.CertFile, renewed.CertFile)
	assert.NotEqual(t, old.GenerationDir, renewed.GenerationDir)
	assert.NotEqual(t, oldKey, mustReadFile(t, renewed.KeyFile))
	assert.NotEqual(t, oldCert, mustReadFile(t, renewed.CertFile))
	assert.NoDirExists(t, old.GenerationDir)
}

func TestIssuedPendingCleanupSurvivesGenerationFinalizationFailure(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	trustDir := filepath.Join(t.TempDir(), "trust")
	caCert, caKey, caDER := mgrTestCA(t)
	requester := RequesterFunc(func(_ context.Context, request Request) (Response, error) {
		require.NotNil(t, request.Submit)
		certificatePEM := mgrIssueFromCSR(t, request.Submit.CSRPEM, time.Now().Add(365*24*time.Hour), caCert, caKey)
		return Response{Disposition: DispositionIssued, RequestID: 9, CertificateDER: certificateDER(t, certificatePEM)}, nil
	})
	manager := lifecycleManager(t, stateDir, trustDir, caDER, requester)
	require.NoError(t, manager.enroll(context.Background(), mgrTestObject))
	state, err := loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	old := state.CAs[0].Templates[0]

	var csr string
	requester = RequesterFunc(func(_ context.Context, request Request) (Response, error) {
		if request.Submit != nil {
			csr = request.Submit.CSRPEM
			return Response{Disposition: DispositionPending, RequestID: 77}, nil
		}
		certificatePEM := mgrIssueFromCSR(t, csr, time.Now().Add(365*24*time.Hour), caCert, caKey)
		return Response{Disposition: DispositionIssued, RequestID: 77, CertificateDER: certificateDER(t, certificatePEM)}, nil
	})
	manager = lifecycleManager(t, stateDir, trustDir, caDER, requester)
	require.ErrorIs(t, manager.RenewCertificates(context.Background(), mgrTestObject, old.Nickname, false, nil), ErrEnrollmentPending)
	state, err = loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	require.Len(t, state.Pending, 1)
	pending := state.Pending[0]

	manager = lifecycleManager(t, stateDir, trustDir, caDER, requester)
	remove := manager.generationOps.remove
	manager.generationOps.remove = func(path string) error {
		if filepath.Base(path) == generationMarker {
			return errors.New("injected generation marker remove failure")
		}
		return remove(path)
	}
	removePending := manager.removePending
	manager.removePending = func(stateDir string, pending pendingEnrollment) error {
		return errors.Join(
			removePending(stateDir, pending),
			errors.New("injected post-cleanup pending error"),
		)
	}

	err = manager.RenewCertificates(context.Background(), mgrTestObject, old.Nickname, false, nil)
	require.ErrorContains(t, err, "injected generation marker remove failure")
	require.ErrorContains(t, err, "injected post-cleanup pending error")

	state, err = loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	require.Empty(t, state.Pending)
	require.Len(t, state.CAs, 1)
	require.Len(t, state.CAs[0].Templates, 1)
	renewed := state.CAs[0].Templates[0]
	assert.NotEqual(t, old.GenerationDir, renewed.GenerationDir)
	assert.FileExists(t, renewed.KeyFile)
	assert.FileExists(t, renewed.CertFile)
	assert.NoFileExists(t, pending.KeyFile)
	assert.NoFileExists(t, pending.CSRFile)
	assert.NoDirExists(t, filepath.Dir(pending.KeyFile))
	assert.FileExists(t, filepath.Join(renewed.GenerationDir, generationMarker))
	assert.DirExists(t, old.GenerationDir)

	require.NoError(t, reconcileGenerationPublications(stateDir, defaultGenerationPublishOps()))
	assert.NoFileExists(t, filepath.Join(renewed.GenerationDir, generationMarker))
	assert.NoDirExists(t, old.GenerationDir)
	reconciled, err := loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	require.Empty(t, reconciled.Pending)
	assert.Equal(t, renewed.GenerationDir, reconciled.CAs[0].Templates[0].GenerationDir)
}

func TestDeniedPendingRenewalPreservesOldGeneration(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	trustDir := filepath.Join(t.TempDir(), "trust")
	caCert, caKey, caDER := mgrTestCA(t)
	stage := 0
	requester := RequesterFunc(func(_ context.Context, request Request) (Response, error) {
		if request.Submit != nil {
			stage++
			if stage == 2 {
				return Response{Disposition: DispositionPending, RequestID: 88}, nil
			}
			certificatePEM := mgrIssueFromCSR(t, request.Submit.CSRPEM, time.Now().Add(365*24*time.Hour), caCert, caKey)
			return Response{Disposition: DispositionIssued, RequestID: 7, CertificateDER: certificateDER(t, certificatePEM)}, nil
		}
		return Response{
			Disposition: DispositionDenied,
			RequestID:   88,
			Message:     "approval denied",
		}, nil
	})
	manager := lifecycleManager(t, stateDir, trustDir, caDER, requester)
	require.NoError(t, manager.enroll(context.Background(), mgrTestObject))
	state, err := loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	old := state.CAs[0].Templates[0]
	oldKey := mustReadFile(t, old.KeyFile)
	oldCert := mustReadFile(t, old.CertFile)

	require.ErrorIs(t, manager.RenewCertificates(context.Background(), mgrTestObject, old.Nickname, false, nil), ErrEnrollmentPending)
	err = manager.RenewCertificates(context.Background(), mgrTestObject, old.Nickname, false, nil)
	require.ErrorContains(t, err, "approval denied")
	state, err = loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	assert.Empty(t, state.Pending)
	require.Len(t, state.CAs, 1)
	assert.Equal(t, oldKey, mustReadFile(t, old.KeyFile))
	assert.Equal(t, oldCert, mustReadFile(t, old.CertFile))
	assert.DirExists(t, old.GenerationDir)
}

func TestInitialRequestFailuresLeaveNoDraftOrState(t *testing.T) {
	tests := map[string]struct {
		response Response
		err      error
		want     string
	}{
		"transport": {
			err:  errors.New("RPC transport failed"),
			want: "RPC transport failed",
		},
		"denied": {
			response: Response{Disposition: DispositionDenied, RequestID: 12, Message: "policy denied"},
			want:     "request denied",
		},
		"revoked": {
			response: Response{Disposition: DispositionRevoked, RequestID: 12, Message: "request revoked"},
			want:     "request revoked",
		},
		"issued out of band without certificate": {
			response: Response{Disposition: DispositionIssuedOutOfBand, RequestID: 12},
			want:     "issued out of band without a usable certificate",
		},
		"unknown disposition": {
			response: Response{Disposition: 99, RequestID: 12},
			want:     "unknown disposition",
		},
		"pending without ID": {
			response: Response{Disposition: DispositionPending},
			want:     "pending disposition with request ID 0",
		},
		"empty issued certificate": {
			response: Response{Disposition: DispositionIssued, RequestID: 12},
			want:     "empty certificate",
		},
		"malformed issued certificate": {
			response: Response{Disposition: DispositionIssued, RequestID: 12, CertificateDER: []byte("not DER")},
			want:     "parsing encoded certificate",
		},
		"oversized issued certificate": {
			response: Response{Disposition: DispositionIssued, RequestID: 12, CertificateDER: make([]byte, maxIssuedCertBytes+1)},
			want:     "oversized certificate",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), "state")
			trustDir := filepath.Join(t.TempDir(), "trust")
			_, _, caDER := mgrTestCA(t)
			requester := RequesterFunc(func(_ context.Context, request Request) (Response, error) {
				require.NotNil(t, request.Submit)
				return cloneResponse(test.response), test.err
			})
			manager := lifecycleManager(t, stateDir, trustDir, caDER, requester)
			err := manager.enroll(context.Background(), mgrTestObject)
			require.ErrorContains(t, err, test.want)
			state, loadErr := loadState(stateDir, mgrTestObject, mgrTestDomain)
			require.NoError(t, loadErr)
			assert.Nil(t, state)
			drafts, globErr := filepath.Glob(filepath.Join(stateDir, "private", "certs", "pending", "*"))
			require.NoError(t, globErr)
			assert.Empty(t, drafts)
		})
	}
}

func TestIssuedOutOfBandAcceptedOnlyWhenFullyVerifiable(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	trustDir := filepath.Join(t.TempDir(), "trust")
	caCert, caKey, caDER := mgrTestCA(t)
	requester := RequesterFunc(func(_ context.Context, request Request) (Response, error) {
		require.NotNil(t, request.Submit)
		certificatePEM := mgrIssueFromCSR(t, request.Submit.CSRPEM, time.Now().Add(24*time.Hour), caCert, caKey)
		return Response{
			Disposition:    DispositionIssuedOutOfBand,
			RequestID:      15,
			CertificateDER: certificateDER(t, certificatePEM),
		}, nil
	})
	manager := lifecycleManager(t, stateDir, trustDir, caDER, requester)
	require.NoError(t, manager.enroll(context.Background(), mgrTestObject))
	state, err := loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	require.Len(t, state.CAs, 1)
	assert.Empty(t, state.Pending)
}

func TestPollTerminalAndMalformedResponses(t *testing.T) {
	tests := map[string]struct {
		response       Response
		pollErr        error
		want           string
		terminal       bool
		wantCanceled   bool
		mismatchedLeaf bool
	}{
		"denied": {
			response: Response{Disposition: DispositionDenied, RequestID: 64, Message: "Denied\nby policy"},
			want:     "Denied by policy",
			terminal: true,
		},
		"revoked": {
			response: Response{Disposition: DispositionRevoked, RequestID: 64, Message: "administratively revoked"},
			want:     "request revoked",
			terminal: true,
		},
		"issued out of band without certificate": {
			response: Response{Disposition: DispositionIssuedOutOfBand, RequestID: 64},
			want:     "issued out of band without a usable certificate",
			terminal: true,
		},
		"transport": {
			pollErr: errors.New("connection reset"),
			want:    "connection reset",
		},
		"cancellation": {
			pollErr:      context.Canceled,
			want:         "context canceled",
			wantCanceled: true,
		},
		"unknown disposition": {
			response: Response{Disposition: 99, RequestID: 64},
			want:     "unknown disposition",
		},
		"pending zero ID": {
			response: Response{Disposition: DispositionPending},
			want:     "pending disposition with request ID 0",
		},
		"changed request ID": {
			response: Response{Disposition: DispositionPending, RequestID: 65},
			want:     "instead of 64",
		},
		"empty issued certificate": {
			response: Response{Disposition: DispositionIssued, RequestID: 64},
			want:     "empty certificate",
		},
		"malformed issued certificate": {
			response: Response{Disposition: DispositionIssued, RequestID: 64, CertificateDER: []byte("bad DER")},
			want:     "parsing encoded certificate",
		},
		"oversized issued certificate": {
			response: Response{Disposition: DispositionIssued, RequestID: 64, CertificateDER: make([]byte, maxIssuedCertBytes+1)},
			want:     "oversized certificate",
		},
		"mismatched issued certificate": {
			response:       Response{Disposition: DispositionIssued, RequestID: 64},
			want:           "does not match",
			mismatchedLeaf: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), "state")
			trustDir := filepath.Join(t.TempDir(), "trust")
			caCert, caKey, caDER := mgrTestCA(t)
			fake := &lifecycleFake{
				t:      t,
				caCert: caCert,
				caKey:  caKey,
				submitResponse: Response{
					Disposition: DispositionPending,
					RequestID:   64,
				},
			}
			manager := lifecycleManager(t, stateDir, trustDir, caDER, fake.requester())
			require.ErrorIs(t, manager.enroll(context.Background(), mgrTestObject), ErrEnrollmentPending)
			state, err := loadState(stateDir, mgrTestObject, mgrTestDomain)
			require.NoError(t, err)
			pending := state.Pending[0]
			keyBefore := mustReadFile(t, pending.KeyFile)
			csrBefore := mustReadFile(t, pending.CSRFile)

			response := cloneResponse(test.response)
			if test.mismatchedLeaf {
				otherKey, keyErr := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, keyErr)
				mismatchedPEM := mgrCASignedLeafForIdentity(
					t, caCert, caKey, &otherKey.PublicKey, "keypress.example.com",
					time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour),
				)
				response.CertificateDER = certificateDER(t, string(mismatchedPEM))
			}
			fake.mu.Lock()
			fake.pollResponse = response
			fake.pollErr = test.pollErr
			fake.mu.Unlock()
			manager = lifecycleManager(t, stateDir, trustDir, caDER, fake.requester())
			err = manager.enroll(context.Background(), mgrTestObject)
			require.ErrorContains(t, err, test.want)
			if test.wantCanceled {
				assert.ErrorIs(t, err, context.Canceled)
			}

			state, loadErr := loadState(stateDir, mgrTestObject, mgrTestDomain)
			require.NoError(t, loadErr)
			if test.terminal {
				require.Empty(t, state.Pending)
				assert.NoFileExists(t, pending.KeyFile)
				assert.NoFileExists(t, pending.CSRFile)
				return
			}
			require.Len(t, state.Pending, 1)
			assert.Equal(t, uint32(64), state.Pending[0].RequestID)
			assert.Equal(t, keyBefore, mustReadFile(t, pending.KeyFile))
			assert.Equal(t, csrBefore, mustReadFile(t, pending.CSRFile))
		})
	}
}

func TestCorruptPendingMaterialFailsClosed(t *testing.T) {
	tests := map[string]func(*testing.T, string, *enrollmentState) string{
		"missing key": func(t *testing.T, _ string, state *enrollmentState) string {
			t.Helper()
			require.NoError(t, os.Remove(state.Pending[0].KeyFile))
			return ""
		},
		"symlinked key": func(t *testing.T, _ string, state *enrollmentState) string {
			t.Helper()
			outside := filepath.Join(t.TempDir(), "outside-key")
			require.NoError(t, os.WriteFile(outside, []byte("do not delete"), 0600))
			require.NoError(t, os.Remove(state.Pending[0].KeyFile))
			require.NoError(t, os.Symlink(outside, state.Pending[0].KeyFile))
			return outside
		},
		"out of root key": func(t *testing.T, stateDir string, state *enrollmentState) string {
			t.Helper()
			outside := filepath.Join(filepath.Dir(stateDir), "outside-key")
			require.NoError(t, os.WriteFile(outside, mustReadFile(t, state.Pending[0].KeyFile), 0600))
			state.Pending[0].KeyFile = outside
			state.Pending[0].MetadataFingerprint = pendingMetadataFingerprint(state.Pending[0])
			require.NoError(t, writeStateFile(stateFilePath(stateDir, mgrTestObject), state))
			return outside
		},
		"out of root chain": func(t *testing.T, stateDir string, state *enrollmentState) string {
			t.Helper()
			outside := filepath.Join(filepath.Dir(stateDir), "outside-chain")
			require.NoError(t, os.WriteFile(outside, mustReadFile(t, state.Pending[0].ChainFiles[0]), 0600))
			state.Pending[0].ChainFiles[0] = outside
			state.Pending[0].RootCerts[0] = outside
			state.Pending[0].MetadataFingerprint = pendingMetadataFingerprint(state.Pending[0])
			require.NoError(t, writeStateFile(stateFilePath(stateDir, mgrTestObject), state))
			return outside
		},
		"corrupt CSR": func(t *testing.T, _ string, state *enrollmentState) string {
			t.Helper()
			require.NoError(t, os.WriteFile(state.Pending[0].CSRFile, []byte("not a CSR"), 0600))
			return ""
		},
		"key fingerprint mismatch": func(t *testing.T, stateDir string, state *enrollmentState) string {
			t.Helper()
			state.Pending[0].KeyFingerprint = "00"
			state.Pending[0].MetadataFingerprint = pendingMetadataFingerprint(state.Pending[0])
			require.NoError(t, writeStateFile(stateFilePath(stateDir, mgrTestObject), state))
			return ""
		},
		"CA metadata mismatch": func(t *testing.T, stateDir string, state *enrollmentState) string {
			t.Helper()
			state.Pending[0].CAName = "OtherCA"
			require.NoError(t, writeStateFile(stateFilePath(stateDir, mgrTestObject), state))
			return ""
		},
		"domain mismatch": func(t *testing.T, stateDir string, state *enrollmentState) string {
			t.Helper()
			state.Pending[0].Domain = "other.example"
			state.Pending[0].MetadataFingerprint = pendingMetadataFingerprint(state.Pending[0])
			require.NoError(t, writeStateFile(stateFilePath(stateDir, mgrTestObject), state))
			return ""
		},
	}

	for name, corrupt := range tests {
		t.Run(name, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), "state")
			trustDir := filepath.Join(t.TempDir(), "trust")
			caCert, caKey, caDER := mgrTestCA(t)
			fake := &lifecycleFake{
				t: t, caCert: caCert, caKey: caKey,
				submitResponse: Response{Disposition: DispositionPending, RequestID: 81},
				pollResponse:   Response{Disposition: DispositionPending, RequestID: 81},
			}
			manager := lifecycleManager(t, stateDir, trustDir, caDER, fake.requester())
			require.ErrorIs(t, manager.enroll(context.Background(), mgrTestObject), ErrEnrollmentPending)
			state, err := loadState(stateDir, mgrTestObject, mgrTestDomain)
			require.NoError(t, err)
			outside := corrupt(t, stateDir, state)

			manager = lifecycleManager(t, stateDir, trustDir, caDER, fake.requester())
			err = manager.enroll(context.Background(), mgrTestObject)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "validating pending request")
			assert.Zero(t, fake.polls, "invalid local state must be rejected before RPC")
			persisted, loadErr := loadState(stateDir, mgrTestObject, mgrTestDomain)
			require.NoError(t, loadErr)
			require.Len(t, persisted.Pending, 1)
			if outside != "" {
				assert.FileExists(t, outside)
				removeErr := manager.RemoveCertificates(context.Background(), mgrTestObject, "", true, true, nil)
				if name == "out of root key" || name == "out of root chain" || name == "symlinked key" {
					require.Error(t, removeErr)
				}
				assert.FileExists(t, outside, "explicit removal must not delete a tampered external target")
				removed, stateErr := loadState(stateDir, mgrTestObject, mgrTestDomain)
				require.NoError(t, stateErr)
				assert.Nil(t, removed)
			}
		})
	}
}

func TestTwoPendingTemplatesPollIndependentlyAndRemoveOnlyTarget(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	trustDir := filepath.Join(t.TempDir(), "trust")
	caCert, caKey, caDER := mgrTestCA(t)
	var mu sync.Mutex
	nextID := uint32(100)
	csrs := make(map[uint32]string)
	templates := make(map[uint32]string)
	submits := 0
	polls := 0
	requester := RequesterFunc(func(_ context.Context, request Request) (Response, error) {
		mu.Lock()
		defer mu.Unlock()
		if request.Submit != nil {
			nextID++
			submits++
			csrs[nextID] = request.Submit.CSRPEM
			templates[nextID] = request.Submit.Template
			return Response{Disposition: DispositionPending, RequestID: nextID}, nil
		}
		polls++
		if templates[request.Poll.RequestID] == "WebServer" {
			return Response{}, errors.New("temporary poll failure")
		}
		certificatePEM := mgrIssueFromCSR(t, csrs[request.Poll.RequestID], time.Now().Add(24*time.Hour), caCert, caKey)
		return Response{
			Disposition:    DispositionIssued,
			RequestID:      request.Poll.RequestID,
			CertificateDER: certificateDER(t, certificatePEM),
		}, nil
	})
	manager := mgrManager(t, stateDir, trustDir,
		WithLDAPConnector(mgrConnector("CN=Configuration,DC=example,DC=com", []string{"Machine", "WebServer"}, caDER)),
		WithCertificateRequester(requester),
	)
	require.ErrorIs(t, manager.enroll(context.Background(), mgrTestObject), ErrEnrollmentPending)
	state, err := loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	require.Len(t, state.Pending, 2)
	assert.NotEqual(t, state.Pending[0].RequestID, state.Pending[1].RequestID)
	assert.NotEqual(t, state.Pending[0].KeyFile, state.Pending[1].KeyFile)
	pendingPaths := map[string][2]string{}
	for _, pending := range state.Pending {
		pendingPaths[pending.Template] = [2]string{pending.KeyFile, pending.CSRFile}
	}

	err = manager.RenewCertificates(context.Background(), mgrTestObject, "", true, nil)
	require.ErrorContains(t, err, "temporary poll failure")
	state, err = loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	require.Len(t, state.CAs, 1)
	require.Len(t, state.CAs[0].Templates, 1)
	assert.Equal(t, "Machine", state.CAs[0].Templates[0].Template)
	require.Len(t, state.Pending, 1)
	assert.Equal(t, "WebServer", state.Pending[0].Template)
	assert.Equal(t, 2, submits)
	assert.Equal(t, 2, polls)
	assert.NoFileExists(t, pendingPaths["Machine"][0])
	assert.NoFileExists(t, pendingPaths["Machine"][1])
	assert.FileExists(t, pendingPaths["WebServer"][0])
	assert.FileExists(t, pendingPaths["WebServer"][1])

	require.NoError(t, manager.RemoveCertificates(context.Background(), mgrTestObject, state.Pending[0].Nickname, false, true, nil))
	state, err = loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	require.Len(t, state.CAs, 1)
	assert.Empty(t, state.Pending)
	assert.FileExists(t, state.CAs[0].Templates[0].KeyFile)
	assert.FileExists(t, state.CAs[0].Templates[0].CertFile)
	assert.NoFileExists(t, pendingPaths["WebServer"][0])
	assert.NoFileExists(t, pendingPaths["WebServer"][1])
}

func TestPendingObjectRemovalDoesNotCrossState(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	trustDir := filepath.Join(t.TempDir(), "trust")
	_, _, caDER := mgrTestCA(t)
	var mu sync.Mutex
	nextID := uint32(200)
	requester := RequesterFunc(func(_ context.Context, request Request) (Response, error) {
		mu.Lock()
		defer mu.Unlock()
		if request.Submit == nil {
			return Response{Disposition: DispositionPending, RequestID: request.Poll.RequestID}, nil
		}
		nextID++
		return Response{Disposition: DispositionPending, RequestID: nextID}, nil
	})
	first := mgrManager(t, stateDir, trustDir,
		WithLDAPConnector(mgrConnector("CN=Configuration,DC=example,DC=com", []string{"Machine"}, caDER)),
		WithCertificateRequester(requester),
	)
	require.ErrorIs(t, first.enroll(context.Background(), mgrTestObject), ErrEnrollmentPending)
	firstState, err := loadState(stateDir, mgrTestObject, mgrTestDomain)
	require.NoError(t, err)
	firstPending := firstState.Pending[0]

	secondObject := "other"
	secondIdentity := machineDirectoryIdentity{
		shortName:      secondObject,
		samAccountName: secondObject + "$",
		dnsName:        secondObject + "." + mgrTestDomain,
	}
	second := mgrManager(t, stateDir, trustDir,
		WithLDAPConnector(mgrConnectorForIdentity(secondIdentity, []mgrDirectoryCA{{
			name: "TestCA", hostname: "ca.example.com", templates: []string{"Machine"}, der: caDER,
		}})),
		WithCertificateRequester(requester),
	)
	require.ErrorIs(t, second.enroll(context.Background(), secondObject), ErrEnrollmentPending)
	secondState, err := loadState(stateDir, secondObject, mgrTestDomain)
	require.NoError(t, err)
	secondPending := secondState.Pending[0]
	assert.NotEqual(t, firstPending.KeyFile, secondPending.KeyFile)

	require.NoError(t, first.RemoveCertificates(context.Background(), mgrTestObject, "", true, true, nil))
	assert.NoFileExists(t, firstPending.KeyFile)
	assert.NoFileExists(t, firstPending.CSRFile)
	assert.FileExists(t, secondPending.KeyFile)
	assert.FileExists(t, secondPending.CSRFile)
	stillPresent, err := loadState(stateDir, secondObject, mgrTestDomain)
	require.NoError(t, err)
	require.Len(t, stillPresent.Pending, 1)
	assert.Equal(t, secondPending.RequestID, stillPresent.Pending[0].RequestID)
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

package certificate

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
)

type enrollmentTarget struct {
	ObjectName        string
	Domain            string
	Identity          string
	CAName            string
	Server            string
	Template          string
	Nickname          string
	GenerationRoot    string
	Binding           templateChainBinding
	RootCerts         []string
	IntermediateCerts []string
	Symlinks          []string
	Renewal           bool
}

const maxPendingMaterialBytes = 1 << 20

type enrollmentDraft struct {
	Directory      string
	KeyFile        string
	CSRFile        string
	KeyPEM         []byte
	CSRPEM         string
	KeyFingerprint string
}

func createEnrollmentDraft(stateDir string, target enrollmentTarget, keySize int) (enrollmentDraft, error) {
	if keySize == 0 {
		keySize = 2048
	}
	keyPEM, csrPEM, err := generateKeyAndCSR(target.Identity, keySize)
	if err != nil {
		return enrollmentDraft{}, err
	}
	fingerprint, err := keyPublicFingerprint(keyPEM)
	if err != nil {
		return enrollmentDraft{}, err
	}

	root := filepath.Join(stateDir, "private", "certs", "pending")
	if err := ensurePrivateDirectory(root); err != nil {
		return enrollmentDraft{}, err
	}
	targetDigest := sha256.Sum256([]byte(strings.Join([]string{
		target.ObjectName, target.Domain, target.Identity, target.CAName, target.Server, target.Template,
	}, "\x00")))
	directory, err := os.MkdirTemp(root, fmt.Sprintf("%x-", targetDigest[:8]))
	if err != nil {
		return enrollmentDraft{}, fmt.Errorf("creating pending enrollment directory: %w", err)
	}
	if err := syncDirectory(root); err != nil {
		cleanupErr := removeDraftPaths(enrollmentDraft{Directory: directory})
		return enrollmentDraft{}, errors.Join(
			fmt.Errorf("syncing pending enrollment directory entry: %w", err),
			cleanupErr,
		)
	}
	if err := os.Chmod(directory, 0700); err != nil { //nolint:gosec // This is a directory; 0700 is the required private mode.
		cleanupErr := removeDraftPaths(enrollmentDraft{Directory: directory})
		return enrollmentDraft{}, errors.Join(
			fmt.Errorf("securing pending enrollment directory: %w", err),
			cleanupErr,
		)
	}
	draft := enrollmentDraft{
		Directory:      directory,
		KeyFile:        filepath.Join(directory, "private.key"),
		CSRFile:        filepath.Join(directory, "request.csr"),
		KeyPEM:         keyPEM,
		CSRPEM:         csrPEM,
		KeyFingerprint: fingerprint,
	}
	if err := writeExclusiveSyncedFile(draft.KeyFile, draft.KeyPEM, 0600); err != nil {
		_ = removeDraftPaths(draft)
		return enrollmentDraft{}, fmt.Errorf("writing pending private key: %w", err)
	}
	if err := writeExclusiveSyncedFile(draft.CSRFile, []byte(draft.CSRPEM), 0600); err != nil {
		_ = removeDraftPaths(draft)
		return enrollmentDraft{}, fmt.Errorf("writing pending CSR: %w", err)
	}
	if err := syncDirectory(directory); err != nil {
		_ = removeDraftPaths(draft)
		return enrollmentDraft{}, fmt.Errorf("syncing pending enrollment material: %w", err)
	}
	if err := syncDirectory(root); err != nil {
		_ = removeDraftPaths(draft)
		return enrollmentDraft{}, fmt.Errorf("syncing pending enrollment directory: %w", err)
	}
	return draft, nil
}

func newPendingEnrollment(target enrollmentTarget, draft enrollmentDraft, requestID uint32) pendingEnrollment {
	pending := pendingEnrollment{
		ObjectName:         target.ObjectName,
		Domain:             normalizeDomainIdentity(target.Domain),
		Identity:           normalizeMachineIdentity(target.Identity),
		CAName:             target.CAName,
		Server:             target.Server,
		Template:           target.Template,
		Nickname:           target.Nickname,
		RequestID:          requestID,
		KeyFile:            draft.KeyFile,
		CSRFile:            draft.CSRFile,
		KeyFingerprint:     draft.KeyFingerprint,
		GenerationRoot:     target.GenerationRoot,
		IssuerFingerprint:  target.Binding.IssuerFingerprint,
		ChainFingerprints:  append([]string(nil), target.Binding.Fingerprints...),
		ChainFiles:         append([]string(nil), target.Binding.Files...),
		TrustAnchorSymlink: target.Binding.TrustAnchorSymlink,
		RootCerts:          append([]string(nil), target.RootCerts...),
		IntermediateCerts:  append([]string(nil), target.IntermediateCerts...),
		Symlinks:           append([]string(nil), target.Symlinks...),
		Renewal:            target.Renewal,
		CreatedAt:          time.Now().UTC(),
	}
	pending.MetadataFingerprint = pendingMetadataFingerprint(pending)
	return pending
}

func pendingMetadataFingerprint(pending pendingEnrollment) string {
	hash := sha256.New()
	write := func(value string) {
		hash.Write([]byte(value))
		hash.Write([]byte{0})
	}
	for _, value := range []string{
		pending.ObjectName,
		normalizeDomainIdentity(pending.Domain),
		normalizeMachineIdentity(pending.Identity),
		pending.CAName,
		strings.ToLower(pending.Server),
		pending.Template,
		pending.Nickname,
		fmt.Sprintf("%d", pending.RequestID),
		filepath.Clean(pending.KeyFile),
		filepath.Clean(pending.CSRFile),
		strings.ToLower(pending.KeyFingerprint),
		filepath.Clean(pending.GenerationRoot),
		strings.ToLower(pending.IssuerFingerprint),
		fmt.Sprintf("%t", pending.Renewal),
	} {
		write(value)
	}
	for _, values := range [][]string{
		pending.ChainFingerprints,
		pending.ChainFiles,
		pending.RootCerts,
		pending.IntermediateCerts,
		pending.Symlinks,
		{pending.TrustAnchorSymlink},
	} {
		write("[")
		for _, value := range values {
			write(value)
		}
		write("]")
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func validatePendingEnrollment(stateDir, globalTrustDir string, state *enrollmentState, pending pendingEnrollment, now time.Time) ([]byte, string, []*x509.Certificate, error) {
	if state == nil {
		return nil, "", nil, fmt.Errorf("pending enrollment has no owning state")
	}
	if pending.ObjectName != state.ObjectName ||
		normalizeDomainIdentity(pending.Domain) != normalizeDomainIdentity(state.Domain) ||
		normalizeMachineIdentity(pending.Identity) != normalizeMachineIdentity(state.Identity) {
		return nil, "", nil, fmt.Errorf("pending enrollment ownership does not match its state")
	}
	if pending.RequestID == 0 {
		return nil, "", nil, fmt.Errorf("pending enrollment has request ID 0")
	}
	if pending.CAName == "" || pending.Server == "" || pending.Template == "" || pending.Nickname == "" {
		return nil, "", nil, fmt.Errorf("pending enrollment target metadata is incomplete")
	}
	expectedFingerprint := pendingMetadataFingerprint(pending)
	if len(pending.MetadataFingerprint) != len(expectedFingerprint) ||
		subtle.ConstantTimeCompare([]byte(strings.ToLower(pending.MetadataFingerprint)), []byte(expectedFingerprint)) != 1 {
		return nil, "", nil, fmt.Errorf("pending enrollment metadata fingerprint does not match")
	}

	privateRoot := filepath.Join(stateDir, "private", "certs")
	if !pathWithin(privateRoot, pending.GenerationRoot) || filepath.Clean(pending.GenerationRoot) == filepath.Clean(privateRoot) {
		return nil, "", nil, fmt.Errorf("pending generation root %s is outside ADSys private state", pending.GenerationRoot)
	}
	keyPEM, err := readPendingRegularFile(privateRoot, pending.KeyFile)
	if err != nil {
		return nil, "", nil, fmt.Errorf("reading pending private key: %w", err)
	}
	csrPEM, err := readPendingRegularFile(privateRoot, pending.CSRFile)
	if err != nil {
		return nil, "", nil, fmt.Errorf("reading pending CSR: %w", err)
	}
	keyFingerprint, err := keyPublicFingerprint(keyPEM)
	if err != nil {
		return nil, "", nil, fmt.Errorf("validating pending private key: %w", err)
	}
	if !strings.EqualFold(keyFingerprint, pending.KeyFingerprint) {
		return nil, "", nil, fmt.Errorf("pending private key fingerprint %s does not match state %s", keyFingerprint, pending.KeyFingerprint)
	}
	csrFingerprint, csrIdentity, err := csrPublicFingerprint(csrPEM)
	if err != nil {
		return nil, "", nil, fmt.Errorf("validating pending CSR: %w", err)
	}
	if !strings.EqualFold(csrFingerprint, pending.KeyFingerprint) {
		return nil, "", nil, fmt.Errorf("pending CSR public key does not match private key")
	}
	if normalizeMachineIdentity(csrIdentity) != normalizeMachineIdentity(pending.Identity) {
		return nil, "", nil, fmt.Errorf("pending CSR identity %q does not match %q", csrIdentity, pending.Identity)
	}

	binding := templateChainBinding{
		IssuerFingerprint:  pending.IssuerFingerprint,
		Fingerprints:       append([]string(nil), pending.ChainFingerprints...),
		Files:              append([]string(nil), pending.ChainFiles...),
		TrustAnchorSymlink: pending.TrustAnchorSymlink,
	}
	if err := validateBindingShape(binding); err != nil {
		return nil, "", nil, fmt.Errorf("pending CA chain binding is invalid: %w", err)
	}
	chain := make([]*x509.Certificate, 0, len(binding.Files))
	for index, path := range binding.Files {
		if err := validateOwnedPendingPath(filepath.Join(stateDir, "certs"), path, false); err != nil {
			return nil, "", nil, fmt.Errorf("pending chain file %d is outside ADSys state: %w", index, err)
		}
		cert, err := readSingleCertificateFile(path)
		if err != nil {
			return nil, "", nil, fmt.Errorf("reading pending chain file %d: %w", index, err)
		}
		if !strings.EqualFold(certificateFingerprint(cert), binding.Fingerprints[index]) {
			return nil, "", nil, fmt.Errorf("pending chain file %d fingerprint does not match state", index)
		}
		chain = append(chain, cert)
	}
	if !strings.EqualFold(certificateFingerprint(chain[0]), binding.IssuerFingerprint) {
		return nil, "", nil, fmt.Errorf("pending issuing CA fingerprint does not match chain")
	}
	if err := verifyExactCAPath(chain, now); err != nil {
		return nil, "", nil, fmt.Errorf("pending exact CA chain is invalid: %w", err)
	}
	expectedRoots := []string{binding.Files[len(binding.Files)-1]}
	expectedIntermediates := append([]string(nil), binding.Files[:len(binding.Files)-1]...)
	if !slicesEqualPaths(pending.RootCerts, expectedRoots) ||
		!slicesEqualPaths(pending.IntermediateCerts, expectedIntermediates) {
		return nil, "", nil, fmt.Errorf("pending CA artifact lists do not match the exact chain")
	}
	if binding.TrustAnchorSymlink != "" {
		if err := validateOwnedPendingPath(globalTrustDir, binding.TrustAnchorSymlink, true); err != nil {
			return nil, "", nil, fmt.Errorf("pending trust-anchor symlink is outside ADSys trust state: %w", err)
		}
		if len(pending.Symlinks) != 1 || filepath.Clean(pending.Symlinks[0]) != filepath.Clean(binding.TrustAnchorSymlink) {
			return nil, "", nil, fmt.Errorf("pending trust-anchor artifact list does not match its binding")
		}
		if got := matchingTrustSymlink([]string{binding.TrustAnchorSymlink}, binding.Files[len(binding.Files)-1]); got == "" {
			return nil, "", nil, fmt.Errorf("pending trust-anchor symlink does not reference the bound root")
		}
	}
	return keyPEM, string(csrPEM), chain, nil
}

func readPendingRegularFile(root, path string) ([]byte, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if !pathWithin(rootAbs, pathAbs) || filepath.Clean(pathAbs) == filepath.Clean(rootAbs) {
		return nil, fmt.Errorf("path %s is outside %s", path, root)
	}
	relative, err := filepath.Rel(rootAbs, pathAbs)
	if err != nil {
		return nil, err
	}
	current := rootAbs
	rootInfo, err := os.Lstat(current)
	if err != nil {
		return nil, err
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("private state root is not a regular directory")
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return nil, err
		}
		if current != pathAbs {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("path component %s is not a regular directory", current)
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s is not a regular non-symlink file", current)
		}
		if info.Size() > maxPendingMaterialBytes {
			return nil, fmt.Errorf("%s exceeds the pending-material size limit", current)
		}
		if info.Mode().Perm()&0077 != 0 {
			return nil, fmt.Errorf("%s has insecure mode %04o", current, info.Mode().Perm())
		}
	}
	return os.ReadFile(pathAbs)
}

func keyPublicFingerprint(keyPEM []byte) (string, error) {
	block, rest := pem.Decode(keyPEM)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return "", fmt.Errorf("private key is not exactly one PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parsing private key: %w", err)
	}
	var publicKey any
	switch key := key.(type) {
	case *rsa.PrivateKey:
		publicKey = &key.PublicKey
	case *ecdsa.PrivateKey:
		publicKey = &key.PublicKey
	default:
		return "", fmt.Errorf("unsupported private key type %T", key)
	}
	return publicKeyFingerprint(publicKey)
}

func csrPublicFingerprint(csrPEM []byte) (string, string, error) {
	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return "", "", fmt.Errorf("CSR is not exactly one PEM certificate request")
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", "", err
	}
	if err := request.CheckSignature(); err != nil {
		return "", "", fmt.Errorf("CSR signature is invalid: %w", err)
	}
	fingerprint, err := publicKeyFingerprint(request.PublicKey)
	if err != nil {
		return "", "", err
	}
	return fingerprint, request.Subject.CommonName, nil
}

func publicKeyFingerprint(publicKey any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(der)
	return hex.EncodeToString(digest[:]), nil
}

func removeDraftPaths(draft enrollmentDraft) error {
	var errs []error
	ops := defaultGenerationPublishOps()
	for _, path := range []string{draft.CSRFile, draft.KeyFile, draft.Directory} {
		if path == "" {
			continue
		}
		if err := removePathAndSync(path, ops); err != nil {
			errs = append(errs, fmt.Errorf("removing enrollment draft %s: %w", path, err))
		}
	}
	return errors.Join(errs...)
}

func removePendingMaterial(stateDir string, pending pendingEnrollment) error {
	privateRoot := filepath.Join(stateDir, "private", "certs")
	for _, path := range []string{pending.KeyFile, pending.CSRFile} {
		if _, err := readPendingRegularFile(privateRoot, path); err != nil {
			return fmt.Errorf("refusing to remove unsafe pending path %s: %w", path, err)
		}
	}
	directory := filepath.Dir(pending.KeyFile)
	if filepath.Dir(pending.CSRFile) != directory || !pathWithin(filepath.Join(privateRoot, "pending"), directory) {
		return fmt.Errorf("pending key and CSR are not in one ADSys-owned directory")
	}
	return removeDraftPaths(enrollmentDraft{
		Directory: directory,
		KeyFile:   pending.KeyFile,
		CSRFile:   pending.CSRFile,
	})
}

func pendingReferencedPaths(pending pendingEnrollment) []string {
	paths := []string{pending.CSRFile, pending.KeyFile}
	if filepath.Dir(pending.KeyFile) == filepath.Dir(pending.CSRFile) {
		paths = append(paths, filepath.Dir(pending.KeyFile))
	}
	paths = append(paths, pending.ChainFiles...)
	paths = append(paths, pending.RootCerts...)
	paths = append(paths, pending.IntermediateCerts...)
	paths = append(paths, pending.Symlinks...)
	paths = append(paths, pending.TrustAnchorSymlink)
	return uniqueStrings(paths)
}

func pendingRemovalPaths(stateDir string, pending pendingEnrollment) ([]string, error) {
	root, err := filepath.Abs(filepath.Join(stateDir, "private", "certs", "pending"))
	if err != nil {
		return nil, err
	}
	key, err := filepath.Abs(pending.KeyFile)
	if err != nil {
		return nil, err
	}
	csr, err := filepath.Abs(pending.CSRFile)
	if err != nil {
		return nil, err
	}
	if !pathWithin(root, key) || !pathWithin(root, csr) || filepath.Dir(key) != filepath.Dir(csr) {
		return nil, fmt.Errorf("pending key/CSR paths are outside ADSys-owned pending state")
	}
	directory := filepath.Dir(key)
	for _, path := range []string{key, csr} {
		info, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("pending material %s is not a regular non-symlink file", path)
		}
	}
	if info, err := os.Lstat(directory); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("pending material parent is not a regular directory")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return []string{csr, key, directory}, nil
}

func pendingArtifactRemovalPaths(stateDir, globalTrustDir string, pending pendingEnrollment) ([]string, error) {
	material, err := pendingRemovalPaths(stateDir, pending)
	if err != nil {
		return nil, err
	}
	paths := append([]string(nil), material...)
	for _, path := range uniqueStrings(append(append(append([]string(nil), pending.ChainFiles...), pending.RootCerts...), pending.IntermediateCerts...)) {
		if err := validateOwnedPendingPath(filepath.Join(stateDir, "certs"), path, false); err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}
	for _, path := range uniqueStrings(append(append([]string(nil), pending.Symlinks...), pending.TrustAnchorSymlink)) {
		if err := validateOwnedPendingPath(globalTrustDir, path, true); err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}
	return uniqueStrings(paths), nil
}

func validateOwnedPendingPath(root, path string, symlink bool) error {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if !pathWithin(rootAbs, pathAbs) || filepath.Clean(rootAbs) == filepath.Clean(pathAbs) {
		return fmt.Errorf("%s is outside %s", path, root)
	}
	rootInfo, err := os.Lstat(rootAbs)
	if err != nil {
		return err
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("owned root %s is not a regular directory", root)
	}
	relative, err := filepath.Rel(rootAbs, pathAbs)
	if err != nil {
		return err
	}
	current := rootAbs
	components := strings.Split(relative, string(filepath.Separator))
	for index, component := range components {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if index != len(components)-1 {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("owned path component %s is not a regular directory", current)
			}
			continue
		}
		if symlink {
			if info.Mode()&os.ModeSymlink == 0 {
				return fmt.Errorf("%s is not a symlink", path)
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular non-symlink file", path)
		}
		return nil
	}
	return nil
}

func terminalDispositionError(response Response, cause error) error {
	label := "terminated"
	switch response.Disposition {
	case DispositionDenied:
		label = "denied"
	case DispositionRevoked:
		label = "revoked"
	case DispositionIssuedOutOfBand:
		label = "issued out of band without a usable certificate"
	}
	detail := ""
	if message := sanitizeDispositionMessage(response.Message); message != "" {
		detail = ": " + message
	}
	base := fmt.Errorf("certificate request %s (request ID %d)%s", label, response.RequestID, detail)
	if cause != nil {
		return &terminalEnrollmentError{err: errors.Join(base, cause)}
	}
	return &terminalEnrollmentError{err: base}
}

type terminalEnrollmentError struct {
	err error
}

func (e *terminalEnrollmentError) Error() string { return e.err.Error() }
func (e *terminalEnrollmentError) Unwrap() error { return e.err }

func logPendingRetention(ctx context.Context, pending pendingEnrollment, err error) {
	log.Warningf(ctx, "Retaining pending certificate request %d for %s after error: %v", pending.RequestID, pending.Nickname, err)
}

package certificate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync/atomic"
	"time"

	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
)

// symlinkTmpCounter yields a unique suffix per atomicSymlink call within the
// process, so concurrent installs of the same CA can't collide on the temporary
// symlink name.
var symlinkTmpCounter atomic.Uint64

type caChainInstallation struct {
	RootFiles         []string
	IntermediateFiles []string
	SymlinkFiles      []string
	ChainFiles        []string

	createdFiles   []createdCertificateFile
	symlinkChanges []symlinkChange

	// removeFile and restoreSymlink let tests inject rollback failures.
	// Production installations leave them nil and fall back to os.Remove and
	// atomicSymlink respectively.
	removeFile     func(string) error
	restoreSymlink func(src, dst string) error
}

type createdCertificateFile struct {
	path string
	raw  []byte
	info os.FileInfo
}

type symlinkChange struct {
	path            string
	installedTarget string
	previousTarget  string
	hadPrevious     bool
	installedInfo   os.FileInfo
}

type trustInstallOps struct {
	replaceSymlink func(src, dst string) error
	beforeSymlink  func() error
}

// trustRollbackError marks an installation error that left one or more trust
// artifacts behind. Callers may skip an ordinary CA installation failure, but
// must never mask this error by preserving or enrolling through another CA.
type trustRollbackError struct {
	err error
}

func (e *trustRollbackError) Error() string {
	return fmt.Sprintf("rolling back partial CA chain installation: %v", e.err)
}

func (e *trustRollbackError) Unwrap() error {
	return e.err
}

type certificateInstallPlan struct {
	cert    *x509.Certificate
	path    string
	staged  string
	publish bool
}

func installCAChain(ca certAuthority, trustDir, globalTrustDir string) (rootFiles, intermediateFiles, symlinkFiles []string, err error) {
	installation, err := installCAChainTransaction(ca, trustDir, globalTrustDir)
	if err != nil {
		return nil, nil, nil, err
	}
	return installation.RootFiles, installation.IntermediateFiles, installation.SymlinkFiles, nil
}

func installCAChainTransaction(ca certAuthority, trustDir, globalTrustDir string) (*caChainInstallation, error) {
	return installCAChainTransactionWithOps(ca, trustDir, globalTrustDir, trustInstallOps{
		replaceSymlink: atomicSymlink,
	})
}

func installCAChainTransactionWithOps(ca certAuthority, trustDir, globalTrustDir string, ops trustInstallOps) (_ *caChainInstallation, err error) {
	chain := ca.Chain
	if chain == nil {
		if len(ca.CACertificate) == 0 {
			return nil, fmt.Errorf("CA %s has no selected certificate chain", ca.Name)
		}
		cert, parseErr := x509.ParseCertificate(ca.CACertificate)
		if parseErr != nil {
			return nil, fmt.Errorf("failed to parse CA certificate for %s: %w", ca.Name, parseErr)
		}
		chain = &expectedCertificateChain{
			Certificates: []*x509.Certificate{cert},
			Fingerprints: []string{certificateFingerprint(cert)},
		}
	}
	if err := verifyExactCAPath(chain.Certificates, time.Now()); err != nil {
		return nil, fmt.Errorf("CA certificate for %s failed directory-chain verification: %w", ca.Name, err)
	}
	if len(chain.Fingerprints) != 0 && len(chain.Fingerprints) != len(chain.Certificates) {
		return nil, fmt.Errorf("CA certificate chain for %s has %d fingerprints for %d certificates", ca.Name, len(chain.Fingerprints), len(chain.Certificates))
	}
	for i, cert := range chain.Certificates {
		if len(chain.Fingerprints) != 0 && chain.Fingerprints[i] != certificateFingerprint(cert) {
			return nil, fmt.Errorf("CA certificate chain fingerprint %d for %s does not match its certificate", i, ca.Name)
		}
	}

	plans := make([]certificateInstallPlan, 0, len(chain.Certificates))
	defer func() {
		var cleanupErrs []error
		for _, plan := range plans {
			if plan.staged != "" {
				if removeErr := os.Remove(plan.staged); removeErr != nil && !os.IsNotExist(removeErr) {
					cleanupErrs = append(cleanupErrs, fmt.Errorf("removing staged CA certificate %s: %w", plan.staged, removeErr))
				}
			}
		}
		if cleanupErr := errors.Join(cleanupErrs...); cleanupErr != nil {
			err = errors.Join(err, &trustRollbackError{err: cleanupErr})
		}
	}()
	installation := &caChainInstallation{}
	log.Debugf(context.Background(), "Installing CA chain for %s with %d certificate(s)", ca.Name, len(chain.Certificates))
	for i, cert := range chain.Certificates {
		role := fmt.Sprintf("intermediate-%d", i)
		if i == 0 {
			role = "issuer"
		}
		isRoot := i == len(chain.Certificates)-1
		if isRoot {
			role = "root"
		}
		certFileName := trustArtifactFileName(ca, cert, role)
		certPath := filepath.Join(trustDir, certFileName)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		plan := certificateInstallPlan{cert: cert, path: certPath}
		switch matches, inspectErr := existingCertificateMatches(certPath, cert); {
		case inspectErr != nil:
			return nil, fmt.Errorf("failed to inspect CA certificate %s: %w", certPath, inspectErr)
		case matches:
		default:
			staged, stageErr := stageCertificateFile(certPath, certPEM, 0644)
			if stageErr != nil {
				return nil, fmt.Errorf("failed to stage CA certificate %s: %w", certPath, stageErr)
			}
			plan.staged = staged
			plan.publish = true
		}
		plans = append(plans, plan)
		installation.ChainFiles = append(installation.ChainFiles, certPath)

		if !isRoot {
			installation.IntermediateFiles = append(installation.IntermediateFiles, certPath)
			continue
		}
		installation.RootFiles = append(installation.RootFiles, certPath)
		symlinkPath := filepath.Join(globalTrustDir, certFileName)
		if info, inspectErr := os.Lstat(symlinkPath); inspectErr == nil {
			if info.Mode()&os.ModeSymlink == 0 {
				return nil, fmt.Errorf("refusing to overwrite non-symlink trust store entry %s", symlinkPath)
			}
		} else if !os.IsNotExist(inspectErr) {
			return nil, fmt.Errorf("failed to inspect existing trust store entry %s: %w", symlinkPath, inspectErr)
		}
		installation.SymlinkFiles = append(installation.SymlinkFiles, symlinkPath)
	}

	for i := range plans {
		if !plans[i].publish {
			continue
		}
		created, err := publishStagedCertificate(plans[i].staged, plans[i].path, plans[i].cert)
		if err != nil {
			return nil, withRollback(installation, fmt.Errorf("failed to publish CA certificate %s: %w", plans[i].path, err))
		}
		if created {
			createdFile := createdCertificateFile{
				path: plans[i].path,
				raw:  append([]byte(nil), plans[i].cert.Raw...),
			}
			createdFile.info, err = os.Lstat(plans[i].path)
			installation.createdFiles = append(installation.createdFiles, createdFile)
			if err != nil {
				return nil, withRollback(installation, fmt.Errorf("failed to inspect published CA certificate %s: %w", plans[i].path, err))
			}
		}
		if err := os.Remove(plans[i].staged); err != nil {
			return nil, withRollback(installation, fmt.Errorf("failed to remove staged CA certificate %s: %w", plans[i].staged, err))
		}
		plans[i].staged = ""
	}

	rootPath := installation.RootFiles[0]
	symlinkPath := installation.SymlinkFiles[0]
	if ops.beforeSymlink != nil {
		if err := ops.beforeSymlink(); err != nil {
			return nil, withRollback(installation, fmt.Errorf("failed before publishing trust store symlink: %w", err))
		}
	}
	previousTarget, readErr := os.Readlink(symlinkPath)
	hadPrevious := readErr == nil
	if readErr != nil && !os.IsNotExist(readErr) {
		return nil, withRollback(installation, fmt.Errorf("failed to read existing trust store symlink %s: %w", symlinkPath, readErr))
	}
	if !hadPrevious || previousTarget != rootPath {
		if ops.replaceSymlink == nil {
			return nil, withRollback(installation, fmt.Errorf("trust symlink publisher is unavailable"))
		}
		if err := ops.replaceSymlink(rootPath, symlinkPath); err != nil {
			return nil, withRollback(installation, fmt.Errorf("failed to create trust store symlink %s -> %s: %w", symlinkPath, rootPath, err))
		}
		change := symlinkChange{
			path:            symlinkPath,
			installedTarget: rootPath,
			previousTarget:  previousTarget,
			hadPrevious:     hadPrevious,
		}
		change.installedInfo, err = os.Lstat(symlinkPath)
		installation.symlinkChanges = append(installation.symlinkChanges, change)
		if err != nil {
			return nil, withRollback(installation, fmt.Errorf("failed to inspect published trust store symlink %s: %w", symlinkPath, err))
		}
	}

	return installation, nil
}

// trustArtifactFileName builds a collision-resistant on-disk name for a CA
// chain certificate. Distinct raw CA identities such as "Corp CA" and "Corp-CA"
// sanitize to the same readable prefix, so the disambiguating component is a
// SHA-256 digest over the full unsanitized CA identity (name and hostname) and
// the certificate's full fingerprint. Two installations therefore share a path
// only when they refer to the exact same CA identity and certificate, and never
// merely because their sanitized names happen to match.
func trustArtifactFileName(ca certAuthority, cert *x509.Certificate, role string) string {
	h := sha256.New()
	h.Write([]byte(ca.Name))
	h.Write([]byte{0})
	h.Write([]byte(ca.Hostname))
	h.Write([]byte{0})
	h.Write([]byte(certificateFingerprint(cert)))
	digest := hex.EncodeToString(h.Sum(nil))
	return fmt.Sprintf("%s.%s.%s.crt", sanitizeName(ca.Name), role, digest)
}

// adsysTrustArtifactPattern matches the on-disk names produced by
// trustArtifactFileName, which is how an entry of the shared global trust
// directory is recognized as adsys-managed. The directory is shared with the
// administrator, so nothing else in it may be attributed to adsys.
var adsysTrustArtifactPattern = regexp.MustCompile(`\.(issuer|root|intermediate-[0-9]+)\.[0-9a-f]{64}\.crt$`)

// isAdsysTrustArtifact reports whether an entry of a trust directory was
// installed by adsys.
func isAdsysTrustArtifact(name string) bool {
	return adsysTrustArtifactPattern.MatchString(name)
}

// withRollback rolls back a partial installation and joins any rollback failure
// with the primary error, so leftover artifacts are never reported as a clean
// abort.
func withRollback(installation *caChainInstallation, err error) error {
	if rbErr := installation.rollback(); rbErr != nil {
		return errors.Join(err, &trustRollbackError{err: rbErr})
	}
	return err
}

func containsRollbackFailure(err error) bool {
	var rollbackErr *trustRollbackError
	return errors.As(err, &rollbackErr)
}

func existingCertificateMatches(path string, expected *x509.Certificate) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("refusing to overwrite non-regular certificate file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return false, fmt.Errorf("existing file is not exactly one PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(cert.Raw, expected.Raw) {
		return false, fmt.Errorf("existing certificate does not match deterministic path fingerprint")
	}
	return true, nil
}

func stageCertificateFile(dst string, data []byte, mode os.FileMode) (_ string, err error) {
	f, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".stage.*")
	if err != nil {
		return "", err
	}
	path := f.Name()
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
				err = errors.Join(err, &trustRollbackError{
					err: fmt.Errorf("removing staged CA certificate %s: %w", path, removeErr),
				})
			}
		}
	}()
	if _, err := f.Write(data); err != nil {
		return "", err
	}
	if err := f.Chmod(mode); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	ok = true
	return path, nil
}

func publishStagedCertificate(staged, dst string, expected *x509.Certificate) (bool, error) {
	if err := os.Link(staged, dst); err != nil {
		if matches, inspectErr := existingCertificateMatches(dst, expected); inspectErr == nil && matches {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// rollback reverses the artifacts published by this installation, restoring or
// removing only entries that still match what it created. It returns an
// aggregated error describing every symlink restoration or file removal that
// could not be completed, so callers never report a clean rollback while
// leftover artifacts remain on disk for a later attempt to repair or adopt.
func (installation *caChainInstallation) rollback() error {
	if installation == nil {
		return nil
	}
	remove := installation.removeFile
	if remove == nil {
		remove = os.Remove
	}
	restore := installation.restoreSymlink
	if restore == nil {
		restore = atomicSymlink
	}
	var errs []error
	for i := len(installation.symlinkChanges) - 1; i >= 0; i-- {
		change := installation.symlinkChanges[i]
		currentTarget, err := os.Readlink(change.path)
		if err != nil {
			if !os.IsNotExist(err) {
				errs = append(errs, fmt.Errorf("reading trust store symlink %s during rollback: %w", change.path, err))
			}
			continue
		}
		// A different target means something else now owns this entry; leave it.
		if currentTarget != change.installedTarget {
			continue
		}
		currentInfo, err := os.Lstat(change.path)
		if err != nil {
			errs = append(errs, fmt.Errorf("inspecting trust store symlink %s during rollback: %w", change.path, err))
			continue
		}
		if change.installedInfo != nil && !os.SameFile(change.installedInfo, currentInfo) {
			continue
		}
		if change.hadPrevious {
			if err := restore(change.previousTarget, change.path); err != nil {
				errs = append(errs, fmt.Errorf("restoring previous trust store symlink %s -> %s during rollback: %w", change.path, change.previousTarget, err))
			}
			continue
		}
		if err := remove(change.path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("removing trust store symlink %s during rollback: %w", change.path, err))
		}
	}
	for i := len(installation.createdFiles) - 1; i >= 0; i-- {
		created := installation.createdFiles[i]
		currentInfo, err := os.Lstat(created.path)
		if err != nil {
			if !os.IsNotExist(err) {
				errs = append(errs, fmt.Errorf("inspecting published certificate %s during rollback: %w", created.path, err))
			}
			continue
		}
		if created.info != nil && !os.SameFile(created.info, currentInfo) {
			continue
		}
		data, err := os.ReadFile(created.path)
		if err != nil {
			errs = append(errs, fmt.Errorf("reading published certificate %s during rollback: %w", created.path, err))
			continue
		}
		block, _ := pem.Decode(data)
		if block == nil || !bytes.Equal(block.Bytes, created.raw) {
			continue
		}
		if err := remove(created.path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("removing published certificate %s during rollback: %w", created.path, err))
		}
	}
	return errors.Join(errs...)
}

// updateCATrustStore runs update-ca-certificates to rebuild the system
// CA trust store after adding or removing root certificates.
func updateCATrustStore() error {
	cmd := findUpdateCACommand()
	if cmd == "" {
		log.Debug(context.Background(), "No CA trust store update command found, skipping")
		return nil // No update command available, skip silently
	}

	log.Debugf(context.Background(), "Updating CA trust store using: %s", cmd)
	//nolint:gosec // G204: cmd comes from findUpdateCACommand, a fixed allowlist resolved via exec.LookPath
	if err := exec.Command(cmd).Run(); err != nil {
		return fmt.Errorf("failed to run %s: %w", cmd, err)
	}
	log.Debug(context.Background(), "CA trust store updated successfully")
	return nil
}

// findUpdateCACommand returns the path to the system command for updating
// the CA trust store, or empty string if not found.
func findUpdateCACommand() string {
	for _, cmd := range []string{"update-ca-certificates", "update-ca-trust"} {
		if path, err := exec.LookPath(cmd); err == nil {
			return path
		}
	}
	return ""
}

// atomicSymlink creates a symlink at dst pointing to src, replacing any
// existing entry atomically. It creates the symlink with a temporary name
// then renames it over the target, avoiding TOCTOU race conditions.
// If the existing entry is a regular file (not a symlink), it refuses to
// overwrite it.
func atomicSymlink(src, dst string) (err error) {
	dir := filepath.Dir(dst)
	base := filepath.Base(dst)

	// Create a temporary symlink in the same directory. The name combines the
	// PID (uniqueness across processes) with a per-call atomic counter
	// (uniqueness across concurrent goroutines in this process) so parallel
	// installs never collide on the temporary name.
	tmpName := filepath.Join(dir, fmt.Sprintf(".%s.tmp.%d.%d", base, os.Getpid(), symlinkTmpCounter.Add(1)))
	// Clean up the temp symlink if anything fails
	defer func() {
		if removeErr := os.Remove(tmpName); removeErr != nil && !os.IsNotExist(removeErr) {
			err = errors.Join(err, &trustRollbackError{
				err: fmt.Errorf("removing temporary trust symlink %s: %w", tmpName, removeErr),
			})
		}
	}()

	// If the target already exists, check that it's a symlink (not a real file)
	if info, err := os.Lstat(dst); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("refusing to overwrite non-symlink trust store entry %s", dst)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to inspect existing trust store entry %s: %w", dst, err)
	}

	if err := os.Symlink(src, tmpName); err != nil {
		return fmt.Errorf("failed to create temporary symlink: %w", err)
	}

	// Rename atomically replaces the existing entry
	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("failed to rename symlink into place: %w", err)
	}

	return nil
}

// sanitizeName replaces characters that are unsafe for filenames.
func sanitizeName(name string) string {
	base := filepath.Base(name)
	if base == "." || base == "" {
		return "unnamed"
	}
	result := make([]byte, 0, len(base))
	for i := 0; i < len(base); i++ {
		c := base[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			result = append(result, c)
		} else {
			result = append(result, '-')
		}
	}
	return string(result)
}

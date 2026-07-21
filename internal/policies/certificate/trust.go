package certificate

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
		for _, plan := range plans {
			if plan.staged != "" {
				_ = os.Remove(plan.staged)
			}
		}
	}()
	installation := &caChainInstallation{}
	log.Debugf(context.Background(), "Installing CA chain for %s with %d certificate(s)", ca.Name, len(chain.Certificates))
	for i, cert := range chain.Certificates {
		fp := certificateFingerprint(cert)
		role := fmt.Sprintf("intermediate-%d", i)
		if i == 0 {
			role = "issuer"
		}
		isRoot := i == len(chain.Certificates)-1
		if isRoot {
			role = "root"
		}
		certFileName := fmt.Sprintf("%s.%s.%s.crt", sanitizeName(ca.Name), role, fp[:16])
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
			installation.rollback()
			return nil, fmt.Errorf("failed to publish CA certificate %s: %w", plans[i].path, err)
		}
		if created {
			createdFile := createdCertificateFile{
				path: plans[i].path,
				raw:  append([]byte(nil), plans[i].cert.Raw...),
			}
			createdFile.info, err = os.Lstat(plans[i].path)
			installation.createdFiles = append(installation.createdFiles, createdFile)
			if err != nil {
				installation.rollback()
				return nil, fmt.Errorf("failed to inspect published CA certificate %s: %w", plans[i].path, err)
			}
		}
		if err := os.Remove(plans[i].staged); err != nil {
			installation.rollback()
			return nil, fmt.Errorf("failed to remove staged CA certificate %s: %w", plans[i].staged, err)
		}
		plans[i].staged = ""
	}

	rootPath := installation.RootFiles[0]
	symlinkPath := installation.SymlinkFiles[0]
	if ops.beforeSymlink != nil {
		if err := ops.beforeSymlink(); err != nil {
			installation.rollback()
			return nil, fmt.Errorf("failed before publishing trust store symlink: %w", err)
		}
	}
	previousTarget, readErr := os.Readlink(symlinkPath)
	hadPrevious := readErr == nil
	if readErr != nil && !os.IsNotExist(readErr) {
		installation.rollback()
		return nil, fmt.Errorf("failed to read existing trust store symlink %s: %w", symlinkPath, readErr)
	}
	if !hadPrevious || previousTarget != rootPath {
		if ops.replaceSymlink == nil {
			installation.rollback()
			return nil, fmt.Errorf("trust symlink publisher is unavailable")
		}
		if err := ops.replaceSymlink(rootPath, symlinkPath); err != nil {
			installation.rollback()
			return nil, fmt.Errorf("failed to create trust store symlink %s -> %s: %w", symlinkPath, rootPath, err)
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
			installation.rollback()
			return nil, fmt.Errorf("failed to inspect published trust store symlink %s: %w", symlinkPath, err)
		}
	}

	return installation, nil
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

func stageCertificateFile(dst string, data []byte, mode os.FileMode) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".stage.*")
	if err != nil {
		return "", err
	}
	path := f.Name()
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(path)
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

func (installation *caChainInstallation) rollback() {
	if installation == nil {
		return
	}
	for i := len(installation.symlinkChanges) - 1; i >= 0; i-- {
		change := installation.symlinkChanges[i]
		currentTarget, err := os.Readlink(change.path)
		if err != nil || currentTarget != change.installedTarget {
			continue
		}
		if currentInfo, err := os.Lstat(change.path); err != nil ||
			(change.installedInfo != nil && !os.SameFile(change.installedInfo, currentInfo)) {
			continue
		}
		if change.hadPrevious {
			_ = atomicSymlink(change.previousTarget, change.path)
		} else {
			_ = os.Remove(change.path)
		}
	}
	for i := len(installation.createdFiles) - 1; i >= 0; i-- {
		created := installation.createdFiles[i]
		currentInfo, err := os.Lstat(created.path)
		if err != nil || (created.info != nil && !os.SameFile(created.info, currentInfo)) {
			continue
		}
		data, err := os.ReadFile(created.path)
		if err != nil {
			continue
		}
		block, _ := pem.Decode(data)
		if block != nil && bytes.Equal(block.Bytes, created.raw) {
			_ = os.Remove(created.path)
		}
	}
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
func atomicSymlink(src, dst string) error {
	dir := filepath.Dir(dst)
	base := filepath.Base(dst)

	// Create a temporary symlink in the same directory. The name combines the
	// PID (uniqueness across processes) with a per-call atomic counter
	// (uniqueness across concurrent goroutines in this process) so parallel
	// installs never collide on the temporary name.
	tmpName := filepath.Join(dir, fmt.Sprintf(".%s.tmp.%d.%d", base, os.Getpid(), symlinkTmpCounter.Add(1)))
	// Clean up the temp symlink if anything fails
	defer os.Remove(tmpName)

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

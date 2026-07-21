package certificate

import (
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

// installRootCACerts is kept for callers that only need the root paths. The
// enrollment flow uses installCAChain so subordinate intermediates are tracked.
func installRootCACerts(ca certAuthority, trustDir, globalTrustDir string) (certFiles []string, symlinkFiles []string, err error) {
	roots, _, symlinks, err := installCAChain(ca, trustDir, globalTrustDir)
	return roots, symlinks, err
}

func installCAChain(ca certAuthority, trustDir, globalTrustDir string) (rootFiles, intermediateFiles, symlinkFiles []string, err error) {
	chain := ca.Chain
	if chain == nil {
		if len(ca.CACertificate) == 0 {
			return nil, nil, nil, fmt.Errorf("CA %s has no selected certificate chain", ca.Name)
		}
		cert, parseErr := x509.ParseCertificate(ca.CACertificate)
		if parseErr != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse CA certificate for %s: %w", ca.Name, parseErr)
		}
		chain = &expectedCertificateChain{
			Certificates: []*x509.Certificate{cert},
			Fingerprints: []string{certificateFingerprint(cert)},
		}
	}
	if err := verifyExactCAPath(chain.Certificates, time.Now()); err != nil {
		return nil, nil, nil, fmt.Errorf("CA certificate for %s failed directory-chain verification: %w", ca.Name, err)
	}

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
		if err := safeWriteFile(certPath, certPEM, 0644); err != nil {
			return rootFiles, intermediateFiles, symlinkFiles, fmt.Errorf("failed to write CA certificate: %w", err)
		}

		if !isRoot {
			intermediateFiles = append(intermediateFiles, certPath)
			continue
		}
		rootFiles = append(rootFiles, certPath)
		symlinkPath := filepath.Join(globalTrustDir, certFileName)
		if err := atomicSymlink(certPath, symlinkPath); err != nil {
			return rootFiles, intermediateFiles, symlinkFiles, fmt.Errorf("failed to create trust store symlink %s -> %s: %w", symlinkPath, certPath, err)
		}
		symlinkFiles = append(symlinkFiles, symlinkPath)
	}
	return rootFiles, intermediateFiles, symlinkFiles, nil
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

// removeRootCACerts removes the certificate files and symlinks for a given CA.
func removeRootCACerts(certFiles, symlinkFiles []string) {
	for _, f := range symlinkFiles {
		log.Debugf(context.Background(), "Removing CA trust store symlink: %s", f)
		os.Remove(f)
	}
	for _, f := range certFiles {
		log.Debugf(context.Background(), "Removing CA certificate file: %s", f)
		os.Remove(f)
	}
}

func removeCAChainCerts(rootFiles, intermediateFiles, symlinkFiles []string) {
	removeRootCACerts(rootFiles, symlinkFiles)
	for _, f := range intermediateFiles {
		log.Debugf(context.Background(), "Removing intermediate CA certificate: %s", f)
		_ = os.Remove(f)
	}
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

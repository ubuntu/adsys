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

// installRootCACerts writes the DER-encoded CA certificate to the trust
// directory and creates a symlink in the global trust directory.
// Returns the list of created cert files and symlink paths.
func installRootCACerts(ca certAuthority, trustDir, globalTrustDir string) (certFiles []string, symlinkFiles []string, err error) {
	if len(ca.CACertificate) == 0 {
		log.Debugf(context.Background(), "No CA certificate to install for %s", ca.Name)
		return nil, nil, nil
	}
	log.Debugf(context.Background(), "Installing root CA certificate for %s", ca.Name)

	// Parse the DER certificate to PEM
	cert, err := x509.ParseCertificate(ca.CACertificate)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate for %s: %w", ca.Name, err)
	}
	if !cert.IsCA {
		return nil, nil, fmt.Errorf("certificate for %s is not a CA certificate", ca.Name)
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, nil, fmt.Errorf("CA certificate for %s is not allowed to sign certificates", ca.Name)
	}

	// Sanity-check the discovered CA certificate before installing it. For a
	// self-signed AD CS root this can only confirm the certificate is
	// well-formed and currently valid; legitimacy is established by the
	// authenticated, StartTLS-protected LDAP channel it was discovered through
	// (see verifyPeerCertificate), mirroring how Windows autoenrollment trusts
	// the directory. A non-self-signed CA must additionally chain to a root
	// already trusted by the system or previously installed by adsys.
	if err := verifyCACertificate(cert, globalTrustDir); err != nil {
		return nil, nil, fmt.Errorf("CA certificate for %s failed verification: %w", ca.Name, err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	// Write the certificate file
	certFileName := fmt.Sprintf("%s.crt", sanitizeName(ca.Name))
	certPath := filepath.Join(trustDir, certFileName)
	//nolint:gosec // G306: CA certificates are public trust anchors and must be world-readable by TLS clients
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return nil, nil, fmt.Errorf("failed to write CA certificate: %w", err)
	}
	log.Debugf(context.Background(), "Wrote CA certificate to %s", certPath)
	certFiles = append(certFiles, certPath)

	// Create symlink in the global trust directory using an atomic
	// rename pattern to avoid TOCTOU race conditions: create the symlink
	// with a temporary name, then rename it over the final path.
	symlinkPath := filepath.Join(globalTrustDir, certFileName)
	if err := atomicSymlink(certPath, symlinkPath); err != nil {
		return certFiles, nil, fmt.Errorf("failed to create trust store symlink %s -> %s: %w", symlinkPath, certPath, err)
	}
	log.Debugf(context.Background(), "Created trust store symlink: %s -> %s", symlinkPath, certPath)
	symlinkFiles = append(symlinkFiles, symlinkPath)

	return certFiles, symlinkFiles, nil
}

// verifyCACertificate performs a best-effort sanity check on a CA certificate
// discovered over LDAP before it is installed into the system trust store.
//
// AD CS root CAs are self-signed, so for the common case this can only confirm
// the certificate is currently within its validity period; a self-signed
// certificate carries no external proof of legitimacy. The real trust anchor is
// the authenticated, StartTLS-protected LDAP channel the certificate was
// discovered through (see verifyPeerCertificate), exactly as Windows
// autoenrollment trusts the directory itself. A non-self-signed CA is held to a
// stronger bar: it must chain to a root already trusted by the system or
// previously installed by adsys. Any additional trustDirs are consulted when
// building that chain (e.g. a non-default configured global trust directory).
func verifyCACertificate(cert *x509.Certificate, trustDirs ...string) error {
	now := time.Now()

	// Self-signed (root) CA: we can only validate the temporal window.
	if cert.CheckSignatureFrom(cert) == nil {
		if now.Before(cert.NotBefore) {
			return fmt.Errorf("self-signed CA certificate is not yet valid (NotBefore: %s)", cert.NotBefore)
		}
		if now.After(cert.NotAfter) {
			return fmt.Errorf("self-signed CA certificate has expired (NotAfter: %s)", cert.NotAfter)
		}
		return nil
	}

	// Non-self-signed CA: require a chain to a trusted anchor.
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	addAdsysCAsToPool(pool, trustDirs...)

	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: x509.NewCertPool(),
	}); err != nil {
		return fmt.Errorf("CA certificate does not chain to a trusted root: %w", err)
	}
	return nil
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

package certificate

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
)

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

	// Symlink to global trust directory
	symlinkPath := filepath.Join(globalTrustDir, certFileName)
	// Remove any existing (possibly stale) symlink first, and surface failures
	// so a half-populated trust store does not silently look like a success.
	if info, err := os.Lstat(symlinkPath); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return certFiles, nil, fmt.Errorf("refusing to overwrite non-symlink trust store entry %s", symlinkPath)
		}
		if err := os.Remove(symlinkPath); err != nil {
			return certFiles, nil, fmt.Errorf("failed to remove existing trust store symlink %s: %w", symlinkPath, err)
		}
	} else if !os.IsNotExist(err) {
		return certFiles, nil, fmt.Errorf("failed to inspect existing trust store entry %s: %w", symlinkPath, err)
	}
	if err := os.Symlink(certPath, symlinkPath); err != nil {
		return certFiles, nil, fmt.Errorf("failed to create trust store symlink %s -> %s: %w", symlinkPath, certPath, err)
	}
	log.Debugf(context.Background(), "Created trust store symlink: %s -> %s", symlinkPath, certPath)
	symlinkFiles = append(symlinkFiles, symlinkPath)

	return certFiles, symlinkFiles, nil
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

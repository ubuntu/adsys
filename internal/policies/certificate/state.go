package certificate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
)

// enrollmentState represents the persisted state of certificate enrollment
// for a single machine. This replaces the Samba TDB cache.
type enrollmentState struct {
	ObjectName string       `json:"object_name"`
	Domain     string       `json:"domain"`
	CAs        []enrolledCA `json:"cas"`
	UpdatedAt  time.Time    `json:"updated_at"`
}

// enrolledCA tracks a single CA that the machine is enrolled with.
type enrolledCA struct {
	Name      string             `json:"name"`
	Hostname  string             `json:"hostname"`
	RootCerts []string           `json:"root_certs"` // paths to root CA cert files
	Symlinks  []string           `json:"symlinks"`   // paths to symlinks in global trust dir
	Templates []enrolledTemplate `json:"templates"`
}

// enrolledTemplate tracks a single certificate template enrollment.
type enrolledTemplate struct {
	Nickname string `json:"nickname"`  // sanitized on-disk identifier (e.g. "CA-Name.Machine")
	Template string `json:"template"`  // template name
	KeyFile  string `json:"key_file"`  // path to private key
	CertFile string `json:"cert_file"` // path to certificate
}

// stateFilePath returns the path to the enrollment state file for a given object.
func stateFilePath(stateDir, objectName string) string {
	// objectName originates from policy data, so sanitize it to keep the file
	// name within the certs directory and avoid path traversal.
	return filepath.Join(stateDir, "certs", fmt.Sprintf("state_%s.json", sanitizeName(objectName)))
}

// loadState reads the enrollment state from disk.
// Returns nil state with no error if the file does not exist.
func loadState(stateDir, objectName string) (*enrollmentState, error) {
	path := stateFilePath(stateDir, objectName)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Debugf(context.Background(), "No enrollment state file found at %s", path)
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read enrollment state: %w", err)
	}

	var state enrollmentState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse enrollment state: %w", err)
	}

	log.Debugf(context.Background(), "Loaded enrollment state for %s (last updated: %s)", state.ObjectName, state.UpdatedAt.Format("2006-01-02 15:04:05"))
	return &state, nil
}

// saveState writes the enrollment state to disk.
func saveState(stateDir string, state *enrollmentState) error {
	state.UpdatedAt = time.Now()

	dir := filepath.Dir(stateFilePath(stateDir, state.ObjectName))
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create state directory: %w", err)
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal enrollment state: %w", err)
	}

	path := stateFilePath(stateDir, state.ObjectName)
	log.Debugf(context.Background(), "Writing enrollment state for %s to %s", state.ObjectName, path)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write enrollment state: %w", err)
	}

	return nil
}

// removeState deletes the enrollment state file from disk.
func removeState(stateDir, objectName string) error {
	path := stateFilePath(stateDir, objectName)
	log.Debugf(context.Background(), "Removing enrollment state file: %s", path)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove enrollment state: %w", err)
	}
	return nil
}

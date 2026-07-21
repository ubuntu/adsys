package certificate

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
)

// stateFileMu serializes state migration with state saves and removals. Manager
// operations additionally hold trustLifecycleMu while state and its referenced
// artifacts are inspected or changed.
var stateFileMu sync.Mutex

var errStateOwnership = errors.New("enrollment state belongs to a different object, domain, or identity")

// enrollmentState represents the persisted state of certificate enrollment
// for a single machine. This replaces the Samba TDB cache.
type enrollmentState struct {
	ObjectName string       `json:"object_name"`
	Identity   string       `json:"identity,omitempty"`
	Domain     string       `json:"domain"`
	CAs        []enrolledCA `json:"cas"`
	UpdatedAt  time.Time    `json:"updated_at"`
}

// enrolledCA tracks a single CA that the machine is enrolled with.
type enrolledCA struct {
	Name              string             `json:"name"`
	Hostname          string             `json:"hostname"`
	IssuerFingerprint string             `json:"issuer_fingerprint,omitempty"`
	ChainFingerprints []string           `json:"chain_fingerprints,omitempty"`
	RootCerts         []string           `json:"root_certs"`                   // paths to self-signed root CA cert files
	IntermediateCerts []string           `json:"intermediate_certs,omitempty"` // ordered issuing/intermediate CA files
	Symlinks          []string           `json:"symlinks"`                     // paths to root symlinks in global trust dir
	Templates         []enrolledTemplate `json:"templates"`
}

// enrolledTemplate tracks a single certificate template enrollment.
type enrolledTemplate struct {
	Nickname           string   `json:"nickname"`  // management identifier
	Template           string   `json:"template"`  // template name
	KeyFile            string   `json:"key_file"`  // path to private key
	CertFile           string   `json:"cert_file"` // path to certificate
	LeafFingerprint    string   `json:"leaf_fingerprint,omitempty"`
	IssuerFingerprint  string   `json:"issuer_fingerprint,omitempty"`
	ChainFingerprints  []string `json:"chain_fingerprints,omitempty"`
	ChainFiles         []string `json:"chain_files,omitempty"` // ordered issuer-to-root certificate files
	TrustAnchorSymlink string   `json:"trust_anchor_symlink,omitempty"`
}

// stateFilePath returns the collision-resistant state path for objectName. The
// readable prefix is not injective, so a digest of the complete raw object name
// is part of every new filename.
func stateFilePath(stateDir, objectName string) string {
	digest := sha256.Sum256([]byte(objectName))
	return filepath.Join(stateDir, "certs", fmt.Sprintf("state_%s.%x.json", sanitizeName(objectName), digest[:8]))
}

func legacyStateFilePath(stateDir, objectName string) string {
	return filepath.Join(stateDir, "certs", fmt.Sprintf("state_%s.json", sanitizeName(objectName)))
}

// loadState reads and ownership-validates the requested object's state. A
// matching legacy state is migrated atomically to the collision-resistant
// filename. A legacy file for a different raw object is a sanitized-name
// collision and is ignored, never removed or reused.
func loadState(stateDir, objectName, domain string) (*enrollmentState, error) {
	stateFileMu.Lock()
	defer stateFileMu.Unlock()

	path := stateFilePath(stateDir, objectName)
	state, _, err := readStateFile(path)
	if err == nil {
		if err := validateStateOwnership(state, objectName, domain); err != nil {
			return nil, fmt.Errorf("validating enrollment state %s: %w", path, err)
		}
		if err := validateUniqueNicknames(state); err != nil {
			return nil, fmt.Errorf("validating enrollment state %s: %w", path, err)
		}
		removeMatchingLegacyState(stateDir, objectName, domain)
		log.Debugf(context.Background(), "Loaded enrollment state for %s (last updated: %s)", state.ObjectName, state.UpdatedAt.Format("2006-01-02 15:04:05"))
		return state, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}

	legacyPath := legacyStateFilePath(stateDir, objectName)
	legacy, legacyInfo, err := readStateFile(legacyPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Debugf(context.Background(), "No enrollment state file found at %s", path)
			return nil, nil
		}
		return nil, err
	}
	if legacy.ObjectName != objectName {
		log.Debugf(context.Background(), "Ignoring legacy enrollment state for raw object %q while loading %q", legacy.ObjectName, objectName)
		return nil, nil
	}
	if err := validateStateOwnership(legacy, objectName, domain); err != nil {
		return nil, fmt.Errorf("validating legacy enrollment state %s: %w", legacyPath, err)
	}
	if err := normalizeDuplicateNicknames(legacy); err != nil {
		return nil, fmt.Errorf("migrating legacy enrollment state %s: %w", legacyPath, err)
	}
	if err := writeStateFile(path, legacy); err != nil {
		return nil, fmt.Errorf("migrating legacy enrollment state to %s: %w", path, err)
	}
	if err := removeStateFileIfSame(legacyPath, legacyInfo); err != nil {
		return nil, fmt.Errorf("removing migrated legacy enrollment state %s: %w", legacyPath, err)
	}
	log.Debugf(context.Background(), "Migrated enrollment state for %s from %s to %s", objectName, legacyPath, path)
	return legacy, nil
}

func readStateFile(path string) (*enrollmentState, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("enrollment state %s is not a regular file", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read enrollment state %s: %w", path, err)
	}
	var state enrollmentState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, nil, fmt.Errorf("failed to parse enrollment state %s: %w", path, err)
	}
	return &state, info, nil
}

func validateStateOwnership(state *enrollmentState, objectName, domain string) error {
	if state == nil {
		return fmt.Errorf("%w: state is missing", errStateOwnership)
	}
	if state.ObjectName == "" || state.ObjectName != objectName {
		return fmt.Errorf("%w: state object %q does not match requested object %q", errStateOwnership, state.ObjectName, objectName)
	}
	requestedDomain := normalizeDomainIdentity(domain)
	if requestedDomain == "" || normalizeDomainIdentity(state.Domain) != requestedDomain {
		return fmt.Errorf("%w: state domain %q does not match requested domain %q", errStateOwnership, state.Domain, domain)
	}
	requested, err := enrollmentMachineIdentity(objectName, domain)
	if err != nil {
		return fmt.Errorf("%w: deriving requested machine identity: %w", errStateOwnership, err)
	}
	if state.Identity != "" && normalizeMachineIdentity(state.Identity) != normalizeMachineIdentity(requested.dnsName) {
		return fmt.Errorf("%w: state identity %q does not match requested machine %q", errStateOwnership, state.Identity, requested.dnsName)
	}
	return nil
}

func validateUniqueNicknames(state *enrollmentState) error {
	seen := make(map[string]struct{})
	for _, ca := range state.CAs {
		for _, tmpl := range ca.Templates {
			if tmpl.Nickname == "" {
				return fmt.Errorf("CA %q template %q has an empty nickname", ca.Name, tmpl.Template)
			}
			if _, ok := seen[tmpl.Nickname]; ok {
				return fmt.Errorf("duplicate certificate nickname %q", tmpl.Nickname)
			}
			seen[tmpl.Nickname] = struct{}{}
		}
	}
	return nil
}

// normalizeDuplicateNicknames upgrades colliding legacy nicknames to their
// raw-identity-discriminated form before they are written as new state.
func normalizeDuplicateNicknames(state *enrollmentState) error {
	counts := make(map[string]int)
	for _, ca := range state.CAs {
		for _, tmpl := range ca.Templates {
			counts[tmpl.Nickname]++
		}
	}
	for ci := range state.CAs {
		for ti := range state.CAs[ci].Templates {
			tmpl := &state.CAs[ci].Templates[ti]
			if tmpl.Nickname == "" || counts[tmpl.Nickname] > 1 {
				tmpl.Nickname = managementNickname(state.CAs[ci].Name, state.CAs[ci].Hostname, tmpl.Template)
			}
		}
	}
	return validateUniqueNicknames(state)
}

// saveState writes state atomically. UpdatedAt and any duplicate-legacy
// nickname normalization become visible to the caller only after the durable
// replacement succeeds.
func saveState(stateDir string, state *enrollmentState) error {
	stateFileMu.Lock()
	defer stateFileMu.Unlock()

	if state == nil {
		return fmt.Errorf("refusing to save nil enrollment state")
	}
	working := cloneEnrollmentState(state)
	working.UpdatedAt = time.Now()
	if err := validateStateOwnership(working, working.ObjectName, working.Domain); err != nil {
		return fmt.Errorf("refusing to save invalid enrollment state: %w", err)
	}
	if err := normalizeDuplicateNicknames(working); err != nil {
		return fmt.Errorf("refusing to save invalid enrollment state: %w", err)
	}
	path := stateFilePath(stateDir, working.ObjectName)
	log.Debugf(context.Background(), "Writing enrollment state for %s to %s", working.ObjectName, path)
	if err := writeStateFile(path, working); err != nil {
		return fmt.Errorf("failed to write enrollment state: %w", err)
	}
	*state = *working
	return nil
}

func writeStateFile(path string, state *enrollmentState) error {
	if err := validateUniqueNicknames(state); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return fmt.Errorf("failed to create state directory: %w", err)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal enrollment state: %w", err)
	}
	return safeWriteFile(path, data, 0600)
}

func cloneEnrollmentState(state *enrollmentState) *enrollmentState {
	if state == nil {
		return nil
	}
	clone := *state
	clone.CAs = append([]enrolledCA(nil), state.CAs...)
	for i := range clone.CAs {
		clone.CAs[i].Templates = append([]enrolledTemplate(nil), state.CAs[i].Templates...)
	}
	return &clone
}

// removeState removes only files whose embedded owner matches the request.
// A colliding legacy file for another raw object is deliberately retained.
func removeState(stateDir, objectName, domain string) error {
	stateFileMu.Lock()
	defer stateFileMu.Unlock()

	var candidates []string
	canonical := stateFilePath(stateDir, objectName)
	state, _, err := readStateFile(canonical)
	switch {
	case err == nil:
		if err := validateStateOwnership(state, objectName, domain); err != nil {
			return fmt.Errorf("validating enrollment state before removal: %w", err)
		}
		candidates = append(candidates, canonical)
	case !os.IsNotExist(err):
		return err
	}

	legacy := legacyStateFilePath(stateDir, objectName)
	legacyState, _, err := readStateFile(legacy)
	switch {
	case err == nil && legacyState.ObjectName == objectName:
		if err := validateStateOwnership(legacyState, objectName, domain); err != nil {
			return fmt.Errorf("validating legacy enrollment state before removal: %w", err)
		}
		candidates = append(candidates, legacy)
	case err == nil:
		// Sanitized-name collision owned by another raw object.
	case !os.IsNotExist(err):
		return err
	}

	for _, path := range candidates {
		log.Debugf(context.Background(), "Removing enrollment state file: %s", path)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove enrollment state %s: %w", path, err)
		}
	}
	return nil
}

func removeMatchingLegacyState(stateDir, objectName, domain string) {
	path := legacyStateFilePath(stateDir, objectName)
	state, info, err := readStateFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warningf(context.Background(), "Could not inspect duplicate legacy enrollment state %s: %v", path, err)
		}
		return
	}
	if state.ObjectName != objectName {
		return
	}
	if err := validateStateOwnership(state, objectName, domain); err != nil {
		log.Warningf(context.Background(), "Refusing to remove legacy enrollment state %s with mismatched ownership: %v", path, err)
		return
	}
	if err := removeStateFileIfSame(path, info); err != nil {
		log.Warningf(context.Background(), "Could not remove duplicate legacy enrollment state %s: %v", path, err)
	}
}

func removeStateFileIfSame(path string, expected os.FileInfo) error {
	current, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if expected == nil || !os.SameFile(expected, current) {
		return fmt.Errorf("state file changed during migration")
	}
	return os.Remove(path)
}

func stateOwnerKey(state *enrollmentState) string {
	return state.ObjectName + "\x00" + normalizeDomainIdentity(state.Domain)
}

func isCanonicalStatePath(stateDir, path string, state *enrollmentState) bool {
	return filepath.Clean(path) == filepath.Clean(stateFilePath(stateDir, state.ObjectName))
}

func isLegacyStatePath(stateDir, path string, state *enrollmentState) bool {
	return filepath.Clean(path) == filepath.Clean(legacyStateFilePath(stateDir, state.ObjectName))
}

func validateEnumeratedState(state *enrollmentState) error {
	if state == nil || strings.TrimSpace(state.ObjectName) == "" || normalizeDomainIdentity(state.Domain) == "" {
		return fmt.Errorf("state owner is incomplete")
	}
	return validateStateOwnership(state, state.ObjectName, state.Domain)
}

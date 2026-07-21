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
	ObjectName string              `json:"object_name"`
	Identity   string              `json:"identity,omitempty"`
	Domain     string              `json:"domain"`
	CAs        []enrolledCA        `json:"cas"`
	Pending    []pendingEnrollment `json:"pending,omitempty"`
	UpdatedAt  time.Time           `json:"updated_at"`
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
	GenerationRoot     string   `json:"generation_root,omitempty"`
	GenerationPointer  string   `json:"generation_pointer,omitempty"`
	GenerationDir      string   `json:"generation_dir,omitempty"`
	LeafFingerprint    string   `json:"leaf_fingerprint,omitempty"`
	IssuerFingerprint  string   `json:"issuer_fingerprint,omitempty"`
	ChainFingerprints  []string `json:"chain_fingerprints,omitempty"`
	ChainFiles         []string `json:"chain_files,omitempty"` // ordered issuer-to-root certificate files
	TrustAnchorSymlink string   `json:"trust_anchor_symlink,omitempty"`
}

// pendingEnrollment contains everything required to poll and finish a request
// without rediscovery, failover, or generating another key.
type pendingEnrollment struct {
	ObjectName          string    `json:"object_name"`
	Domain              string    `json:"domain"`
	Identity            string    `json:"identity"`
	CAName              string    `json:"ca_name"`
	Server              string    `json:"server"`
	Template            string    `json:"template"`
	Nickname            string    `json:"nickname"`
	RequestID           uint32    `json:"request_id"`
	KeyFile             string    `json:"key_file"`
	CSRFile             string    `json:"csr_file"`
	KeyFingerprint      string    `json:"key_fingerprint"`
	GenerationRoot      string    `json:"generation_root"`
	IssuerFingerprint   string    `json:"issuer_fingerprint"`
	ChainFingerprints   []string  `json:"chain_fingerprints"`
	ChainFiles          []string  `json:"chain_files"`
	TrustAnchorSymlink  string    `json:"trust_anchor_symlink"`
	RootCerts           []string  `json:"root_certs"`
	IntermediateCerts   []string  `json:"intermediate_certs,omitempty"`
	Symlinks            []string  `json:"symlinks"`
	Renewal             bool      `json:"renewal,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
	LastPolledAt        time.Time `json:"last_polled_at,omitempty"`
	MetadataFingerprint string    `json:"metadata_fingerprint"`
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
		if err := validateGenerationStatePaths(stateDir, state); err != nil {
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
	if err := validateGenerationStatePaths(stateDir, legacy); err != nil {
		return nil, fmt.Errorf("validating legacy enrollment state %s: %w", legacyPath, err)
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
	if err := validatePendingStateMetadata(working); err != nil {
		return fmt.Errorf("refusing to save invalid enrollment state: %w", err)
	}
	if err := validateGenerationStatePaths(stateDir, working); err != nil {
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

func validateGenerationStatePaths(stateDir string, state *enrollmentState) error {
	privateRoot, err := filepath.Abs(filepath.Join(stateDir, "private", "certs"))
	if err != nil {
		return err
	}
	for _, ca := range state.CAs {
		for _, tmpl := range ca.Templates {
			if tmpl.GenerationRoot == "" && tmpl.GenerationPointer == "" && tmpl.GenerationDir == "" {
				continue
			}
			root, err := filepath.Abs(tmpl.GenerationRoot)
			if err != nil {
				return err
			}
			if !pathWithin(privateRoot, root) || filepath.Clean(root) == filepath.Clean(privateRoot) {
				return fmt.Errorf("template %s generation root is outside ADSys private state", tmpl.Nickname)
			}
			if err := validateGenerationRootComponents(privateRoot, root); err != nil {
				return fmt.Errorf("template %s generation root is unsafe: %w", tmpl.Nickname, err)
			}
			pointer, err := filepath.Abs(tmpl.GenerationPointer)
			if err != nil || filepath.Clean(pointer) != filepath.Join(root, "current") {
				return fmt.Errorf("template %s generation pointer is outside its root", tmpl.Nickname)
			}
			directory, err := filepath.Abs(tmpl.GenerationDir)
			if err != nil || !pathWithin(filepath.Join(root, "generations"), directory) ||
				filepath.Clean(directory) == filepath.Join(root, "generations") {
				return fmt.Errorf("template %s immutable generation is outside its root", tmpl.Nickname)
			}
		}
	}
	return nil
}

func validateGenerationRootComponents(privateRoot, root string) error {
	rootInfo, err := os.Lstat(privateRoot)
	if err != nil {
		return err
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("private certificate root is not a regular directory")
	}
	relative, err := filepath.Rel(privateRoot, root)
	if err != nil {
		return err
	}
	current := privateRoot
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is not a regular directory", current)
		}
	}
	return nil
}

func validatePendingStateMetadata(state *enrollmentState) error {
	targets := make(map[string]struct{}, len(state.Pending))
	requests := make(map[string]struct{}, len(state.Pending))
	for _, pending := range state.Pending {
		if pending.ObjectName != state.ObjectName ||
			normalizeDomainIdentity(pending.Domain) != normalizeDomainIdentity(state.Domain) ||
			normalizeMachineIdentity(pending.Identity) != normalizeMachineIdentity(state.Identity) {
			return fmt.Errorf("pending request %d ownership does not match state", pending.RequestID)
		}
		if pending.RequestID == 0 {
			return fmt.Errorf("pending request for %s has ID 0", pending.Nickname)
		}
		if pending.CAName == "" || pending.Server == "" || pending.Template == "" || pending.Nickname == "" ||
			pending.KeyFile == "" || pending.CSRFile == "" || pending.KeyFingerprint == "" ||
			pending.GenerationRoot == "" || pending.IssuerFingerprint == "" ||
			len(pending.ChainFingerprints) == 0 || len(pending.ChainFiles) != len(pending.ChainFingerprints) {
			return fmt.Errorf("pending request %d metadata is incomplete", pending.RequestID)
		}
		if !strings.EqualFold(pending.MetadataFingerprint, pendingMetadataFingerprint(pending)) {
			return fmt.Errorf("pending request %d metadata fingerprint does not match", pending.RequestID)
		}
		target := pendingTargetKey(pending.CAName, pending.Server, pending.Template)
		if _, exists := targets[target]; exists {
			return fmt.Errorf("duplicate pending target %s", pending.Nickname)
		}
		targets[target] = struct{}{}
		request := strings.ToLower(pending.Server) + "\x00" + strings.ToLower(pending.CAName) + fmt.Sprintf("\x00%d", pending.RequestID)
		if _, exists := requests[request]; exists {
			return fmt.Errorf("duplicate pending request ID %d for CA %s", pending.RequestID, pending.CAName)
		}
		requests[request] = struct{}{}
	}
	return nil
}

func writeStateFile(path string, state *enrollmentState) error {
	if err := validateUniqueNicknames(state); err != nil {
		return err
	}
	if err := mkdirAllWithoutSymlinks(filepath.Dir(path), 0750); err != nil {
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
		clone.CAs[i].ChainFingerprints = append([]string(nil), state.CAs[i].ChainFingerprints...)
		clone.CAs[i].RootCerts = append([]string(nil), state.CAs[i].RootCerts...)
		clone.CAs[i].IntermediateCerts = append([]string(nil), state.CAs[i].IntermediateCerts...)
		clone.CAs[i].Symlinks = append([]string(nil), state.CAs[i].Symlinks...)
		clone.CAs[i].Templates = append([]enrolledTemplate(nil), state.CAs[i].Templates...)
		for j := range clone.CAs[i].Templates {
			clone.CAs[i].Templates[j].ChainFingerprints = append([]string(nil), state.CAs[i].Templates[j].ChainFingerprints...)
			clone.CAs[i].Templates[j].ChainFiles = append([]string(nil), state.CAs[i].Templates[j].ChainFiles...)
		}
	}
	clone.Pending = append([]pendingEnrollment(nil), state.Pending...)
	for i := range clone.Pending {
		clone.Pending[i].ChainFingerprints = append([]string(nil), state.Pending[i].ChainFingerprints...)
		clone.Pending[i].ChainFiles = append([]string(nil), state.Pending[i].ChainFiles...)
		clone.Pending[i].RootCerts = append([]string(nil), state.Pending[i].RootCerts...)
		clone.Pending[i].IntermediateCerts = append([]string(nil), state.Pending[i].IntermediateCerts...)
		clone.Pending[i].Symlinks = append([]string(nil), state.Pending[i].Symlinks...)
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

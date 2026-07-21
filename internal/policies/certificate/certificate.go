// Package certificate provides a manager that handles certificate
// autoenrollment.
//
// This manager only applies to computer objects.
//
// Two enrollment methods are supported, selectable via configuration:
//
//   - "ldap" (default for new installations): Pure Go implementation that
//     discovers CAs and templates from LDAP, installs root CA certificates,
//     and submits CSRs directly to AD CS in-process using the MS-ICPR protocol
//     (DCOM/RPC), writing the issued certificate and private key to disk.
//
//   - "cepces" (default for existing installations): Legacy implementation that
//     delegates to an embedded Python script which uses vendored Samba code and
//     the CEPCES helper for certificate enrollment via certmonger.
//
// If the GPO is disabled/not configured, the manager will unenroll the machine
// by removing the issued certificates, updating the system trust store, and
// clearing the persisted enrollment state.
package certificate

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	_ "embed" // embed cert enroll python script
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/leonelquinteros/gotext"
	"github.com/ubuntu/adsys/internal/consts"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/smbsafe"
	"github.com/ubuntu/decorate"
)

const (
	// See [MS-CAESO] 4.4.5.1.
	enrollFlag   int = 0x1
	disabledFlag int = 0x8000

	policyServersPrefix                   = "Software/Policies/Microsoft/Cryptography/PolicyServers/"
	policyServerAutoEnrollmentEnabledFlag = 0x10
)

// gpoEntry is a single GPO registry entry to be serialised to JSON in a format
// Samba expects. Used only by the CEPCES enrollment method.
type gpoEntry struct {
	KeyName   string `json:"keyname"`
	ValueName string `json:"valuename"`
	Data      any    `json:"data"`
	Type      int    `json:"type"`
}

// integerGPOValues is a list of GPO registry values that contain integer data.
var integerGPOValues = []string{"AuthFlags", "Cost", "Flags"}

// trustLifecycleMu protects the complete state-and-artifact lifecycle across
// Manager instances. Individual trust installation helpers intentionally do
// not acquire it, because one lifecycle may prepare several CA installations.
var trustLifecycleMu sync.RWMutex

const (
	gpoTypeString  int = 1 // REG_SZ
	gpoTypeInteger int = 4 // REG_DWORD
)

// CertEnrollCode is the embedded Python script which requests
// Samba to autoenroll for certificates using the given GPOs.
// Used only by the CEPCES enrollment method.
//
//go:embed cert-autoenroll
var CertEnrollCode string

// Manager handles certificate autoenrollment policy application.
type Manager struct {
	domain           string
	stateDir         string
	krb5CacheDir     string
	globalTrustDir   string
	enrollmentMethod string

	// Fields used by "ldap" enrollment method.
	ldapConnect         LDAPConnector
	requestCertificate  Requester
	installChain        func(certAuthority, string, string) (*caChainInstallation, error)
	publishGeneration   func(string, []byte, []byte, generationPublishOps) (generationPaths, error)
	saveEnrollmentState func(string, *enrollmentState) error

	// Fields used by "cepces" enrollment method.
	vendorPythonDir string
	certEnrollCmd   []string

	mu sync.Mutex
}

type options struct {
	stateDir           string
	runDir             string
	shareDir           string
	globalTrustDir     string
	enrollmentMethod   string
	ldapConnect        LDAPConnector
	requestCertificate Requester
	certAutoenrollCmd  []string
}

// Option represents an optional function to change the certificate manager.
type Option func(*options)

// WithStateDir overrides the default state directory.
func WithStateDir(p string) func(*options) {
	return func(a *options) {
		a.stateDir = p
	}
}

// WithRunDir overrides the default run directory.
func WithRunDir(p string) func(*options) {
	return func(a *options) {
		a.runDir = p
	}
}

// WithShareDir overrides the default share directory.
func WithShareDir(p string) func(*options) {
	return func(a *options) {
		a.shareDir = p
	}
}

// WithGlobalTrustDir overrides the default global trust store directory.
func WithGlobalTrustDir(p string) func(*options) {
	return func(a *options) {
		a.globalTrustDir = p
	}
}

// WithLDAPConnector overrides the LDAP connector (for testing).
func WithLDAPConnector(c LDAPConnector) func(*options) {
	return func(a *options) {
		a.ldapConnect = c
	}
}

// WithCertificateRequester overrides the typed submit/poll client (for testing).
func WithCertificateRequester(requester Requester) func(*options) {
	return func(a *options) {
		a.requestCertificate = requester
	}
}

// WithEnrollmentMethod overrides the certificate enrollment method.
// Valid values are "ldap" and "cepces".
func WithEnrollmentMethod(method string) func(*options) {
	return func(a *options) {
		if normalized, ok := normalizeEnrollmentMethod(method); ok {
			a.enrollmentMethod = normalized
		}
	}
}

// WithCertAutoenrollCmd overrides the default certificate autoenroll command
// used by the CEPCES enrollment method.
func WithCertAutoenrollCmd(cmd []string) func(*options) {
	return func(a *options) {
		a.certAutoenrollCmd = cmd
	}
}

// New returns a new manager for the certificate policy.
func New(domain string, opts ...Option) *Manager {
	// defaults
	args := options{
		stateDir:          consts.DefaultStateDir,
		runDir:            consts.DefaultRunDir,
		shareDir:          consts.DefaultShareDir,
		globalTrustDir:    consts.DefaultGlobalTrustDir,
		enrollmentMethod:  consts.DefaultCertificateEnrollment,
		certAutoenrollCmd: []string{"python3", "-c", CertEnrollCode},
	}
	// applied options
	for _, o := range opts {
		o(&args)
	}

	krb5CacheDir := filepath.Join(args.runDir, "krb5cc")

	m := &Manager{
		domain:              domain,
		stateDir:            args.stateDir,
		krb5CacheDir:        krb5CacheDir,
		globalTrustDir:      args.globalTrustDir,
		enrollmentMethod:    args.enrollmentMethod,
		installChain:        installCAChainTransaction,
		publishGeneration:   publishCertificateGeneration,
		saveEnrollmentState: saveState,
	}

	switch m.enrollmentMethod {
	case consts.CertEnrollmentLDAP:
		// Use the provided LDAP connector, or create the default one that
		// performs GSSAPI bind using the machine's Kerberos credential cache.
		ldapConnect := args.ldapConnect
		if ldapConnect == nil {
			// allowBootstrap: on the first enrollment the enterprise CA is not
			// installed yet; adsys discovers and installs it during this run, so
			// LDAP discovery is protected by Kerberos confidentiality until the
			// DC's StartTLS certificate chains to managed trust.
			ldapConnect = newKerberosLDAPConnector(krb5CacheDir, args.globalTrustDir, true)
		}

		// Use the provided requester, or create the default one that
		// authenticates to AD CS using the machine's Kerberos credential cache.
		requester := args.requestCertificate
		if requester == nil {
			requester = newCertificateRequester(krb5CacheDir)
		}

		m.ldapConnect = ldapConnect
		m.requestCertificate = requester
	default:
		// CEPCES (legacy) enrollment method
		m.vendorPythonDir = filepath.Join(args.shareDir, "python")
		m.certEnrollCmd = args.certAutoenrollCmd
	}

	return m
}

func normalizeEnrollmentMethod(method string) (string, bool) {
	method = strings.ToLower(strings.TrimSpace(method))
	switch method {
	case "":
		return "", false
	case consts.CertEnrollmentLDAP, consts.CertEnrollmentCEPCES:
		return method, true
	default:
		return "", false
	}
}

// ApplyPolicy applies the certificate autoenrollment policy.
func (m *Manager) ApplyPolicy(ctx context.Context, objectName string, isComputer, isOnline bool, entries []entry.Entry) (err error) {
	defer decorate.OnError(&err, gotext.Get("can't apply certificate policy"))

	m.mu.Lock()
	defer m.mu.Unlock()

	if !isComputer {
		log.Debug(ctx, "Certificate policy is only supported for computers, skipping...")
		return nil
	}

	if !isOnline {
		log.Debug(ctx, gotext.Get("AD backend is offline, skipping certificate policy"))
		return nil
	}

	trustLifecycleMu.Lock()
	defer trustLifecycleMu.Unlock()

	switch m.enrollmentMethod {
	case consts.CertEnrollmentLDAP:
		return m.applyPolicyLDAP(ctx, objectName, entries)
	default:
		return m.applyPolicyCEPCES(ctx, objectName, entries)
	}
}

// applyPolicyLDAP implements the native Go LDAP/RPC enrollment path.
func (m *Manager) applyPolicyLDAP(ctx context.Context, objectName string, entries []entry.Entry) error {
	idx := slices.IndexFunc(entries, func(e entry.Entry) bool { return e.Key == "autoenroll" })
	if idx == -1 {
		// Check if we have existing enrollment state or legacy Samba cache to clean up
		existingState, stateErr := loadState(m.stateDir, objectName, m.domain)
		_, sambaErr := os.Stat(filepath.Join(m.stateDir, "samba"))
		hasSambaCache := sambaErr == nil

		if existingState == nil && stateErr == nil && !hasSambaCache {
			return nil
		}
		if stateErr != nil {
			return fmt.Errorf("failed to load existing enrollment state before unenrollment: %w", stateErr)
		}

		log.Debug(ctx, "Certificate autoenrollment is not configured, unenrolling machine")
		return m.unenrollLocked(ctx, objectName)
	}

	log.Debug(ctx, "ApplyPolicy certificate policy")

	e := entries[idx]
	value, err := strconv.Atoi(e.Value)
	if err != nil {
		return errors.New(gotext.Get("failed to parse certificate policy entry value: %v", err))
	}

	if value&disabledFlag == disabledFlag {
		log.Debug(ctx, "Certificate policy is disabled, skipping...")
		return nil
	}

	log.Debugf(ctx, "Certificate policy value: %d", value)

	if value&enrollFlag != enrollFlag {
		return m.unenrollLocked(ctx, objectName)
	}

	allowed, err := ldapPolicyAllowsEnrollment(entries)
	if err != nil {
		return err
	}
	if !allowed {
		log.Debug(ctx, "Certificate enrollment policy has no enabled LDAP endpoint, skipping")
		return nil
	}

	return m.enrollLocked(ctx, objectName)
}

// applyPolicyCEPCES implements the legacy CEPCES/Python enrollment path.
func (m *Manager) applyPolicyCEPCES(ctx context.Context, objectName string, entries []entry.Entry) error {
	idx := slices.IndexFunc(entries, func(e entry.Entry) bool { return e.Key == "autoenroll" })
	if idx == -1 {
		// If the Samba cache directory doesn't exist, we don't have anything to unenroll
		if _, err := os.Stat(filepath.Join(m.stateDir, "samba")); err != nil && os.IsNotExist(err) {
			return nil
		}

		log.Debug(ctx, "Certificate autoenrollment is not configured, unenrolling machine")
		if err := m.runScript(ctx, "unenroll", objectName); err != nil {
			return err
		}

		return nil
	}

	log.Debug(ctx, "ApplyPolicy certificate policy")

	e := entries[idx]
	value, err := strconv.Atoi(e.Value)
	if err != nil {
		return errors.New(gotext.Get("failed to parse certificate policy entry value: %v", err))
	}

	if value&disabledFlag == disabledFlag {
		log.Debug(ctx, "Certificate policy is disabled, skipping...")
		return nil
	}

	var polSrvRegistryEntries []gpoEntry
	for _, entry := range entries {
		if entry.Key == "autoenroll" {
			continue
		}

		// Samba expects the key parts to be joined by backslashes
		keyparts := strings.Split(entry.Key, "/")
		keyname := strings.Join(keyparts[:len(keyparts)-1], `\`)
		valuename := keyparts[len(keyparts)-1]
		gpoData, err := gpoData(entry.Value, valuename)
		if err != nil {
			return errors.New(gotext.Get("failed to parse policy entry value: %v", err))
		}
		polSrvRegistryEntries = append(polSrvRegistryEntries, gpoEntry{keyname, valuename, gpoData, gpoType(valuename)})

		log.Debugf(ctx, "Certificate policy entry: %#v", entry)
	}

	var action string
	log.Debugf(ctx, "Certificate policy value: %d", value)
	action = "unenroll"
	if value&enrollFlag == enrollFlag {
		action = "enroll"
	}

	jsonGPOData, err := json.Marshal(polSrvRegistryEntries)
	if err != nil {
		return errors.New(gotext.Get("failed to marshal policy server registry entries: %v", err))
	}

	if err := m.runScript(ctx, action, objectName, "--policy_servers_json", string(jsonGPOData), "--debug"); err != nil {
		return err
	}

	return nil
}

// runScript runs the certificate autoenrollment script with the given arguments.
// Used only by the CEPCES enrollment method.
func (m *Manager) runScript(ctx context.Context, action, objectName string, extraArgs ...string) error {
	scriptArgs := []string{action, objectName, m.domain, "--state_dir", m.stateDir, "--global_trust_dir", m.globalTrustDir}
	scriptArgs = append(scriptArgs, extraArgs...)
	cmdArgs := append(m.certEnrollCmd, scriptArgs...)
	cmdCtx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	log.Debugf(ctx, "Running cert autoenroll script with arguments: %q", strings.Join(scriptArgs, " "))
	// #nosec G204 - cmdArgs is under our control (python embedded script or mock for tests)
	cmd := exec.CommandContext(cmdCtx, cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("KRB5CCNAME=%s", filepath.Join(m.krb5CacheDir, objectName)),
		fmt.Sprintf("PYTHONPATH=%s:%s", os.Getenv("PYTHONPATH"), m.vendorPythonDir),
	)
	smbsafe.WaitExec()
	defer smbsafe.DoneExec()

	output, err := cmd.CombinedOutput()
	defer log.Debugf(ctx, "Certificate autoenrollment script output:\n%s", strings.ReplaceAll(string(output), "\\n", "\n"))
	if err != nil {
		return errors.New(gotext.Get("failed to run certificate autoenrollment script (exited with %d): %v\n%s", cmd.ProcessState.ExitCode(), err, string(output)))
	}
	log.Info(ctx, gotext.Get("Certificate autoenrollment script ran successfully\n"))
	return nil
}

// enroll performs a complete enrollment lifecycle when called directly.
func (m *Manager) enroll(ctx context.Context, objectName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	trustLifecycleMu.Lock()
	defer trustLifecycleMu.Unlock()
	return m.enrollLocked(ctx, objectName)
}

// enrollLocked performs the full enrollment flow:
//  1. Discovers and verifies CA chains from LDAP
//  2. Authorizes published templates against the machine token
//  3. Installs discovered root CA certificates
//  4. Requests and verifies certificates directly from AD CS
//  5. Saves CA/domain-bound enrollment state
//
// The caller must hold m.mu and trustLifecycleMu for writing.
func (m *Manager) enrollLocked(ctx context.Context, objectName string) error {
	existingState, err := loadState(m.stateDir, objectName, m.domain)
	if err != nil {
		return fmt.Errorf("failed to load existing enrollment state: %w", err)
	}
	if existingState != nil {
		log.Debugf(ctx, "Loaded existing enrollment state with %d CAs and %d pending requests", len(existingState.CAs), len(existingState.Pending))
		pollSummary := m.pollPendingEnrollments(ctx, existingState, nil, nil)
		if len(pollSummary.Errors) != 0 {
			return errors.Join(pollSummary.Errors...)
		}
	}

	server := dcHostnameFromDomain(m.domain)
	log.Debugf(ctx, "Discovering CAs from LDAP server: %s", server)

	directoryData, err := discoverEnrollmentDirectoryData(ctx, m.ldapConnect, server, objectName, m.domain)
	if err != nil {
		return fmt.Errorf("failed to discover enrollment configuration: %w", err)
	}

	if directoryData.PublishedCAs == 0 {
		if existingState != nil && len(existingState.Pending) != 0 {
			return fmt.Errorf("%w: %d request(s)", ErrEnrollmentPending, len(existingState.Pending))
		}
		log.Info(ctx, "No certificate authorities found in AD, skipping enrollment")
		return nil
	}
	cas := directoryData.CAs
	if len(cas) == 0 {
		if existingState != nil && len(existingState.Pending) != 0 {
			return fmt.Errorf("%w: %d request(s)", ErrEnrollmentPending, len(existingState.Pending))
		}
		return fmt.Errorf("no published certificate templates are eligible for machine autoenrollment")
	}

	log.Debugf(ctx, "Discovered %d eligible certificate authorities from LDAP", len(cas))

	// Ensure directories exist
	trustDir := filepath.Join(m.stateDir, "certs")
	privateDir := filepath.Join(m.stateDir, "private", "certs")
	for _, dir := range []string{trustDir, m.globalTrustDir} {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}
	if err := os.MkdirAll(privateDir, 0700); err != nil {
		return fmt.Errorf("failed to create private directory: %w", err)
	}

	attrsByName := directoryData.TemplateAttrs
	machineIdentity := directoryData.MachineIdentity.dnsName

	type preparedEnrollmentCA struct {
		authority    certAuthority
		installation *caChainInstallation
		binding      templateChainBinding
		preserved    *enrolledCA
		skip         bool
		durable      bool
	}
	preparedCAs := make([]*preparedEnrollmentCA, 0, len(cas))
	rollbackPrepared := func() error {
		var errs []error
		for _, prepared := range preparedCAs {
			if prepared.installation != nil && !prepared.durable {
				if err := prepared.installation.rollback(); err != nil {
					errs = append(errs, err)
				}
			}
		}
		return errors.Join(errs...)
	}
	for _, ca := range cas {
		prepared := &preparedEnrollmentCA{authority: ca}
		installation, err := m.installChain(ca, trustDir, m.globalTrustDir)
		if err != nil {
			if containsRollbackFailure(err) {
				return errors.Join(
					fmt.Errorf("installing verified CA chain for %s left trust artifacts behind: %w", ca.Name, err),
					rollbackContext("prepared CA chain installations", rollbackPrepared()),
				)
			}
			previousCA, found := existingCAEnrollment(existingState, ca.Name, ca.Hostname)
			if !found {
				log.Warningf(ctx, "Skipping CA %s: could not install its verified CA chain: %v", ca.Name, err)
				prepared.skip = true
				preparedCAs = append(preparedCAs, prepared)
				continue
			}
			preserved, validationErr := validatePreviousCAForPreservation(
				previousCA,
				existingState,
				machineIdentity,
				normalizeDomainIdentity(m.domain),
				time.Now(),
			)
			if validationErr != nil {
				return fmt.Errorf("could not install current chain for CA %s and previous enrollment cannot be safely preserved: %w", ca.Name, errors.Join(
					fmt.Errorf("installing current chain: %w", err),
					fmt.Errorf("validating previous state: %w", validationErr),
					rollbackContext("prepared CA chain installations", rollbackPrepared()),
				))
			}
			log.Warningf(ctx, "Could not install current chain for CA %s; preserving its validated previous enrollment: %v", ca.Name, err)
			prepared.preserved = &preserved
			preparedCAs = append(preparedCAs, prepared)
			continue
		}
		currentBinding, err := chainBindingFromInstallation(ca.Chain, installation)
		if err != nil {
			return errors.Join(
				fmt.Errorf("failed to bind installed CA chain for %s: %w", ca.Name, err),
				rollbackContext("installed CA chain", installation.rollback()),
				rollbackContext("prepared CA chain installations", rollbackPrepared()),
			)
		}
		prepared.installation = installation
		prepared.binding = currentBinding
		preparedCAs = append(preparedCAs, prepared)
	}

	var enrolledCAs []enrolledCA
	var rollbackErrs []error
	var enrollmentErrs []error
	var publications []generationPaths
	for _, prepared := range preparedCAs {
		ca := prepared.authority
		if prepared.skip {
			continue
		}
		if prepared.preserved != nil {
			enrolledCAs = append(enrolledCAs, *prepared.preserved)
			continue
		}
		log.Debugf(ctx, "Processing CA: %s (%s) with %d templates", ca.Name, ca.Hostname, len(ca.Templates))
		installation := prepared.installation
		currentBinding := prepared.binding
		var enrolledTemplates []enrolledTemplate
		for _, tmplName := range ca.Templates {
			var previousValidated *enrolledTemplate
			if previousCA, tmpl, ok := existingEnrollment(existingState, ca.Name, ca.Hostname, tmplName); ok {
				validated, validationErr := validateStoredEnrollment(previousCA, tmpl, existingState, ca, currentBinding, machineIdentity, normalizeDomainIdentity(m.domain), time.Now())
				if validationErr != nil {
					log.Warningf(ctx, "Existing certificate for template %s on CA %s is not reusable: %v", tmplName, ca.Name, validationErr)
				} else {
					previousValidated = &validated
				}
				if previousValidated != nil && !certNeedsRenewal(ctx, tmpl) {
					log.Debugf(ctx, "Template %s for CA %s is bound to the current domain and CA chain, reusing existing cert files", tmplName, ca.Name)
					enrolledTemplates = append(enrolledTemplates, *previousValidated)
					continue
				}
			}

			attrs, ok := attrsByName[tmplName]
			if !ok {
				log.Warningf(ctx, "Skipping template %s on CA %s: LDAP attributes are unavailable", tmplName, ca.Name)
				continue
			}
			log.Debugf(ctx, "Template %s requires minimum key size: %d bits", attrs.Name, attrs.MinKeySize)

			// CA and template names come from LDAP and are used to build the
			// human-readable nickname, so sanitize them to avoid unexpected or
			// traversing filenames. On-disk key/cert paths additionally embed a
			// raw-identity hash so distinct CA identities that sanitize to the
			// same nickname (e.g. "Corp CA" vs "Corp-CA") never share files.
			nickname := managementNickname(ca.Name, ca.Hostname, tmplName)
			artifactBase := leafArtifactBase(objectName, ca, tmplName)
			target := enrollmentTarget{
				ObjectName:        objectName,
				Domain:            normalizeDomainIdentity(m.domain),
				Identity:          machineIdentity,
				CAName:            ca.Name,
				Server:            ca.Hostname,
				Template:          attrs.Name,
				Nickname:          nickname,
				GenerationRoot:    filepath.Join(privateDir, artifactBase),
				Binding:           currentBinding,
				RootCerts:         append([]string(nil), installation.RootFiles...),
				IntermediateCerts: append([]string(nil), installation.IntermediateFiles...),
				Symlinks:          append([]string(nil), installation.SymlinkFiles...),
				Renewal:           previousValidated != nil,
			}
			if pending, ok := pendingForTarget(existingState, ca.Name, ca.Hostname, attrs.Name); ok {
				if err := pendingMatchesTarget(pending, target); err != nil {
					enrollmentErrs = append(enrollmentErrs, fmt.Errorf("pending request %d for %s no longer matches current enrollment target: %w", pending.RequestID, nickname, err))
				}
				if previousValidated != nil {
					enrolledTemplates = append(enrolledTemplates, *previousValidated)
				}
				prepared.durable = true
				continue
			}

			result, requestErr := m.requestNewCertificate(ctx, target, attrs.MinKeySize, ca.Chain.Certificates)
			if requestErr != nil {
				enrollmentErrs = append(enrollmentErrs, fmt.Errorf("%s: %w", nickname, requestErr))
				log.Warningf(ctx, "Failed to request certificate for template %s: %v", tmplName, requestErr)
				if previousValidated != nil {
					log.Infof(ctx, "Retaining still-valid certificate for template %s after failed renewal", tmplName)
					enrolledTemplates = append(enrolledTemplates, *previousValidated)
				}
				continue
			}
			if result.Pending != nil {
				working := cloneEnrollmentState(existingState)
				if working == nil {
					working = &enrollmentState{
						ObjectName: objectName,
						Identity:   machineIdentity,
						Domain:     normalizeDomainIdentity(m.domain),
					}
				}
				if err := addPendingEnrollment(working, *result.Pending); err != nil {
					cleanupErr := removePendingMaterial(m.stateDir, *result.Pending)
					enrollmentErrs = append(enrollmentErrs, errors.Join(err, cleanupErr))
				} else if err := m.saveEnrollmentState(m.stateDir, working); err != nil {
					cleanupErr := removePendingMaterial(m.stateDir, *result.Pending)
					enrollmentErrs = append(enrollmentErrs, errors.Join(fmt.Errorf("saving pending request %d: %w", result.Pending.RequestID, err), cleanupErr))
				} else {
					existingState = working
					prepared.durable = true
					log.Infof(ctx, "Certificate request %d for template %s is pending CA approval", result.Pending.RequestID, tmplName)
				}
				if previousValidated != nil {
					enrolledTemplates = append(enrolledTemplates, *previousValidated)
				}
				continue
			}

			log.Debugf(ctx, "Successfully enrolled certificate for template %s from CA %s", attrs.Name, ca.Name)
			publications = append(publications, result.Publication)
			if result.PublishErr != nil {
				enrollmentErrs = append(enrollmentErrs, fmt.Errorf("publishing certificate generation for %s: %w", nickname, result.PublishErr))
			}
			enrolledTemplates = append(enrolledTemplates, result.Template)
		}

		if len(enrolledTemplates) == 0 {
			log.Warningf(ctx, "No issued certificate templates enrolled for CA %s, skipping", ca.Name)
			if !prepared.durable {
				if err := installation.rollback(); err != nil {
					rollbackErrs = append(rollbackErrs, fmt.Errorf("rolling back unused CA chain for %s: %w", ca.Name, err))
				}
			}
			continue
		}

		enrolledCA := enrolledCA{
			Name:              ca.Name,
			Hostname:          ca.Hostname,
			IssuerFingerprint: ca.Chain.issuerFingerprint(),
			ChainFingerprints: append([]string(nil), ca.Chain.Fingerprints...),
			RootCerts:         append([]string(nil), installation.RootFiles...),
			IntermediateCerts: append([]string(nil), installation.IntermediateFiles...),
			Symlinks:          append([]string(nil), installation.SymlinkFiles...),
			Templates:         enrolledTemplates,
		}
		if err := rebuildCAArtifacts(&enrolledCA); err != nil {
			trustRollbackErr := rollbackPrepared()
			return errors.Join(append([]error{
				fmt.Errorf("building enrollment state for CA %s: %w", ca.Name, err),
				rollbackContext("prepared CA chain installations", trustRollbackErr),
			}, rollbackErrs...)...)
		}
		enrolledCAs = append(enrolledCAs, enrolledCA)
	}

	if len(enrolledCAs) == 0 {
		if existingState != nil && len(existingState.Pending) != 0 {
			pendingErr := fmt.Errorf("%w: %d request(s)", ErrEnrollmentPending, len(existingState.Pending))
			return errors.Join(append([]error{pendingErr}, enrollmentErrs...)...)
		}
		return errors.Join(append([]error{
			fmt.Errorf("could not enroll to any certificate authorities out of %d discovered", len(cas)),
		}, append(rollbackErrs, enrollmentErrs...)...)...)
	}

	log.Debugf(ctx, "Saving enrollment state for %s with %d enrolled CAs", objectName, len(enrolledCAs))
	state := &enrollmentState{
		ObjectName: objectName,
		Identity:   machineIdentity,
		Domain:     normalizeDomainIdentity(m.domain),
		CAs:        enrolledCAs,
	}
	if existingState != nil {
		state.Pending = append([]pendingEnrollment(nil), existingState.Pending...)
	}
	if err := m.saveEnrollmentState(m.stateDir, state); err != nil {
		return errors.Join(append([]error{
			fmt.Errorf("failed to save enrollment state: %w", err),
			rollbackContext("prepared CA chain installations", rollbackPrepared()),
		}, append(rollbackErrs, enrollmentErrs...)...)...)
	}

	var terminalErrs []error
	terminalErrs = append(terminalErrs, rollbackErrs...)
	terminalErrs = append(terminalErrs, enrollmentErrs...)
	for _, publication := range publications {
		if publication.MarkerFile == "" {
			continue
		}
		if err := finalizeGenerationPublication(publication); err != nil {
			terminalErrs = append(terminalErrs, err)
		}
	}
	if existingState != nil {
		if err := cleanupOrphanedCerts(ctx, m.stateDir, m.globalTrustDir, m.domain, existingState, state); err != nil {
			terminalErrs = append(terminalErrs, fmt.Errorf("cleaning up obsolete enrollment artifacts: %w", err))
		}
	}
	if err := updateCATrustStore(); err != nil {
		log.Warningf(ctx, "Failed to update CA trust store after enrollment: %v", err)
	}

	caNames := make([]string, 0, len(enrolledCAs))
	for _, ca := range enrolledCAs {
		caNames = append(caNames, ca.Name)
	}
	log.Infof(ctx, "Enrolled to certificate authorities: %s", strings.Join(caNames, ", "))
	if len(state.Pending) != 0 {
		terminalErrs = append(terminalErrs, fmt.Errorf("%w: %d request(s)", ErrEnrollmentPending, len(state.Pending)))
	}

	return errors.Join(terminalErrs...)
}

// unenrollLocked removes all certificate enrollments and cleans up state. The
// caller must hold m.mu and trustLifecycleMu for writing.
func (m *Manager) unenrollLocked(ctx context.Context, objectName string) error {
	state, err := loadState(m.stateDir, objectName, m.domain)
	if err != nil {
		return fmt.Errorf("failed to load enrollment state: %w", err)
	}

	var obsoleteChainPaths []string
	var cleanupErrs []error
	if state != nil {
		log.Debugf(ctx, "Unenrolling %d certificate authorities", len(state.CAs))
		for _, ca := range state.CAs {
			log.Debugf(ctx, "Removing certificates for CA %s (%d templates)", ca.Name, len(ca.Templates))
			// Do not delete key/cert/chain paths directly: another object's
			// state may reference the same files. Route every candidate through
			// removeUnreferencedPaths below, which honors other state files.
			for _, tmpl := range ca.Templates {
				log.Debugf(ctx, "Removing certificate files for template %s", tmpl.Nickname)
				obsoleteChainPaths = append(obsoleteChainPaths, tmpl.CertFile, tmpl.KeyFile)
				obsoleteChainPaths = append(obsoleteChainPaths, generationArtifactPaths(tmpl)...)
				obsoleteChainPaths = append(obsoleteChainPaths, tmpl.ChainFiles...)
				if tmpl.TrustAnchorSymlink != "" {
					obsoleteChainPaths = append(obsoleteChainPaths, tmpl.TrustAnchorSymlink)
				}
			}
			obsoleteChainPaths = append(obsoleteChainPaths, ca.RootCerts...)
			obsoleteChainPaths = append(obsoleteChainPaths, ca.IntermediateCerts...)
			obsoleteChainPaths = append(obsoleteChainPaths, ca.Symlinks...)
		}
		for _, pending := range state.Pending {
			pendingPaths, err := pendingArtifactRemovalPaths(m.stateDir, m.globalTrustDir, pending)
			if err != nil {
				cleanupErrs = append(cleanupErrs, fmt.Errorf("validating pending request %d artifacts before removal: %w", pending.RequestID, err))
			} else {
				obsoleteChainPaths = append(obsoleteChainPaths, pendingPaths...)
			}
		}
	}

	// Clean up legacy Samba cache if present.
	sambaDir := filepath.Join(m.stateDir, "samba")
	if _, err := os.Stat(sambaDir); err == nil {
		log.Debugf(ctx, "Removing legacy Samba cache directory: %s", sambaDir)
		if err := os.RemoveAll(sambaDir); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("removing legacy Samba cache: %w", err))
		}
	} else if !os.IsNotExist(err) {
		cleanupErrs = append(cleanupErrs, fmt.Errorf("inspecting legacy Samba cache: %w", err))
	}

	if err := removeState(m.stateDir, objectName, m.domain); err != nil {
		cleanupErrs = append(cleanupErrs, fmt.Errorf("removing enrollment state: %w", err))
	} else {
		if err := removeUnreferencedPaths(ctx, m.stateDir, objectName, m.domain, nil, obsoleteChainPaths); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("removing unreferenced certificate paths: %w", err))
		}
	}
	if state != nil {
		if err := updateCATrustStore(); err != nil {
			log.Warningf(ctx, "Failed to update CA trust store after unenrollment: %v", err)
		}
	}

	if len(cleanupErrs) != 0 {
		return errors.Join(cleanupErrs...)
	}
	log.Info(ctx, "Certificate unenrollment completed")
	return nil
}

// cleanupOrphanedCerts removes certificates, keys, and trust store symlinks
// that exist in the old state but are not present in the new set of enrolled
// CAs. This prevents orphaned files from accumulating when CAs or templates
// are removed from AD.
func cleanupOrphanedCerts(ctx context.Context, stateDir, globalTrustDir, domain string, oldState, replacement *enrollmentState) error {
	newPaths := stateReferencedPaths(replacement)
	var validationErrs []error
	// Remove any old paths not in the new set, logging both successes and
	// failures so a stuck orphan is visible in the daemon logs.
	var orphaned []string
	add := func(path string) {
		if path != "" {
			if _, retained := newPaths[path]; retained {
				return
			}
			orphaned = append(orphaned, path)
		}
	}
	for _, ca := range oldState.CAs {
		for _, link := range ca.Symlinks {
			add(link)
		}
		for _, cert := range ca.RootCerts {
			add(cert)
		}
		for _, cert := range ca.IntermediateCerts {
			add(cert)
		}
		for _, tmpl := range ca.Templates {
			add(tmpl.CertFile)
			add(tmpl.KeyFile)
			for _, path := range generationArtifactPaths(tmpl) {
				add(path)
			}
			for _, path := range tmpl.ChainFiles {
				add(path)
			}
			add(tmpl.TrustAnchorSymlink)
		}
	}
	for _, pending := range oldState.Pending {
		pendingPaths, err := pendingArtifactRemovalPaths(stateDir, globalTrustDir, pending)
		if err != nil {
			validationErrs = append(validationErrs, fmt.Errorf("validating obsolete pending request %d artifacts: %w", pending.RequestID, err))
		}
		for _, path := range pendingPaths {
			add(path)
		}
	}

	return errors.Join(
		errors.Join(validationErrs...),
		removeUnreferencedPaths(ctx, stateDir, oldState.ObjectName, domain, replacement, orphaned),
	)
}

func existingEnrollment(state *enrollmentState, caName, caHostname, template string) (enrolledCA, enrolledTemplate, bool) {
	if state == nil {
		return enrolledCA{}, enrolledTemplate{}, false
	}
	for _, ca := range state.CAs {
		if !strings.EqualFold(ca.Name, caName) || !strings.EqualFold(ca.Hostname, caHostname) {
			continue
		}
		for _, enrolled := range ca.Templates {
			if strings.EqualFold(enrolled.Template, template) {
				return ca, enrolled, true
			}
		}
	}
	return enrolledCA{}, enrolledTemplate{}, false
}

func existingCAEnrollment(state *enrollmentState, caName, hostname string) (enrolledCA, bool) {
	if state == nil {
		return enrolledCA{}, false
	}
	for _, ca := range state.CAs {
		if strings.EqualFold(ca.Name, caName) && strings.EqualFold(ca.Hostname, hostname) {
			return ca, true
		}
	}
	return enrolledCA{}, false
}

// validateStateEnvelope checks the persisted enrollment state envelope (its
// domain and, when present, machine identity) independently of any single
// leaf's current validity. Keeping this separate lets a targeted renewal
// replace an expired, missing or mismatched target leaf as long as the state it
// belongs to is safe.
func validateStateEnvelope(state *enrollmentState, identity, domain string) error {
	if state == nil {
		return fmt.Errorf("enrollment state is missing")
	}
	if normalizeDomainIdentity(state.Domain) != domain {
		return fmt.Errorf("state domain %q does not match %q", state.Domain, domain)
	}
	if state.Identity != "" && normalizeMachineIdentity(state.Identity) != normalizeMachineIdentity(identity) {
		return fmt.Errorf("state machine identity %q does not match %q", state.Identity, identity)
	}
	return nil
}

func validatePreviousCAForPreservation(previousCA enrolledCA, state *enrollmentState, identity, domain string, now time.Time) (enrolledCA, error) {
	if err := validateStateEnvelope(state, identity, domain); err != nil {
		return enrolledCA{}, err
	}
	for i, tmpl := range previousCA.Templates {
		validated, err := validatePersistedTemplate(previousCA, tmpl, identity, now)
		if err != nil {
			return enrolledCA{}, fmt.Errorf("validating template %s: %w", tmpl.Nickname, err)
		}
		previousCA.Templates[i] = validated
	}
	if err := rebuildCAArtifacts(&previousCA); err != nil {
		return enrolledCA{}, err
	}
	return previousCA, nil
}

// leafArtifactBase builds a collision-resistant on-disk basename for a template
// leaf's key and certificate. Distinct object/CA/template raw identities that
// sanitize to the same nickname (for example "Corp CA" and "Corp-CA") would
// otherwise share the same key/cert path; embedding a SHA-256 digest over the
// full unsanitized identity guarantees separate files while keeping the
// readable nickname prefix.
func leafArtifactBase(objectName string, ca certAuthority, template string) string {
	h := sha256.New()
	h.Write([]byte(objectName))
	h.Write([]byte{0})
	h.Write([]byte(ca.Name))
	h.Write([]byte{0})
	h.Write([]byte(ca.Hostname))
	h.Write([]byte{0})
	h.Write([]byte(template))
	digest := hex.EncodeToString(h.Sum(nil))
	return sanitizeName(fmt.Sprintf("%s.%s", ca.Name, template)) + "." + digest[:16]
}

func legacyManagementNickname(caName, template string) string {
	return sanitizeName(fmt.Sprintf("%s.%s", caName, template))
}

// managementNickname keeps the historical readable prefix while binding the
// identifier to the complete raw CA name, hostname, and template. The suffix
// lets management operations target one entry even when raw names sanitize to
// the same prefix.
func managementNickname(caName, caHostname, template string) string {
	h := sha256.New()
	h.Write([]byte(caName))
	h.Write([]byte{0})
	h.Write([]byte(caHostname))
	h.Write([]byte{0})
	h.Write([]byte(template))
	digest := hex.EncodeToString(h.Sum(nil))
	return legacyManagementNickname(caName, template) + "." + digest[:12]
}

// rollbackContext wraps a rollback failure with a description so it can be
// joined into a caller's primary error, or returns nil when the rollback was
// clean.
func rollbackContext(what string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("rolling back %s: %w", what, err)
}

func validateStoredEnrollment(previousCA enrolledCA, tmpl enrolledTemplate, state *enrollmentState, currentCA certAuthority, currentBinding templateChainBinding, identity, domain string, now time.Time) (enrolledTemplate, error) {
	if state == nil {
		return enrolledTemplate{}, fmt.Errorf("enrollment state is missing")
	}
	if normalizeDomainIdentity(state.Domain) != domain {
		return enrolledTemplate{}, fmt.Errorf("state domain %q does not match %q", state.Domain, domain)
	}
	if state.Identity != "" && normalizeMachineIdentity(state.Identity) != normalizeMachineIdentity(identity) {
		return enrolledTemplate{}, fmt.Errorf("state machine identity %q does not match %q", state.Identity, identity)
	}
	if currentCA.Chain == nil || currentCA.Chain.issuer() == nil {
		return enrolledTemplate{}, fmt.Errorf("current CA chain is unavailable")
	}
	if err := validateBindingShape(currentBinding); err != nil {
		return enrolledTemplate{}, fmt.Errorf("current CA chain binding is invalid: %w", err)
	}
	previousBinding, _, _, err := loadTemplateChain(previousCA, tmpl, now)
	if err != nil {
		return enrolledTemplate{}, fmt.Errorf("loading persisted CA chain: %w", err)
	}
	if !strings.EqualFold(previousBinding.IssuerFingerprint, currentBinding.IssuerFingerprint) {
		return enrolledTemplate{}, fmt.Errorf("state issuing CA fingerprint %s does not match discovered CA %s", previousBinding.IssuerFingerprint, currentBinding.IssuerFingerprint)
	}
	if !equalFoldStrings(previousBinding.Fingerprints, currentBinding.Fingerprints) {
		return enrolledTemplate{}, fmt.Errorf("state CA chain fingerprints do not match the discovered chain")
	}

	keyPath, certPath, err := templateGenerationReadPaths(tmpl)
	if err != nil {
		return enrolledTemplate{}, fmt.Errorf("validating certificate generation: %w", err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return enrolledTemplate{}, fmt.Errorf("reading existing certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return enrolledTemplate{}, fmt.Errorf("reading existing private key: %w", err)
	}
	cert, err := verifyIssuedCertificate(string(certPEM), keyPEM, identity, currentCA.Chain.Certificates, now)
	if err != nil {
		return enrolledTemplate{}, err
	}
	leafFingerprint := certificateFingerprint(cert)
	if tmpl.LeafFingerprint != "" && !strings.EqualFold(tmpl.LeafFingerprint, leafFingerprint) {
		return enrolledTemplate{}, fmt.Errorf("state leaf fingerprint %s does not match certificate %s", tmpl.LeafFingerprint, leafFingerprint)
	}
	tmpl.LeafFingerprint = leafFingerprint
	bindTemplateToChain(&tmpl, currentBinding)
	return tmpl, nil
}

func filesExist(paths ...string) bool {
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			return false
		}
	}
	return true
}

// certRenewalWindow is how long before expiry an enrolled certificate is
// re-enrolled on the next policy refresh instead of being reused.
const certRenewalWindow = 30 * 24 * time.Hour

// parseCertFile reads and parses the PEM certificate at path, returning nil if
// it is missing, unreadable, or malformed.
func parseCertFile(path string) *x509.Certificate {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return cert
}

func parseTemplateCert(tmpl enrolledTemplate) *x509.Certificate {
	_, certPath, err := templateGenerationReadPaths(tmpl)
	if err != nil {
		return nil
	}
	return parseCertFile(certPath)
}

// certNeedsRenewal reports whether the certificate for tmpl should be
// re-enrolled rather than reused: it returns true if the file is missing,
// unreadable, unparseable, or within certRenewalWindow of (or past) its
// expiry. Because adsys does not register issued certificates with certmonger,
// this expiry-driven re-enrollment on each policy refresh is what keeps
// machine certificates current.
func certNeedsRenewal(ctx context.Context, tmpl enrolledTemplate) bool {
	cert := parseTemplateCert(tmpl)
	if cert == nil {
		log.Warningf(ctx, "Could not load existing certificate %s, re-enrolling", tmpl.CertFile)
		return true
	}
	if time.Now().Add(certRenewalWindow).After(cert.NotAfter) {
		log.Infof(ctx, "Certificate %s expires at %s (within renewal window), re-enrolling", tmpl.CertFile, cert.NotAfter)
		return true
	}
	return false
}

func ldapPolicyAllowsEnrollment(entries []entry.Entry) (bool, error) {
	type endpoint struct {
		url   string
		flags int
	}

	endpoints := make(map[string]endpoint)
	hasPolicyServerConfig := false
	for _, e := range entries {
		if !strings.HasPrefix(e.Key, policyServersPrefix) {
			continue
		}

		rel := strings.TrimPrefix(e.Key, policyServersPrefix)
		idx := strings.LastIndex(rel, "/")
		if idx == -1 {
			continue
		}
		hasPolicyServerConfig = true

		id, valueName := rel[:idx], rel[idx+1:]
		ep := endpoints[id]
		switch valueName {
		case "URL":
			ep.url = e.Value
		case "Flags":
			flags, err := strconv.Atoi(e.Value)
			if err != nil {
				return false, errors.New(gotext.Get("failed to parse certificate policy server flags: %v", err))
			}
			ep.flags = flags
		}
		endpoints[id] = ep
	}

	if !hasPolicyServerConfig {
		return true, nil
	}

	for _, ep := range endpoints {
		if strings.EqualFold(ep.url, "LDAP:") && ep.flags&policyServerAutoEnrollmentEnabledFlag == policyServerAutoEnrollmentEnabledFlag {
			return true, nil
		}
	}

	return false, nil
}

// gpoData returns the data for a GPO entry.
// Used only by the CEPCES enrollment method.
func gpoData(data, value string) (any, error) {
	if slices.Contains(integerGPOValues, value) {
		return strconv.Atoi(data)
	}

	return data, nil
}

// gpoType returns the type for a GPO entry.
// Used only by the CEPCES enrollment method.
func gpoType(value string) int {
	if slices.Contains(integerGPOValues, value) {
		return gpoTypeInteger
	}

	return gpoTypeString
}

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
	"crypto/x509"
	_ "embed" // embed cert enroll python script
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
	ldapConnect LDAPConnector
	submitCSR   CSRSubmitter

	// Fields used by "cepces" enrollment method.
	vendorPythonDir string
	certEnrollCmd   []string

	mu sync.Mutex
}

type options struct {
	stateDir          string
	runDir            string
	shareDir          string
	globalTrustDir    string
	enrollmentMethod  string
	ldapConnect       LDAPConnector
	submitCSR         CSRSubmitter
	certAutoenrollCmd []string
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

// WithCSRSubmitter overrides the CSR submitter (for testing).
func WithCSRSubmitter(submitter CSRSubmitter) func(*options) {
	return func(a *options) {
		a.submitCSR = submitter
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
		domain:           domain,
		stateDir:         args.stateDir,
		krb5CacheDir:     krb5CacheDir,
		globalTrustDir:   args.globalTrustDir,
		enrollmentMethod: args.enrollmentMethod,
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

		// Use the provided CSR submitter, or create the default one that
		// authenticates to AD CS using the machine's Kerberos credential cache.
		submitCSR := args.submitCSR
		if submitCSR == nil {
			submitCSR = newSubmitCSR(krb5CacheDir)
		}

		m.ldapConnect = ldapConnect
		m.submitCSR = submitCSR
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
		existingState, stateErr := loadState(m.stateDir, objectName)
		_, sambaErr := os.Stat(filepath.Join(m.stateDir, "samba"))
		hasSambaCache := sambaErr == nil

		if existingState == nil && stateErr == nil && !hasSambaCache {
			return nil
		}
		if stateErr != nil {
			log.Warningf(ctx, "Failed to load existing enrollment state, attempting cleanup anyway: %v", stateErr)
		}

		log.Debug(ctx, "Certificate autoenrollment is not configured, unenrolling machine")
		return m.unenroll(ctx, objectName)
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
		return m.unenroll(ctx, objectName)
	}

	allowed, err := ldapPolicyAllowsEnrollment(entries)
	if err != nil {
		return err
	}
	if !allowed {
		log.Debug(ctx, "Certificate enrollment policy has no enabled LDAP endpoint, skipping")
		return nil
	}

	return m.enroll(ctx, objectName)
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

// enroll performs the full enrollment flow:
//  1. Discovers and verifies CA chains from LDAP
//  2. Authorizes published templates against the machine token
//  3. Installs discovered root CA certificates
//  4. Requests and verifies certificates directly from AD CS
//  5. Saves CA/domain-bound enrollment state
func (m *Manager) enroll(ctx context.Context, objectName string) error {
	server := dcHostnameFromDomain(m.domain)
	log.Debugf(ctx, "Discovering CAs from LDAP server: %s", server)

	directoryData, err := discoverEnrollmentDirectoryData(ctx, m.ldapConnect, server, objectName, m.domain)
	if err != nil {
		return fmt.Errorf("failed to discover enrollment configuration: %w", err)
	}

	if directoryData.PublishedCAs == 0 {
		log.Info(ctx, "No certificate authorities found in AD, skipping enrollment")
		return nil
	}
	cas := directoryData.CAs
	if len(cas) == 0 {
		return fmt.Errorf("no published certificate templates are eligible for machine autoenrollment")
	}

	log.Debugf(ctx, "Discovered %d eligible certificate authorities from LDAP", len(cas))

	existingState, err := loadState(m.stateDir, objectName)
	if err != nil {
		log.Warningf(ctx, "Failed to load existing enrollment state: %v", err)
	}
	if existingState != nil {
		log.Debugf(ctx, "Loaded existing enrollment state with %d CAs", len(existingState.CAs))
	}

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

	var enrolledCAs []enrolledCA
	for _, ca := range cas {
		log.Debugf(ctx, "Processing CA: %s (%s) with %d templates", ca.Name, ca.Hostname, len(ca.Templates))

		// Install root CA certificate. If this fails (e.g. the CA cert is
		// malformed, expired, or unverifiable) skip the CA entirely, since
		// certificates issued by it would not validate without its root in
		// the trust store.
		rootFiles, intermediateFiles, symlinkFiles, err := installCAChain(ca, trustDir, m.globalTrustDir)
		if err != nil {
			log.Warningf(ctx, "Skipping CA %s: could not install its verified CA chain: %v", ca.Name, err)
			removeCAChainCerts(rootFiles, intermediateFiles, symlinkFiles)
			continue
		}

		var enrolledTemplates []enrolledTemplate
		for _, tmplName := range ca.Templates {
			if previousCA, tmpl, ok := existingEnrollment(existingState, ca.Name, tmplName); ok {
				validated, validationErr := validateStoredEnrollment(previousCA, tmpl, existingState, ca, machineIdentity, normalizeDomainIdentity(m.domain), time.Now())
				if validationErr != nil {
					log.Warningf(ctx, "Existing certificate for template %s on CA %s is not reusable: %v", tmplName, ca.Name, validationErr)
				} else if !certNeedsRenewal(ctx, tmpl.CertFile) {
					log.Debugf(ctx, "Template %s for CA %s is bound to the current domain and CA chain, reusing existing cert files", tmplName, ca.Name)
					enrolledTemplates = append(enrolledTemplates, validated)
					continue
				}
			}

			attrs, ok := attrsByName[tmplName]
			if !ok {
				log.Warningf(ctx, "Skipping template %s on CA %s: LDAP attributes are unavailable", tmplName, ca.Name)
				continue
			}
			log.Debugf(ctx, "Template %s requires minimum key size: %d bits", attrs.Name, attrs.MinKeySize)

			// CA and template names come from LDAP and are used to build on-disk
			// paths, so sanitize them to avoid unexpected or traversing filenames.
			nickname := sanitizeName(fmt.Sprintf("%s.%s", ca.Name, tmplName))
			keyFile := filepath.Join(privateDir, nickname+".key")
			certFile := filepath.Join(trustDir, nickname+".crt")

			if err := EnrollCertificate(ctx, m.submitCSR, EnrollmentRequest{
				Server:        ca.Hostname,
				CAName:        ca.Name,
				Template:      attrs.Name,
				CommonName:    machineIdentity,
				KeyFile:       keyFile,
				CertFile:      certFile,
				KeySize:       attrs.MinKeySize,
				ExpectedChain: ca.Chain.Certificates,
			}); err != nil {
				log.Warningf(ctx, "Failed to request certificate for template %s: %v", tmplName, err)
				// A failed renewal may retain only material that still validates
				// against the current machine identity, key and selected CA chain.
				if previousCA, tmpl, ok := existingEnrollment(existingState, ca.Name, tmplName); ok {
					validated, validationErr := validateStoredEnrollment(previousCA, tmpl, existingState, ca, machineIdentity, normalizeDomainIdentity(m.domain), time.Now())
					if validationErr != nil {
						continue
					}
					log.Infof(ctx, "Retaining still-valid certificate for template %s after failed renewal", tmplName)
					enrolledTemplates = append(enrolledTemplates, validated)
				}
				continue
			}

			log.Debugf(ctx, "Successfully enrolled certificate for template %s from CA %s", attrs.Name, ca.Name)
			issuedCert := parseCertFile(certFile)
			if issuedCert == nil {
				log.Warningf(ctx, "Issued certificate for template %s could not be reloaded after enrollment", tmplName)
				continue
			}
			enrolledTemplates = append(enrolledTemplates, enrolledTemplate{
				Nickname:        nickname,
				Template:        attrs.Name,
				KeyFile:         keyFile,
				CertFile:        certFile,
				LeafFingerprint: certificateFingerprint(issuedCert),
			})
		}

		if len(enrolledTemplates) == 0 {
			log.Warningf(ctx, "No certificate templates enrolled for CA %s, skipping", ca.Name)
			removeCAChainCerts(rootFiles, intermediateFiles, symlinkFiles)
			continue
		}

		enrolledCAs = append(enrolledCAs, enrolledCA{
			Name:              ca.Name,
			Hostname:          ca.Hostname,
			IssuerFingerprint: ca.Chain.issuerFingerprint(),
			ChainFingerprints: append([]string(nil), ca.Chain.Fingerprints...),
			RootCerts:         rootFiles,
			IntermediateCerts: intermediateFiles,
			Symlinks:          symlinkFiles,
			Templates:         enrolledTemplates,
		})
	}

	if len(enrolledCAs) == 0 {
		return fmt.Errorf("could not enroll to any certificate authorities out of %d discovered", len(cas))
	}

	// Clean up certificates and symlinks from the previous state that are
	// no longer present in the newly discovered CAs/templates. This prevents
	// orphaned cert/key files and trust store symlinks from accumulating.
	if existingState != nil {
		cleanupOrphanedCerts(ctx, existingState, enrolledCAs)
	}

	// Rebuild the system trust store after BOTH installing new roots and
	// removing orphaned ones, so the consolidated bundle reflects additions
	// and removals in a single pass.
	if err := updateCATrustStore(); err != nil {
		log.Warningf(ctx, "Failed to update CA trust store: %v", err)
	}

	// Save state
	log.Debugf(ctx, "Saving enrollment state for %s with %d enrolled CAs", objectName, len(enrolledCAs))
	state := &enrollmentState{
		ObjectName: objectName,
		Identity:   machineIdentity,
		Domain:     normalizeDomainIdentity(m.domain),
		CAs:        enrolledCAs,
	}
	if err := saveState(m.stateDir, state); err != nil {
		return fmt.Errorf("failed to save enrollment state: %w", err)
	}

	caNames := make([]string, 0, len(enrolledCAs))
	for _, ca := range enrolledCAs {
		caNames = append(caNames, ca.Name)
	}
	log.Infof(ctx, "Enrolled to certificate authorities: %s", strings.Join(caNames, ", "))

	return nil
}

// unenroll removes all certificate enrollments and cleans up state.
func (m *Manager) unenroll(ctx context.Context, objectName string) error {
	state, err := loadState(m.stateDir, objectName)
	if err != nil {
		log.Warningf(ctx, "Failed to load enrollment state: %v", err)
	}

	if state != nil {
		log.Debugf(ctx, "Unenrolling %d certificate authorities", len(state.CAs))
		for _, ca := range state.CAs {
			log.Debugf(ctx, "Removing certificates for CA %s (%d templates)", ca.Name, len(ca.Templates))
			for _, tmpl := range ca.Templates {
				log.Debugf(ctx, "Removing certificate files for template %s", tmpl.Nickname)
				os.Remove(tmpl.CertFile)
				os.Remove(tmpl.KeyFile)
			}

			removeCAChainCerts(ca.RootCerts, ca.IntermediateCerts, ca.Symlinks)
		}

		// Update trust store after removing certs
		if err := updateCATrustStore(); err != nil {
			log.Warningf(ctx, "Failed to update CA trust store: %v", err)
		}
	}

	// Clean up legacy Samba cache if present
	sambaDir := filepath.Join(m.stateDir, "samba")
	if _, err := os.Stat(sambaDir); err == nil {
		log.Debugf(ctx, "Removing legacy Samba cache directory: %s", sambaDir)
		os.RemoveAll(sambaDir)
	}

	// Remove state file
	if err := removeState(m.stateDir, objectName); err != nil {
		log.Warningf(ctx, "Failed to remove enrollment state file: %v", err)
	}

	log.Info(ctx, "Certificate unenrollment completed")
	return nil
}

// cleanupOrphanedCerts removes certificates, keys, and trust store symlinks
// that exist in the old state but are not present in the new set of enrolled
// CAs. This prevents orphaned files from accumulating when CAs or templates
// are removed from AD.
func cleanupOrphanedCerts(ctx context.Context, oldState *enrollmentState, newCAs []enrolledCA) {
	// Build a set of all cert/key/symlink paths in the new state
	newPaths := make(map[string]bool)
	for _, ca := range newCAs {
		for _, cert := range ca.RootCerts {
			newPaths[cert] = true
		}
		for _, cert := range ca.IntermediateCerts {
			newPaths[cert] = true
		}
		for _, link := range ca.Symlinks {
			newPaths[link] = true
		}
		for _, tmpl := range ca.Templates {
			newPaths[tmpl.KeyFile] = true
			newPaths[tmpl.CertFile] = true
		}
	}

	// Remove any old paths not in the new set, logging both successes and
	// failures so a stuck orphan is visible in the daemon logs.
	var removed int
	remove := func(path, kind string) {
		if path == "" || newPaths[path] {
			return
		}
		if err := os.Remove(path); err != nil {
			if !os.IsNotExist(err) {
				log.Warningf(ctx, "Failed to remove orphaned %s %s: %v", kind, path, err)
			}
			return
		}
		log.Debugf(ctx, "Removed orphaned %s: %s", kind, path)
		removed++
	}
	for _, ca := range oldState.CAs {
		for _, link := range ca.Symlinks {
			remove(link, "trust store symlink")
		}
		for _, cert := range ca.RootCerts {
			remove(cert, "CA certificate")
		}
		for _, cert := range ca.IntermediateCerts {
			remove(cert, "intermediate CA certificate")
		}
		for _, tmpl := range ca.Templates {
			remove(tmpl.CertFile, "certificate")
			remove(tmpl.KeyFile, "private key")
		}
	}

	if removed > 0 {
		log.Debugf(ctx, "Cleaned up %d orphaned trust store entries", removed)
	}
}

func existingEnrollment(state *enrollmentState, caName, template string) (enrolledCA, enrolledTemplate, bool) {
	if state == nil {
		return enrolledCA{}, enrolledTemplate{}, false
	}
	for _, ca := range state.CAs {
		if !strings.EqualFold(ca.Name, caName) {
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

func validateStoredEnrollment(previousCA enrolledCA, tmpl enrolledTemplate, state *enrollmentState, currentCA certAuthority, identity, domain string, now time.Time) (enrolledTemplate, error) {
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
	currentIssuerFingerprint := currentCA.Chain.issuerFingerprint()
	if previousCA.IssuerFingerprint != "" && !strings.EqualFold(previousCA.IssuerFingerprint, currentIssuerFingerprint) {
		return enrolledTemplate{}, fmt.Errorf("state issuing CA fingerprint %s does not match discovered CA %s", previousCA.IssuerFingerprint, currentIssuerFingerprint)
	}
	if len(previousCA.ChainFingerprints) > 0 && !slices.EqualFunc(previousCA.ChainFingerprints, currentCA.Chain.Fingerprints, strings.EqualFold) {
		return enrolledTemplate{}, fmt.Errorf("state CA chain fingerprints do not match the discovered chain")
	}

	certPEM, err := os.ReadFile(tmpl.CertFile)
	if err != nil {
		return enrolledTemplate{}, fmt.Errorf("reading existing certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(tmpl.KeyFile)
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

// certNeedsRenewal reports whether the certificate at certFile should be
// re-enrolled rather than reused: it returns true if the file is missing,
// unreadable, unparseable, or within certRenewalWindow of (or past) its
// expiry. Because adsys does not register issued certificates with certmonger,
// this expiry-driven re-enrollment on each policy refresh is what keeps
// machine certificates current.
func certNeedsRenewal(ctx context.Context, certFile string) bool {
	cert := parseCertFile(certFile)
	if cert == nil {
		log.Warningf(ctx, "Could not load existing certificate %s, re-enrolling", certFile)
		return true
	}
	if time.Now().Add(certRenewalWindow).After(cert.NotAfter) {
		log.Infof(ctx, "Certificate %s expires at %s (within renewal window), re-enrolling", certFile, cert.NotAfter)
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

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
			// the DC's StartTLS certificate is trusted via the Kerberos bind
			// until then (see verifyPeerCertificate).
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
//  1. Discovers CAs and templates from LDAP
//  2. Installs root CA certificates to the system trust store
//  3. Requests certificates directly from AD CS for each template
//  4. Saves enrollment state
func (m *Manager) enroll(ctx context.Context, objectName string) error {
	server := dcHostnameFromDomain(m.domain)
	log.Debugf(ctx, "Discovering CAs from LDAP server: %s", server)

	cas, err := discoverCAsAndTemplates(m.ldapConnect, server)
	if err != nil {
		return fmt.Errorf("failed to discover CAs: %w", err)
	}

	if len(cas) == 0 {
		log.Info(ctx, "No certificate authorities found in AD, skipping enrollment")
		return nil
	}

	log.Debugf(ctx, "Discovered %d certificate authorities from LDAP", len(cas))

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

	conn, err := m.ldapConnect(server)
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP for template attrs: %w", err)
	}
	defer conn.Close()

	configDN, err := fetchConfigDN(conn)
	if err != nil {
		return fmt.Errorf("failed to fetch config DN: %w", err)
	}

	var enrolledCAs []enrolledCA
	for _, ca := range cas {
		log.Debugf(ctx, "Processing CA: %s (%s) with %d templates", ca.Name, ca.Hostname, len(ca.Templates))

		// Install root CA certificate. If this fails (e.g. the CA cert is
		// malformed, expired, or unverifiable) skip the CA entirely, since
		// certificates issued by it would not validate without its root in
		// the trust store.
		certFiles, symlinkFiles, err := installRootCACerts(ca, trustDir, m.globalTrustDir)
		if err != nil {
			log.Warningf(ctx, "Skipping CA %s: could not install its root certificate: %v", ca.Name, err)
			// Preserve previously-enrolled state for this CA so a transient
			// failure doesn't orphan still-valid certificates; otherwise drop
			// any partial files this attempt may have created.
			if prev, ok := existingCA(existingState, ca.Name); ok {
				enrolledCAs = append(enrolledCAs, prev)
			} else {
				removeRootCACerts(certFiles, symlinkFiles)
			}
			continue
		}

		var enrolledTemplates []enrolledTemplate
		for _, tmplName := range ca.Templates {
			if tmpl, ok := existingTemplate(existingState, ca.Name, tmplName); ok && filesExist(tmpl.KeyFile, tmpl.CertFile) && !certNeedsRenewal(ctx, tmpl.CertFile) {
				log.Debugf(ctx, "Template %s for CA %s already enrolled and current, reusing existing cert files", tmplName, ca.Name)
				enrolledTemplates = append(enrolledTemplates, tmpl)
				continue
			}

			attrs, err := fetchTemplateAttrs(conn, configDN, tmplName)
			if err != nil {
				log.Warningf(ctx, "Failed to fetch attrs for template %s: %v", tmplName, err)
				attrs = templateAttrs{Name: tmplName, MinKeySize: 2048}
			}
			log.Debugf(ctx, "Template %s requires minimum key size: %d bits", attrs.Name, attrs.MinKeySize)

			// CA and template names come from LDAP and are used to build on-disk
			// paths, so sanitize them to avoid unexpected or traversing filenames.
			nickname := sanitizeName(fmt.Sprintf("%s.%s", ca.Name, tmplName))
			keyFile := filepath.Join(privateDir, nickname+".key")
			certFile := filepath.Join(trustDir, nickname+".crt")

			if err := EnrollCertificate(ctx, m.submitCSR, EnrollmentRequest{
				Server:     ca.Hostname,
				CAName:     ca.Name,
				Template:   attrs.Name,
				CommonName: certificateCommonName(objectName, m.domain),
				KeyFile:    keyFile,
				CertFile:   certFile,
				KeySize:    attrs.MinKeySize,
			}); err != nil {
				log.Warningf(ctx, "Failed to request certificate for template %s: %v", tmplName, err)
				// If a previously-issued certificate is still on disk and not
				// yet expired, keep using it rather than dropping it: dropping
				// would let cleanupOrphanedCerts delete still-valid key material
				// just because a renewal attempt failed transiently.
				if tmpl, ok := existingTemplate(existingState, ca.Name, tmplName); ok && filesExist(tmpl.KeyFile) && certUsable(tmpl.CertFile) {
					log.Infof(ctx, "Retaining still-valid certificate for template %s after failed renewal", tmplName)
					enrolledTemplates = append(enrolledTemplates, tmpl)
				}
				continue
			}

			log.Debugf(ctx, "Successfully enrolled certificate for template %s from CA %s", attrs.Name, ca.Name)
			enrolledTemplates = append(enrolledTemplates, enrolledTemplate{
				Nickname: nickname,
				Template: attrs.Name,
				KeyFile:  keyFile,
				CertFile: certFile,
			})
		}

		if len(enrolledTemplates) == 0 {
			log.Warningf(ctx, "No certificate templates enrolled for CA %s, skipping", ca.Name)
			removeRootCACerts(certFiles, symlinkFiles)
			continue
		}

		enrolledCAs = append(enrolledCAs, enrolledCA{
			Name:      ca.Name,
			Hostname:  ca.Hostname,
			RootCerts: certFiles,
			Symlinks:  symlinkFiles,
			Templates: enrolledTemplates,
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
		Domain:     m.domain,
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

			removeRootCACerts(ca.RootCerts, ca.Symlinks)
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
		for _, tmpl := range ca.Templates {
			remove(tmpl.CertFile, "certificate")
			remove(tmpl.KeyFile, "private key")
		}
	}

	if removed > 0 {
		log.Debugf(ctx, "Cleaned up %d orphaned trust store entries", removed)
	}
}

func existingTemplate(state *enrollmentState, caName, template string) (enrolledTemplate, bool) {
	if state == nil {
		return enrolledTemplate{}, false
	}
	for _, ca := range state.CAs {
		if ca.Name != caName {
			continue
		}
		for _, enrolled := range ca.Templates {
			if enrolled.Template == template {
				return enrolled, true
			}
		}
	}
	return enrolledTemplate{}, false
}

// existingCA returns the previously-enrolled state for the named CA, if any.
func existingCA(state *enrollmentState, caName string) (enrolledCA, bool) {
	if state == nil {
		return enrolledCA{}, false
	}
	for _, ca := range state.CAs {
		if ca.Name == caName {
			return ca, true
		}
	}
	return enrolledCA{}, false
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

// certUsable reports whether the certificate at certFile is present, parseable
// and not yet expired. Unlike certNeedsRenewal it ignores the renewal window,
// so a still-valid (if soon-to-expire) certificate is considered usable.
func certUsable(certFile string) bool {
	cert := parseCertFile(certFile)
	return cert != nil && time.Now().Before(cert.NotAfter)
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

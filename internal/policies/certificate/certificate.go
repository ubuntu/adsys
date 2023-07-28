// Package certificate provides a manager that handles certificate
// autoenrollment.
//
// This manager only applies to computer objects.
//
// Provided that the AD backend is online and AD CS is set up, the manager will
// parse the relevant GPOs and delegate to an external Python script that will
// request Samba to enroll or un-enroll the machine for certificates.
//
// No action is taken if the certificate GPO is disabled, not configured, or
// absent.
// If the enroll flag is not set, the machine will be un-enrolled,
// namely the certificates will be removed and monitoring will stop.
// If any errors occur during the enrollment process, the manager will log them
// prior to failing.
package certificate

import (
	"bytes"
	"context"
	_ "embed" // embed cert enroll python script
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ubuntu/adsys/internal/consts"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/smbsafe"
	"github.com/ubuntu/decorate"
	"golang.org/x/exp/slices"
)

// Manager prevents running multiple Python scripts in parallel while parsing
// the policy in ApplyPolicy.
type Manager struct {
	domain          string
	sambaCacheDir   string
	krb5CacheDir    string
	vendorPythonDir string
	certEnrollCmd   []string

	mu sync.Mutex // Prevents multiple instances of the certificate manager from running in parallel
}

// gpoEntry is a single GPO registry entry to be serialised to JSON in a format
// Samba expects.
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

	// See [MS-CAESO] 4.4.5.1.
	enrollFlag   int = 0x1
	disabledFlag int = 0x8000
)

// CertEnrollCode is the embedded Python script which requests
// Samba to autoenroll for certificates using the given GPOs.
//
//go:embed cert-autoenroll
var CertEnrollCode string

type options struct {
	stateDir          string
	runDir            string
	shareDir          string
	certAutoenrollCmd []string
}

// Option reprents an optional function to change the certificate manager.
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

// WithCertAutoenrollCmd overrides the default certificate autoenroll command.
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
		certAutoenrollCmd: []string{"python3", "-c", CertEnrollCode},
	}
	// applied options
	for _, o := range opts {
		o(&args)
	}

	return &Manager{
		domain:          domain,
		sambaCacheDir:   filepath.Join(args.stateDir, "samba"),
		krb5CacheDir:    filepath.Join(args.runDir, "krb5cc"),
		vendorPythonDir: filepath.Join(args.shareDir, "python"),
		certEnrollCmd:   args.certAutoenrollCmd,
	}
}

// ApplyPolicy runs the certificate autoenrollment script to enroll or un-enroll the machine.
func (m *Manager) ApplyPolicy(ctx context.Context, objectName string, isComputer, isOnline bool, entries []entry.Entry) (err error) {
	defer decorate.OnError(&err, i18n.G("can't apply certificate policy"))

	m.mu.Lock()
	defer m.mu.Unlock()

	idx := slices.IndexFunc(entries, func(e entry.Entry) bool { return e.Key == "autoenroll" })
	if idx == -1 {
		log.Debug(ctx, "Certificate autoenrollment is not configured")
		return nil
	}

	if !isComputer {
		log.Debug(ctx, "Certificate policy is only supported for computers, skipping...")
		return nil
	}

	if !isOnline {
		log.Info(ctx, i18n.G("AD backend is offline, skipping certificate policy"))
		return nil
	}

	log.Debug(ctx, "ApplyPolicy certificate policy")

	entry := entries[idx]
	value, err := strconv.Atoi(entry.Value)
	if err != nil {
		return fmt.Errorf(i18n.G("failed to parse certificate policy entry value: %w"), err)
	}

	if value&disabledFlag == disabledFlag {
		log.Debug(ctx, "Certificate policy is disabled, skipping...")
		return nil
	}

	var polSrvRegistryEntries []gpoEntry
	for _, entry := range entries {
		// We already handled the autoenroll entry
		if entry.Key == "autoenroll" {
			continue
		}

		// Samba expects the key parts to be joined by backslashes
		keyparts := strings.Split(entry.Key, "/")
		keyname := strings.Join(keyparts[:len(keyparts)-1], `\`)
		valuename := keyparts[len(keyparts)-1]
		polSrvRegistryEntries = append(polSrvRegistryEntries, gpoEntry{keyname, valuename, gpoData(entry.Value, valuename), gpoType(valuename)})

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
		return fmt.Errorf(i18n.G("failed to marshal policy server registry entries: %v"), err)
	}

	if err := m.runScript(ctx, action, objectName,
		"--policy_servers_json", string(jsonGPOData),
		"--samba_cache_dir", m.sambaCacheDir,
	); err != nil {
		return err
	}

	return nil
}

// runScript runs the certificate autoenrollment script with the given arguments.
func (m *Manager) runScript(ctx context.Context, action, objectName string, extraArgs ...string) error {
	scriptArgs := []string{action, objectName, m.domain}
	scriptArgs = append(scriptArgs, extraArgs...)
	cmdArgs := append(m.certEnrollCmd, scriptArgs...)
	cmdCtx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	log.Debugf(ctx, "Running cert autoenroll script with arguments: %q", strings.Join(scriptArgs, " "))
	// #nosec G204 - cmdArgs is under our control (python embedded script or mock for tests)
	cmd := exec.CommandContext(cmdCtx, cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("KRB5CCNAME=%s", filepath.Join(m.krb5CacheDir, objectName)),
		fmt.Sprintf("PYTHONPATH=%s", m.vendorPythonDir),
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	smbsafe.WaitExec()
	defer smbsafe.DoneExec()

	if err := cmd.Run(); err != nil {
		return fmt.Errorf(i18n.G("failed to run certificate autoenrollment script (exited with %d): %v\n%s"), cmd.ProcessState.ExitCode(), err, stderr.String())
	}
	log.Infof(ctx, i18n.G("Certificate autoenrollment script ran successfully\n%s"), stdout.String())
	return nil
}

// gpoData returns the data for a GPO entry.
func gpoData(data, value string) any {
	if slices.Contains(integerGPOValues, value) {
		intData, _ := strconv.Atoi(data)
		return intData
	}

	return data
}

// gpoType returns the type for a GPO entry.
func gpoType(value string) int {
	if slices.Contains(integerGPOValues, value) {
		return gpoTypeInteger
	}

	return gpoTypeString
}

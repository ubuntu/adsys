package certificate

import (
	"bytes"
	"context"
	_ "embed" // embed cert enroll python script
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ubuntu/adsys/internal/consts"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/smbsafe"
	"github.com/ubuntu/decorate"
)

// Manager prevents running multiple gdm update process in parallel while parsing policy in ApplyPolicy.
type Manager struct {
	domain         string
	krb5CacheDir   string
	stateDir       string
	sysvolCacheDir string
	certEnrollCmd  []string

	mu sync.Mutex // Prevents multiple instances of the certificate manager from running in parallel
}

// CertEnrollCode is the embedded Python script which requests
// Samba to autoenroll for certificates using the given GPOs.
//
//go:embed cert-autoenroll
var CertEnrollCode string

type options struct {
	runDir        string
	stateDir      string
	cacheDir      string
	certEnrollCmd []string
}
type Option func(*options)

// WithRunDir overrides the default run directory.
func WithRunDir(p string) func(*options) {
	return func(a *options) {
		a.runDir = p
	}
}

// WithStateDir overrides the default state directory.
func WithStateDir(p string) func(*options) {
	return func(a *options) {
		a.stateDir = p
	}
}

// WithCacheDir overrides the default cache directory.
func WithCacheDir(p string) func(*options) {
	return func(a *options) {
		a.cacheDir = p
	}
}

// New returns a new manager for gdm policy handlers.
func New(domain string, opts ...Option) *Manager {
	// defaults
	args := options{
		runDir:        consts.DefaultRunDir,
		stateDir:      consts.DefaultStateDir,
		cacheDir:      consts.DefaultCacheDir,
		certEnrollCmd: []string{"python3", "-c", CertEnrollCode},
	}
	// applied options
	for _, o := range opts {
		o(&args)
	}

	return &Manager{
		domain:         domain,
		krb5CacheDir:   filepath.Join(args.runDir, "krb5cc"),
		stateDir:       args.stateDir,
		sysvolCacheDir: filepath.Join(args.cacheDir, "sysvol"),
		certEnrollCmd:  args.certEnrollCmd,
	}
}

// ApplyPolicy generates a dconf computer or user policy based on a list of entries.
func (m *Manager) ApplyPolicy(ctx context.Context, objectName string, isComputer, isOnline bool, gpoPaths []string) (err error) {
	defer decorate.OnError(&err, i18n.G("can't apply certificate policy"))

	log.Debug(ctx, "ApplyPolicy certificate policy")

	m.mu.Lock()
	defer m.mu.Unlock()

	if !isComputer {
		log.Debug(ctx, "Certificate policy is only supported for computers, skipping...")
		return nil
	}

	if !isOnline {
		log.Info(ctx, i18n.G("AD backend is offline, skipping certificate policy"))
		return nil
	}

	args := append([]string{}, m.certEnrollCmd...)
	scriptArgs := []string{m.domain, strings.Join(gpoPaths, ","), "--state-dir", m.stateDir}
	cmdArgs := append(args, scriptArgs...)
	cmdCtx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	log.Debugf(ctx, "Running cert autoenroll script with arguments: %q", strings.Join(scriptArgs, " "))
	// #nosec G204 - cmdArgs is under our control (python embedded script or mock for tests)
	cmd := exec.CommandContext(cmdCtx, cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("KRB5CCNAME=%s", filepath.Join(m.krb5CacheDir, objectName)),
		fmt.Sprintf("PYTHONPATH=%s", "/usr/share/adsys/python"), // TODO: use overridable consts
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	smbsafe.WaitExec()
	err = cmd.Run()
	smbsafe.DoneExec()
	if err != nil {
		return fmt.Errorf(i18n.G("failed to run certificate autoenrollment script (exited with %d): %v\n%s"), cmd.ProcessState.ExitCode(), err, stderr.String())
	}
	log.Infof(ctx, i18n.G("Certificate autoenrollment script ran successfully (exited with %d)\n%s"), cmd.ProcessState.ExitCode(), stdout.String())

	return nil
}

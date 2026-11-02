// Package policies - Policy manager guidelines
//
// ADSys is expected to apply configuration policies, not enforce them. We are responsible for
// properly configuring those policies and set up the machine to apply them, but we can not ensure that
// they will be executed as this relies on lots of variables and system functionalities.
// As such, policy managers are expected to only prevent authentication when something goes wrong
// during the configuration of the policies, whilst ensuring that the user will be warned should a
// configuration fail to execute.
//
// We should prevent authentication on errors such as:
//   - failed to copy the policy requested assets to the machine;
//   - failed to parse policy configuration values;
//   - failed to write the requested files on disk;
//   - missing required auxiliar binary to set up the policy (e.g. apparmor_parser, dconf);
//
// We should only warn the user on errors such as:
//   - systemd unit failed to start due to some system error;
//   - copied asset failed to be executed due to own misconfiguration;
//   - script failed during execution;
//   - requested shared folder does not exist and, as such, can not be mounted;
//
// This is supposed to be a guideline, rather than a rule. Therefore, some of these errors can be
// interchangeable depending on which policy is being applied.
package policies

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/leonelquinteros/gotext"
	"github.com/ubuntu/adsys/internal/ad/backends"
	"github.com/ubuntu/adsys/internal/consts"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/policies/apparmor"
	"github.com/ubuntu/adsys/internal/policies/certificate"
	"github.com/ubuntu/adsys/internal/policies/dconf"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/policies/gdm"
	"github.com/ubuntu/adsys/internal/policies/mount"
	"github.com/ubuntu/adsys/internal/policies/privilege"
	"github.com/ubuntu/adsys/internal/policies/proxy"
	"github.com/ubuntu/adsys/internal/policies/scripts"
	"github.com/ubuntu/adsys/internal/systemd"
	"github.com/ubuntu/decorate"
	"golang.org/x/sync/errgroup"
)

// ProOnlyRules are the rules that are only available for Pro subscribers. They
// will be filtered otherwise.
var ProOnlyRules = []string{"privilege", "scripts", "mount", "apparmor", "proxy", "certificate"}

// Manager handles all managers for various policy handlers.
type Manager struct {
	policiesCacheDir string
	hostname         string

	backend backends.Backend

	dconf       *dconf.Manager
	privilege   *privilege.Manager
	scripts     *scripts.Manager
	mount       *mount.Manager
	gdm         *gdm.Manager
	apparmor    *apparmor.Manager
	proxy       *proxy.Manager
	certificate *certificate.Manager

	subscriptionDbus dbus.BusObject

	// muMu protects the objectMu mutex.
	muMu *sync.Mutex
	// objectMu prevents applying multiple policies concurrently for the same object.
	objectMu map[string]*sync.Mutex
}

// systemdCaller is the interface to interact with systemd.
type systemdCaller interface {
	StartUnit(context.Context, string) error
	StopUnit(context.Context, string) error

	EnableUnit(context.Context, string) error
	DisableUnit(context.Context, string) error

	DaemonReload(context.Context) error
}

type options struct {
	cacheDir           string
	stateDir           string
	dconfDir           string
	sudoersDir         string
	policyKitDir       string
	policyKitSystemDir string
	runDir             string
	shareDir           string
	apparmorDir        string
	apparmorFsDir      string
	systemUnitDir      string
	globalTrustDir     string
	proxyApplier       proxy.Caller
	systemdCaller      systemdCaller
	gdm                *gdm.Manager

	apparmorParserCmd []string
	certAutoenrollCmd []string
}

// Option reprents an optional function to change Policies behavior.
type Option func(*options) error

// WithCacheDir specifies a personalized daemon cache directory.
func WithCacheDir(p string) Option {
	return func(o *options) error {
		o.cacheDir = p
		return nil
	}
}

// WithStateDir specifies a personalized state directory.
func WithStateDir(p string) Option {
	return func(o *options) error {
		o.stateDir = p
		return nil
	}
}

// WithDconfDir specifies a personalized dconf directory.
func WithDconfDir(p string) Option {
	return func(o *options) error {
		o.dconfDir = p
		return nil
	}
}

// WithSudoersDir specifies a personalized sudoers directory.
func WithSudoersDir(p string) Option {
	return func(o *options) error {
		o.sudoersDir = p
		return nil
	}
}

// WithPolicyKitDir specifies a personalized policykit directory.
func WithPolicyKitDir(p string) Option {
	return func(o *options) error {
		o.policyKitDir = p
		return nil
	}
}

// WithPolicyKitSystemDir specifies a personalized policykit system reserved directory.
func WithPolicyKitSystemDir(p string) Option {
	return func(o *options) error {
		o.policyKitSystemDir = p
		return nil
	}
}

// WithRunDir specifies a personalized run directory.
func WithRunDir(p string) Option {
	return func(o *options) error {
		o.runDir = p
		return nil
	}
}

// WithShareDir specifies a personalized share directory.
func WithShareDir(p string) Option {
	return func(o *options) error {
		o.shareDir = p
		return nil
	}
}

// WithApparmorDir specifies a personalized apparmor directory.
func WithApparmorDir(p string) Option {
	return func(o *options) error {
		o.apparmorDir = p
		return nil
	}
}

// WithApparmorParserCmd overrides the default apparmor_parser command.
func WithApparmorParserCmd(p []string) Option {
	return func(o *options) error {
		o.apparmorParserCmd = p
		return nil
	}
}

// WithApparmorFsDir specifies a personalized directory for the apparmor
// security filesystem.
func WithApparmorFsDir(p string) Option {
	return func(o *options) error {
		o.apparmorFsDir = p
		return nil
	}
}

// WithSystemUnitDir specifies a personalized unit directory for adsys mount units.
func WithSystemUnitDir(p string) Option {
	return func(o *options) error {
		o.systemUnitDir = p
		return nil
	}
}

// WithGlobalTrustDir specifies a personalized global trust directory for use
// with the certificate manager.
func WithGlobalTrustDir(p string) Option {
	return func(o *options) error {
		o.globalTrustDir = p
		return nil
	}
}

// WithProxyApplier specifies a personalized proxy applier for the proxy policy manager.
func WithProxyApplier(p proxy.Caller) Option {
	return func(o *options) error {
		o.proxyApplier = p
		return nil
	}
}

// WithSystemdCaller specifies a personalized systemd caller for the policy managers.
func WithSystemdCaller(p systemdCaller) Option {
	return func(o *options) error {
		o.systemdCaller = p
		return nil
	}
}

// WithCertAutoenrollCmd specifies a personalized certificate autoenroll command.
func WithCertAutoenrollCmd(cmd []string) Option {
	return func(o *options) error {
		o.certAutoenrollCmd = cmd
		return nil
	}
}

// NewManager returns a new manager with all default policy handlers.
func NewManager(bus *dbus.Conn, hostname string, backend backends.Backend, opts ...Option) (m *Manager, err error) {
	defer decorate.OnError(&err, gotext.Get("can't create a new policy handlers manager"))

	defaultSystemdCaller, err := systemd.New(bus)
	if err != nil {
		return nil, err
	}

	// defaults
	args := options{
		cacheDir:           consts.DefaultCacheDir,
		stateDir:           consts.DefaultStateDir,
		runDir:             consts.DefaultRunDir,
		shareDir:           consts.DefaultShareDir,
		apparmorDir:        consts.DefaultApparmorDir,
		systemUnitDir:      consts.DefaultSystemUnitDir,
		globalTrustDir:     consts.DefaultGlobalTrustDir,
		policyKitSystemDir: consts.DefaultPolicyKitSystemDir,
		systemdCaller:      defaultSystemdCaller,
		gdm:                nil,
	}
	// applied options (including dconf manager used by gdm)
	for _, o := range opts {
		if err := o(&args); err != nil {
			return nil, err
		}
	}
	// dconf manager
	dconfManager := &dconf.Manager{}
	if args.dconfDir != "" {
		dconfManager = dconf.NewWithDconfDir(args.dconfDir)
	}

	// privilege manager
	privilegeManager := privilege.NewWithDirs(args.sudoersDir, args.policyKitDir, args.policyKitSystemDir)

	// scripts manager
	scriptsManager, err := scripts.New(args.runDir, args.systemdCaller)
	if err != nil {
		return nil, err
	}

	// mount manager
	mountManager, err := mount.New(args.runDir, args.systemUnitDir, args.systemdCaller)
	if err != nil {
		return nil, err
	}

	// apparmor manager
	var apparmorOptions []apparmor.Option
	if args.apparmorParserCmd != nil {
		apparmorOptions = append(apparmorOptions, apparmor.WithApparmorParserCmd(args.apparmorParserCmd))
	}
	if args.apparmorFsDir != "" {
		apparmorOptions = append(apparmorOptions, apparmor.WithApparmorFsDir(args.apparmorFsDir))
	}
	apparmorManager := apparmor.New(args.apparmorDir, apparmorOptions...)

	// proxy manager
	var proxyOptions []proxy.Option
	if args.proxyApplier != nil {
		proxyOptions = append(proxyOptions, proxy.WithProxyApplier(args.proxyApplier))
	}
	proxyManager := proxy.New(bus, proxyOptions...)

	// certificate manager
	certificateOpts := []certificate.Option{
		certificate.WithStateDir(args.stateDir),
		certificate.WithRunDir(args.runDir),
		certificate.WithShareDir(args.shareDir),
		certificate.WithGlobalTrustDir(args.globalTrustDir),
	}
	if args.certAutoenrollCmd != nil {
		certificateOpts = append(certificateOpts, certificate.WithCertAutoenrollCmd(args.certAutoenrollCmd))
	}
	certificateManager := certificate.New(backend.Domain(), certificateOpts...)

	// inject applied dconf mangager if we need to build a gdm manager
	if args.gdm == nil {
		if args.gdm, err = gdm.New(gdm.WithDconf(dconfManager)); err != nil {
			return nil, err
		}
	}

	policiesCacheDir := filepath.Join(args.cacheDir, PoliciesCacheBaseName)
	if err := os.MkdirAll(policiesCacheDir, 0700); err != nil {
		return nil, err
	}

	subscriptionDbus := bus.Object(consts.SubscriptionDbusRegisteredName,
		dbus.ObjectPath(consts.SubscriptionDbusObjectPath))

	return &Manager{
		backend:          backend,
		policiesCacheDir: policiesCacheDir,
		hostname:         hostname,
		dconf:            dconfManager,
		privilege:        privilegeManager,
		scripts:          scriptsManager,
		mount:            mountManager,
		apparmor:         apparmorManager,
		proxy:            proxyManager,
		certificate:      certificateManager,
		gdm:              args.gdm,

		subscriptionDbus: subscriptionDbus,

		muMu:     &sync.Mutex{},
		objectMu: make(map[string]*sync.Mutex),
	}, nil
}

// ApplyPolicies generates a computer or user policy based on a list of entries
// retrieved from a directory service.
func (m *Manager) ApplyPolicies(ctx context.Context, objectName string, isComputer bool, pols *Policies) (err error) {
	defer decorate.OnError(&err, gotext.Get("failed to apply policy to %q", objectName))

	// We have a lock per objectName to prevent multiple instances of ApplyPolicies for the same object.
	m.muMu.Lock()
	if _, ok := m.objectMu[objectName]; !ok {
		m.objectMu[objectName] = &sync.Mutex{}
	}
	m.objectMu[objectName].Lock()
	defer m.objectMu[objectName].Unlock()
	m.muMu.Unlock()

	rules := pols.GetUniqueRules()
	action := gotext.Get("Applying")
	if len(rules) == 0 {
		action = gotext.Get("Unloading")
	}
	log.Info(ctx, gotext.Get("%s policies for %s (machine: %v)", action, objectName, isComputer))

	var g errgroup.Group
	// Applying dconf policies take a while to complete, so it's better to start applying them before
	// querying dbus for the Pro subscription state, as it does not rely on that.
	g.Go(func() error {
		return m.dconf.ApplyPolicy(ctx, objectName, isComputer, rules["dconf"])
	})
	if !m.GetSubscriptionState(ctx) {
		if filteredRules := filterRules(ctx, rules); len(filteredRules) > 0 {
			log.Warning(ctx, gotext.Get("Rules from the following policy types will be filtered out as the machine is not enrolled to Ubuntu Pro: %s", strings.Join(filteredRules, ", ")))
		}
	}

	g.Go(func() error {
		return m.privilege.ApplyPolicy(ctx, objectName, isComputer, rules["privilege"])
	})
	g.Go(func() error {
		return m.scripts.ApplyPolicy(ctx, objectName, isComputer, rules["scripts"], pols.SaveAssetsTo)
	})
	g.Go(func() error {
		return m.mount.ApplyPolicy(ctx, objectName, isComputer, rules["mount"])
	})
	g.Go(func() error {
		return m.apparmor.ApplyPolicy(ctx, objectName, isComputer, rules["apparmor"], pols.SaveAssetsTo)
	})
	g.Go(func() error {
		return m.proxy.ApplyPolicy(ctx, objectName, isComputer, rules["proxy"])
	})
	g.Go(func() error {
		// Ignore error as we don't want to fail because of online status this late in the process
		isOnline, _ := m.backend.IsOnline()
		return m.certificate.ApplyPolicy(ctx, objectName, isComputer, isOnline, rules["certificate"])
	})
	if err := g.Wait(); err != nil {
		return err
	}

	if isComputer {
		// Apply GDM policy only now as we need dconf machine database to be ready first
		if err := m.gdm.ApplyPolicy(ctx, rules["gdm"]); err != nil {
			return err
		}
	}

	// Write cache Policies
	return pols.Save(filepath.Join(m.policiesCacheDir, objectName))
}

// DumpPolicies displays the currently applied policies and rules (since last update) for objectName.
// It can in addition show the rules and overridden content.
func (m *Manager) DumpPolicies(ctx context.Context, objectName string, computerOnly, withRules, withOverridden bool) (msg string, err error) {
	defer decorate.OnError(&err, gotext.Get("failed to dump policies for %q", objectName))

	log.Infof(ctx, "Dumping policies for %s", objectName)

	var out strings.Builder

	var alreadyProcessedRules map[string]struct{}
	if !computerOnly {
		fmt.Fprintln(&out, gotext.Get("Policies from machine configuration:"))
		policiesHost, err := NewFromCache(ctx, filepath.Join(m.policiesCacheDir, m.hostname))
		if err != nil {
			return "", errors.New(gotext.Get("no policy applied for %q: %v", m.hostname, err))
		}
		for _, g := range policiesHost.GPOs {
			alreadyProcessedRules = g.Format(&out, withRules, withOverridden, alreadyProcessedRules)
		}
		fmt.Fprintln(&out, gotext.Get("Policies from user configuration:"))
	}

	// Load target policies
	policiesTarget, err := NewFromCache(ctx, filepath.Join(m.policiesCacheDir, objectName))
	if err != nil {
		log.Info(ctx, gotext.Get("User %q not found on cache.", objectName))
		return "", errors.New(gotext.Get("no policy applied for %q: %v", objectName, err))
	}
	for _, g := range policiesTarget.GPOs {
		alreadyProcessedRules = g.Format(&out, withRules, withOverridden, alreadyProcessedRules)
	}

	return out.String(), nil
}

// LastUpdateFor returns the last update time for object or current machine.
func (m *Manager) LastUpdateFor(ctx context.Context, objectName string, isMachine bool) (t time.Time, err error) {
	defer decorate.OnError(&err, gotext.Get("failed to get policy last update time %q (machine: %v)", objectName, isMachine))

	log.Infof(ctx, "Get policies last update time %q (machine: %t)", objectName, isMachine)

	if isMachine {
		objectName = m.hostname
	}

	info, err := os.Stat(filepath.Join(m.policiesCacheDir, objectName))
	if err != nil {
		return time.Time{}, errors.New(gotext.Get("policies were not applied for %q: %v", objectName, err))
	}
	return info.ModTime(), nil
}

// GetSubscriptionState returns the subscription status from Ubuntu Pro.
func (m *Manager) GetSubscriptionState(ctx context.Context) (subscriptionEnabled bool) {
	log.Debug(ctx, "Refresh subscription state")

	defer func() {
		if subscriptionEnabled {
			log.Debug(ctx, "Ubuntu Pro is enabled for GPO restrictions")
			return
		}

		log.Debug(ctx, "Ubuntu Pro is not enabled for GPO restrictions")
	}()

	// Check if the device is entitled to the Pro policy
	prop, err := m.subscriptionDbus.GetProperty(consts.SubscriptionDbusInterface + ".Attached")
	if err != nil {
		log.Warningf(ctx, "no dbus connection to Ubuntu Pro. Considering device as not enabled: %v", err)
		return false
	}
	enabled, ok := prop.Value().(bool)
	if !ok {
		log.Warningf(ctx, "dbus returned an improper value from Ubuntu Pro. Considering device as not enabled: %v", prop.Value())
		return false
	}

	if !enabled {
		return false
	}

	return true
}

// filterRules allows to filter any rules that are not eligible for the current device,
// and returns the sorted list of filtered rules.
func filterRules(ctx context.Context, rules map[string][]entry.Entry) []string {
	log.Debug(ctx, "Filtering Rules")

	var filteredRules []string
	for rule := range rules {
		if !slices.Contains(ProOnlyRules, rule) {
			continue
		}
		filteredRules = append(filteredRules, rule)
		rules[rule] = nil
	}

	// Return the filtered rules in the same order as ProOnlyRules, which is the
	// order of the rules to apply
	slices.SortFunc(filteredRules, func(a, b string) int {
		return slices.Index(ProOnlyRules, a) - slices.Index(ProOnlyRules, b)
	})

	return filteredRules
}

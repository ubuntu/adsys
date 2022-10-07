package policies

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/ubuntu/adsys/internal/consts"
	"github.com/ubuntu/adsys/internal/decorate"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/apparmor"
	"github.com/ubuntu/adsys/internal/policies/dconf"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/policies/gdm"
	"github.com/ubuntu/adsys/internal/policies/mount"
	"github.com/ubuntu/adsys/internal/policies/privilege"
	"github.com/ubuntu/adsys/internal/policies/scripts"
	"golang.org/x/sync/errgroup"
)

// Manager handles all managers for various policy handlers.
type Manager struct {
	policiesCacheDir string

	dconf     *dconf.Manager
	privilege *privilege.Manager
	scripts   *scripts.Manager
	mount     *mount.Manager
	gdm       *gdm.Manager
	apparmor  *apparmor.Manager

	subscriptionDbus dbus.BusObject
}

type options struct {
	cacheDir     string
	dconfDir     string
	sudoersDir   string
	policyKitDir string
	runDir       string
	apparmorDir  string
	gdm          *gdm.Manager
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

// WithRunDir specifies a personalized run directory.
func WithRunDir(p string) Option {
	return func(o *options) error {
		o.runDir = p
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

// NewManager returns a new manager with all default policy handlers.
func NewManager(bus *dbus.Conn, opts ...Option) (m *Manager, err error) {
	defer decorate.OnError(&err, i18n.G("can't create a new policy handlers manager"))

	// defaults
	args := options{
		cacheDir:    consts.DefaultCacheDir,
		runDir:      consts.DefaultRunDir,
		apparmorDir: consts.DefaultApparmorDir,
		gdm:         nil,
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
	privilegeManager := privilege.NewWithDirs(args.sudoersDir, args.policyKitDir)

	// scripts manager
	scriptsManager, err := scripts.New(args.runDir)
	if err != nil {
		return nil, err
	}

	// mount manager
	mountManager, err := mount.New(args.runDir)
	if err != nil {
		return nil, err
	}

	// apparmor manager
	apparmorManager := apparmor.New(args.apparmorDir)

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
		policiesCacheDir: policiesCacheDir,

		dconf:     dconfManager,
		privilege: privilegeManager,
		scripts:   scriptsManager,
		mount:     mountManager,
		apparmor:  apparmorManager,
		gdm:       args.gdm,

		subscriptionDbus: subscriptionDbus,
	}, nil
}

// ApplyPolicies generates a computer or user policy based on a list of entries
// retrieved from a directory service.
func (m *Manager) ApplyPolicies(ctx context.Context, objectName string, isComputer bool, pols *Policies) (err error) {
	defer decorate.OnError(&err, i18n.G("failed to apply policy to %q"), objectName)

	log.Infof(ctx, "Apply policy for %s (machine: %v)", objectName, isComputer)

	rules := pols.GetUniqueRules()
	var g errgroup.Group
	g.Go(func() error { return m.dconf.ApplyPolicy(ctx, objectName, isComputer, rules["dconf"]) })
	if !m.GetSubscriptionState(ctx) {
		filterRules(ctx, rules)
	}

	g.Go(func() error { return m.privilege.ApplyPolicy(ctx, objectName, isComputer, rules["privilege"]) })
	g.Go(func() error {
		return m.scripts.ApplyPolicy(ctx, objectName, isComputer, rules["scripts"], pols.SaveAssetsTo)
	})
	g.Go(func() error { return m.mount.ApplyPolicy(ctx, objectName, isComputer, rules["mount"]) })
	g.Go(func() error {
		return m.apparmor.ApplyPolicy(ctx, objectName, isComputer, rules["apparmor"], pols.SaveAssetsTo)
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
func (m *Manager) DumpPolicies(ctx context.Context, objectName string, withRules bool, withOverridden bool) (msg string, err error) {
	defer decorate.OnError(&err, i18n.G("failed to dump policies for %q"), objectName)

	log.Infof(ctx, "Dumping policies for %s", objectName)

	var out strings.Builder

	// Load machine for user
	// FIXME: fqdn in hostname?
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}

	var alreadyProcessedRules map[string]struct{}
	if objectName != hostname {
		fmt.Fprintln(&out, i18n.G("Policies from machine configuration:"))
		policiesHost, err := NewFromCache(ctx, filepath.Join(m.policiesCacheDir, hostname))
		if err != nil {
			return "", fmt.Errorf(i18n.G("no policy applied for %q: %v"), hostname, err)
		}
		for _, g := range policiesHost.GPOs {
			alreadyProcessedRules = g.Format(&out, withRules, withOverridden, alreadyProcessedRules)
		}
		fmt.Fprintln(&out, i18n.G("Policies from user configuration:"))
	}

	// Load target policies
	policiesTarget, err := NewFromCache(ctx, filepath.Join(m.policiesCacheDir, objectName))
	if err != nil {
		return "", fmt.Errorf(i18n.G("no policy applied for %q: %v"), objectName, err)
	}
	for _, g := range policiesTarget.GPOs {
		alreadyProcessedRules = g.Format(&out, withRules, withOverridden, alreadyProcessedRules)
	}

	return out.String(), nil
}

// LastUpdateFor returns the last update time for object or current machine.
func (m *Manager) LastUpdateFor(ctx context.Context, objectName string, isMachine bool) (t time.Time, err error) {
	defer decorate.OnError(&err, i18n.G("failed to get policy last update time %q (machine: %q)"), objectName, isMachine)

	log.Infof(ctx, "Get policies last update time %q (machine: %t)", objectName, isMachine)

	if isMachine {
		hostname, err := os.Hostname()
		if err != nil {
			return time.Time{}, err
		}
		objectName = hostname
	}

	info, err := os.Stat(filepath.Join(m.policiesCacheDir, objectName))
	if err != nil {
		return time.Time{}, fmt.Errorf(i18n.G("policies were not applied for %q: %v"), objectName, err)
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

// filterRules allow to filter any rules that is not eligible for the current device.
func filterRules(ctx context.Context, rules map[string][]entry.Entry) {
	log.Debug(ctx, "Filtering Rules")

	rules["privilege"] = nil
	rules["scripts"] = nil
	rules["mount"] = nil
	rules["apparmor"] = nil
}

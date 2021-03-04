package policies

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ubuntu/adsys/internal/config"
	"github.com/ubuntu/adsys/internal/decorate"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/dconf"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"golang.org/x/sync/errgroup"
)

// Manager handles all managers for various policy handlers.
type Manager struct {
	gpoRulesCacheDir string

	dconf dconf.Manager
}

type options struct {
	cacheDir string
}
type option func(*options) error

// WithCacheDir specifies a personalized daemon cache directory
func WithCacheDir(p string) func(o *options) error {
	return func(o *options) error {
		o.cacheDir = p
		return nil
	}
}

// New returns a new manager with all default policy handlers.
func New(opts ...option) (m *Manager, err error) {
	defer decorate.OnError(&err, i18n.G("can't create a new policy handlers manager"))

	// defaults
	args := options{
		cacheDir: config.DefaultCacheDir,
	}
	// applied options
	for _, o := range opts {
		if err := o(&args); err != nil {
			return nil, err
		}
	}

	gpoRulesCacheDir := filepath.Join(args.cacheDir, entry.GPORulesCacheBaseName)
	if err := os.MkdirAll(gpoRulesCacheDir, 0700); err != nil {
		return nil, err
	}

	return &Manager{
		gpoRulesCacheDir: gpoRulesCacheDir,

		dconf: dconf.Manager{},
	}, nil
}

// ApplyPolicy generates a computer or user policy based on a list of entries
// retrieved from a directory service.
func (m *Manager) ApplyPolicy(ctx context.Context, objectName string, isComputer bool, gpos []entry.GPO) (err error) {
	defer decorate.OnError(&err, i18n.G("failed to apply policy to %q"), objectName)

	log.Infof(ctx, "Apply policy for %s (machine: %v)", objectName, isComputer)

	rules := entry.GetUniqueRules(gpos)
	var g errgroup.Group
	g.Go(func() error { return m.dconf.ApplyPolicy(ctx, objectName, isComputer, rules["dconf"]) })
	// TODO g.Go(func() error { return m.scripts.ApplyPolicy(ctx, objectName, isComputer, rules["scripts"]) })
	// TODO g.Go(func() error { return m.apparmor.ApplyPolicy(ctx, objectName, isComputer, rules["apparmor"]) })
	if err := g.Wait(); err != nil {
		return err
	}

	// Write cache GPO results
	if err := entry.SaveGPOs(gpos, filepath.Join(m.gpoRulesCacheDir, objectName)); err != nil {
		return err
	}

	return nil
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
		gposHost, err := entry.NewGPOs(filepath.Join(m.gpoRulesCacheDir, hostname))
		if err != nil {
			return "", fmt.Errorf(i18n.G("no policy applied for %q: %v"), hostname, err)
		}
		for _, g := range gposHost {
			alreadyProcessedRules = g.FormatGPO(&out, withRules, withOverridden, alreadyProcessedRules)
		}
		fmt.Fprintln(&out, i18n.G("Policies from user configuration:"))
	}

	// Load target policies
	gposTarget, err := entry.NewGPOs(filepath.Join(m.gpoRulesCacheDir, objectName))
	if err != nil {
		return "", fmt.Errorf(i18n.G("no policy applied for %q: %v"), objectName, err)
	}
	for _, g := range gposTarget {
		alreadyProcessedRules = g.FormatGPO(&out, withRules, withOverridden, alreadyProcessedRules)
	}

	return out.String(), nil
}

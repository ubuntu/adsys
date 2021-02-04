package policies

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ubuntu/adsys/internal/config"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/dconf"
	"github.com/ubuntu/adsys/internal/policies/entry"
)

// KeyPrefix is the prefix for all our policies in the GPO
const KeyPrefix = "Software/Policies"

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
func New(opts ...option) (*Manager, error) {
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

	gpoRulesCacheDir := filepath.Join(args.cacheDir, "gpo_rules")
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
func (m *Manager) ApplyPolicy(ctx context.Context, objectName string, isComputer bool, gpos []entry.GPO) error {
	log.Infof(ctx, "Apply policy for %s (machine: %v)", objectName, isComputer)
	var err error

	for entryType, entries := range entry.GetUniqueRules(gpos) {
		switch entryType {
		case "dconf":
			err = m.dconf.ApplyPolicy(ctx, objectName, isComputer, entries)
		case "script":
			// TODO err = script.ApplyPolicy(objectName, isComputer, entries)
		case "apparmor":
			// TODO err = apparmor.ApplyPolicy(objectName, isComputer, entries)
		default:
			return fmt.Errorf(i18n.G("unknown entry type: %s for keys %s"), entryType, entries)
		}
		if err != nil {
			return err
		}
	}

	// Write cache GPO results
	if err := entry.SaveGPOs(gpos, filepath.Join(m.gpoRulesCacheDir, objectName)); err != nil {
		return err
	}

	return nil
}

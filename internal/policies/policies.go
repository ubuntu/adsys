package policies

import (
	"context"
	"fmt"

	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/dconf"
	"github.com/ubuntu/adsys/internal/policies/entry"
)

// KeyPrefix is the prefix for all our policies in the GPO
const KeyPrefix = "Software/Policies"

// Manager handles all managers for various policy handlers.
type Manager struct {
	dconf dconf.Manager
}

// New returns a new manager with all default policy handlers.
func New() Manager {
	return Manager{
		dconf: dconf.Manager{},
	}
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

	return nil
}

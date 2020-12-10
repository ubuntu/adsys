package policies

import (
	"context"
	"fmt"
	"strings"

	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/dconf"
	"github.com/ubuntu/adsys/internal/policies/entry"
)

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
func (m *Manager) ApplyPolicy(ctx context.Context, objectName string, isComputer bool, entries []entry.Entry) error {

	log.Infof(ctx, "Apply policy for %s (machine: %v)", objectName, isComputer)

	var dconfEntries, scriptEntries, apparmorEntries []entry.Entry
	for _, entry := range entries {
		trimstr := "Software/Ubuntu/"
		if isComputer {
			trimstr += "Computer/"
		} else {
			trimstr += "User/"
		}
		e := strings.SplitN(strings.TrimPrefix(entry.Key, trimstr), "/", 2)
		entryType := e[0]
		entry.Key = e[1]

		switch entryType {
		case "dconf":
			dconfEntries = append(dconfEntries, entry)
		case "script":
			scriptEntries = append(scriptEntries, entry)
		case "apparmor":
			apparmorEntries = append(apparmorEntries, entry)
		default:
			return fmt.Errorf(i18n.G("unknown entry type: %s for key %s"), entryType, entry.Key)
		}
	}

	err := m.dconf.ApplyPolicy(ctx, objectName, isComputer, dconfEntries)
	if err != nil {
		return err
	}

	// TODO
	/*
		err = script.ApplyPolicy(objectName, isComputer, scriptEntries)
		err = apparmor.ApplyPolicy(objectName, isComputer, apparmorEntries)
	*/

	return nil
}

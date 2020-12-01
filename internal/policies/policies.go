package policies

import (
	"fmt"
	"strings"

	"github.com/ubuntu/adsys/internal/i18n"
)

// Entry represents a key/value based policy (dconf, apparmor, ...) entry
type Entry struct {
	Key      string // Absolute path to setting. Ex: Sofware/Ubuntu/User/dconf/wallpaper
	Value    string
	Disabled bool
	Meta     string
}

// ApplyPolicy generates a computer or user policy based on a list of entries
// retrieved from a directory service.
func ApplyPolicy(objectName string, isComputer bool, entries []Entry) error {
	var dconfEntries, scriptEntries, apparmorEntries []Entry
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

	// TODO
	/*
		err := dconf.ApplyPolicy(objectName, isComputer, dconfEntries)
		err = script.ApplyPolicy(objectName, isComputer, scriptEntries)
		err = apparmor.ApplyPolicy(objectName, isComputer, apparmorEntries)
	*/

	return nil
}

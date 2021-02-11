package entry

import (
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"
	"sort"

	"github.com/ubuntu/adsys/internal/decorate"
	"github.com/ubuntu/adsys/internal/i18n"
	"gopkg.in/yaml.v2"
)

// Entry represents a key/value based policy (dconf, apparmor, ...) entry
type Entry struct {
	Key      string // Absolute path to setting. Ex: Software/Ubuntu/User/dconf/wallpaper
	Value    string
	Disabled bool
	Meta     string
}

const (
	// GPORulesCacheBaseName is the base directory where we want to cache gpo rules
	GPORulesCacheBaseName = "gpo_rules"
)

// GPO is a representation of a GPO with rules we support
type GPO struct {
	ID   string
	Name string
	// the string is the domain of rules (dconf, install…)
	Rules map[string][]Entry
}

// GetUniqueRules return order rules, with one entry per key for a given type.
// Returned file is a map of type to its entries.
func GetUniqueRules(gpos []GPO) map[string][]Entry {
	r := make(map[string][]Entry)
	keys := make(map[string][]string)

	// Dedup entries, first GPO wins for a given type + key
	dedup := make(map[string]map[string]Entry)
	seen := make(map[string]struct{})
	for _, gpo := range gpos {
		for t, entries := range gpo.Rules {
			if dedup[t] == nil {
				dedup[t] = make(map[string]Entry)
			}
			for _, e := range entries {
				if _, exists := seen[t+e.Key]; exists {
					continue
				}
				dedup[t][e.Key] = e
				keys[t] = append(keys[t], e.Key)
				seen[t+e.Key] = struct{}{}
			}
		}
	}

	// For each t, order entries by ascii order
	for t := range dedup {
		var entries []Entry
		sort.Strings(keys[t])
		for _, k := range keys[t] {
			entries = append(entries, dedup[t][k])
		}
		r[t] = entries
	}

	return r
}

// FormatGPO write to w a formatted GPO. overriden entries are prepended with -
func (g GPO) FormatGPO(w io.Writer, withRules, withOverridden bool, alreadyProcessedRules map[string]struct{}) map[string]struct{} {
	fmt.Fprintf(w, "* %s (%s)\n", g.Name, g.ID)

	if !withRules {
		return nil
	}

	var domains []string
	for domain := range g.Rules {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	for _, d := range domains {
		fmt.Fprintf(w, "** %s:\n", d)
		for _, r := range g.Rules[d] {
			k := filepath.Join(d, r.Key)
			_, overr := alreadyProcessedRules[k]
			if !withOverridden && overr {
				continue
			}
			prefix := "***"
			if overr {
				prefix += "-"
			}
			v := r.Value
			if r.Disabled {
				prefix += "+"
				fmt.Fprintf(w, "%s %s\n", prefix, r.Key)
			} else {
				fmt.Fprintf(w, "%s %s: %s\n", prefix, r.Key, v)
			}

			alreadyProcessedRules[k] = struct{}{}
		}
	}

	return alreadyProcessedRules
}

// NewGPOs returns cached gpos list loaded from the p json file
func NewGPOs(p string) (gpos []GPO, err error) {
	defer decorate.OnError(&err, i18n.G("can't get cached GPO list from %s"), p)

	d, err := ioutil.ReadFile(p)
	if err != nil {
		return nil, err
	}

	if err := yaml.Unmarshal(d, &gpos); err != nil {
		return nil, err
	}
	return gpos, nil
}

// SaveGPOs serializes in p the GPO list
func SaveGPOs(gpos []GPO, p string) (err error) {
	defer decorate.OnError(&err, i18n.G("can't save GPO list to %s"), p)

	d, err := yaml.Marshal(gpos)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(p, d, 0700); err != nil {
		return err
	}

	return nil
}

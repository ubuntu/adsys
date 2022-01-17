package policies

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ubuntu/adsys/internal/policies/entry"
)

const (
	// GPORulesCacheBaseName is the base directory where we want to cache gpo rules.
	GPORulesCacheBaseName = "gpo_rules"
)

// GPO is a representation of a GPO with rules we support.
type GPO struct {
	ID   string
	Name string
	// the string is the domain of rules (dconf, install…)
	Rules map[string][]entry.Entry
}

// GetUniqueRules return order rules, with one entry per key for a given type.
// Returned file is a map of type to its entries.
func GetUniqueRules(gpos []GPO) map[string][]entry.Entry {
	r := make(map[string][]entry.Entry)
	keys := make(map[string][]string)

	// Dedup entries, first GPO wins for a given type + key
	dedup := make(map[string]map[string]entry.Entry)
	seen := make(map[string]struct{})
	for _, gpo := range gpos {
		for t, entries := range gpo.Rules {
			if dedup[t] == nil {
				dedup[t] = make(map[string]entry.Entry)
			}
			for _, e := range entries {
				switch e.Strategy {
				case entry.StrategyAppend:
					// We skip disabled keys as we only append enabled one.
					if e.Disabled {
						continue
					}
					var keyAlreadySeen bool
					// If there is an existing value, prepend new value to it. We are analyzing GPOs in reverse order (closest first).
					if _, exists := seen[t+e.Key]; exists {
						keyAlreadySeen = true
						// We have seen a closest key which is an override. We don’t append furthest append values.
						if dedup[t][e.Key].Strategy != entry.StrategyAppend {
							continue
						}
						e.Value = e.Value + "\n" + dedup[t][e.Key].Value
						// Keep closest meta value.
						e.Meta = dedup[t][e.Key].Meta
					}
					dedup[t][e.Key] = e
					if keyAlreadySeen {
						continue
					}

				default:
					// override case
					if _, exists := seen[t+e.Key]; exists {
						continue
					}
					dedup[t][e.Key] = e
				}

				keys[t] = append(keys[t], e.Key)
				seen[t+e.Key] = struct{}{}
			}
		}
	}

	// For each t, order entries by ascii order
	for t := range dedup {
		var entries []entry.Entry
		sort.Strings(keys[t])
		for _, k := range keys[t] {
			entries = append(entries, dedup[t][k])
		}
		r[t] = entries
	}

	return r
}

// FormatGPO write to w a formatted GPO. overridden entries are prepended with -.
func (g GPO) FormatGPO(w io.Writer, withRules, withOverridden bool, alreadyProcessedRules map[string]struct{}) map[string]struct{} {
	fmt.Fprintf(w, "* %s (%s)\n", g.Name, g.ID)

	if !withRules {
		return nil
	}

	if alreadyProcessedRules == nil {
		alreadyProcessedRules = make(map[string]struct{})
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
			// Trim EOL \n and replace them all with \n in text to keep each value printed in one single line
			v := strings.ReplaceAll(strings.TrimSpace(r.Value), "\n", `\n`)
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

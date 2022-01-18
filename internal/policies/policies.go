package policies

import (
	"io"
	"os"
	"sort"

	"github.com/ubuntu/adsys/internal/decorate"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"gopkg.in/yaml.v3"
)

const (
	// PoliciesCacheBaseName is the base directory where we want to cache policies.
	PoliciesCacheBaseName = "policies"
)

// Policies is the list of GPOs applied to a particular object, with the global data cache.
type Policies struct {
	GPOs []GPO
	Data io.ReaderAt `yaml:"-"`
}

// NewFromCache returns cached policies loaded from the p json file.
func NewFromCache(p string) (pols Policies, err error) {
	defer decorate.OnError(&err, i18n.G("can't get cached policies from %s"), p)

	d, err := os.ReadFile(p)
	if err != nil {
		return pols, err
	}

	if err := yaml.Unmarshal(d, &pols); err != nil {
		return pols, err
	}
	return pols, nil
}

// Save serializes in p the policies.
func (pols *Policies) Save(p string) (err error) {
	defer decorate.OnError(&err, i18n.G("can't save policies to %s"), p)

	d, err := yaml.Marshal(pols)
	if err != nil {
		return err
	}
	if err := os.WriteFile(p, d, 0600); err != nil {
		return err
	}

	return nil
}

// GetUniqueRules return order rules, with one entry per key for a given type.
// Returned file is a map of type to its entries.
func (pols Policies) GetUniqueRules() map[string][]entry.Entry {
	r := make(map[string][]entry.Entry)
	keys := make(map[string][]string)

	// Dedup entries, first GPO wins for a given type + key
	dedup := make(map[string]map[string]entry.Entry)
	seen := make(map[string]struct{})
	for _, gpo := range pols.GPOs {
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

package entry

import "sort"

// Entry represents a key/value based policy (dconf, apparmor, ...) entry
type Entry struct {
	Key      string // Absolute path to setting. Ex: Software/Ubuntu/User/dconf/wallpaper
	Value    string
	Disabled bool
	Meta     string
}

// GPO is the GPO definition with all its parsed rules.
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

// TODO: printing policies (take machine and user for user or only machine and handle the overrides)

package policies

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ubuntu/adsys/internal/policies/entry"
)

// GPO is a representation of a GPO with rules we support.
type GPO struct {
	ID   string
	Name string
	// the string is the domain of rules (dconf, install…)
	Rules map[string][]entry.Entry
}

// Format write to w a formatted GPO. overridden entries are prepended with -.
func (g GPO) Format(w io.Writer, withRules, withOverridden bool, alreadyProcessedRules map[string]struct{}) map[string]struct{} {
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

			// Do not add non overridable key to the alreadyProcessedRules override detection map.
			if r.Strategy == "append" {
				continue
			}
			alreadyProcessedRules[k] = struct{}{}
		}
	}

	return alreadyProcessedRules
}

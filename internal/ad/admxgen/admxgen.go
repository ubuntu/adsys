/*
Package admxgen generates admx and adml from a category and multiple policies per release.

		The process is acting on multiple steps:
		- We generate on each release, for each type of conversion (dconf, install script, apparmor) common.ExpandedPolicy object.
		  The common.ExpandedPolicy is independent of the type of the policy and contains all needed data and metadata for the policy
		  for a given release.
		- Using the category definition, we merge all expanded policies in a finale expandedCategories set, which contains all definitions,
		  including any supported release information for a given policy. It can also adjust the default value information if it
		  differs between releases.
		- Finally, we are taking this expandedCategories object and outputing the administrative template from it.


	    categories.yaml --------------------------------------------|
	                                                                |
	    20.10:                                                      |
	    (install script)                                            |
	    install.yaml   -----|                                       |
	                        |                                       |
	    (dconf)             |----|> ExpandedPolicies --|            |
	    dconf.yaml ---|     |                          |            |
	                  |-----|                          |            |
	    schema -------|                                |            |
	                                                   |        |-------|
	                                                   |--------|   O   |-----|> expandedCategories ----|> PolicyDefinition (ADMX/ADML)
	                                                   |        |-------|
	    20.10:                                         |
	    (install script)                               |
	    install.yaml   -----|                          |
	                        |                          |
	    (dconf)             |----|> ExpandedPolicies --|
	    dconf.yaml ---|     |
	                  |-----|
	    schema -------|
*/
package admxgen

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"text/template"

	"github.com/leonelquinteros/gotext"
	"github.com/ubuntu/adsys/internal/ad/admxgen/common"
	adcommon "github.com/ubuntu/adsys/internal/ad/common"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/decorate"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const dconfPolicyType = "dconf"

// expandedCategories generation

type expandedCategory struct {
	DisplayName string
	Parent      string
	Policies    []mergedPolicy
	Children    []expandedCategory `yaml:",omitempty"`
}

type category struct {
	DisplayName        string
	Parent             string
	DefaultPolicyClass string
	Prefix             string
	Policies           []string
	Children           []category
}

type mergedPolicy struct {
	Key string
	// Merge of all explainText, defaults, supportedOn
	ExplainText string
	// Merge of all metas for enabled key
	MetaEnabled string
	// Merge of all metas for disabled key
	MetaDisabled string
	// Single class convenience (all ExpandedPolicy should match)
	Class string

	ReleasesElements map[string]common.ExpandedPolicy
}

type generator struct {
	distroID          string
	supportedReleases []string
}

var (
	// defaultAppendNote is the default note for append-type policies. It will be used unless a specific note is provided.
	defaultAppendNote = gotext.Get(`
 * Enabled: The value(s) referenced in the entry are applied on the client machine.
 * Disabled: The value(s) are removed from the target machine.
 * Not configured: Value(s) declared higher in the GPO hierarchy will be used if available.`)

	// defaultOverrideNote is the default note for override-type policies. It will be used unless a specific note is provided.
	defaultOverrideNote = gotext.Get(`
 * Enabled: The value(s) referenced in the entry are applied on the client machine.
 * Disabled: The value(s) are removed from the target machine.`)
)

func (g generator) generateExpandedCategories(categories []category, policies []common.ExpandedPolicy, allowMissingKeys bool) (ep []expandedCategory, err error) {
	defer decorate.OnError(&err, gotext.Get("can't generate expanded categories"))

	// noPoliciesOn is a map to attest that each release was assigned at least one property
	noPoliciesOn := make(map[string]struct{})
	for _, r := range g.supportedReleases {
		noPoliciesOn[r] = struct{}{}
	}

	keyPrefix := fmt.Sprintf(`%s\%s`, strings.ReplaceAll(adcommon.KeyPrefix, "/", `\`), g.distroID)

	// 1. Create MergedPolicies, indexed by key

	// Index policies by key and release for easier lookup
	indexedPolicies := make(map[string]map[string]common.ExpandedPolicy)
	unattachedPolicies := make(map[string]struct{})
	for _, p := range policies {
		if indexedPolicies[p.Key] == nil {
			indexedPolicies[p.Key] = make(map[string]common.ExpandedPolicy)
		}
		indexedPolicies[p.Key][p.Release] = p
		unattachedPolicies[p.Key] = struct{}{}
	}

	// Check that configuration is correct: all policies have a release or all are empty
	for _, p := range indexedPolicies {
		if _, ok := p[""]; !ok {
			continue
		}
		if len(p) > 1 {
			return nil, fmt.Errorf("policy %s has multiple release values while specifying to be release independent (no release element)", p[""].Key)
		}
	}

	mergedPolicies := make(map[string]mergedPolicy)
	for key := range indexedPolicies {
		// supportedReleases is ordered with latest being newest.

		var supportedOn, class, highestRelease, defaultString, typePol string
		var defaults []string
		var differentDefaultsBetweenReleases bool
		metasEnabled := make(map[string]map[string]string)
		metasDisabled := make(map[string]map[string]string)
		releasesElements := make(map[string]common.ExpandedPolicy)
		first := true
		for _, release := range g.supportedReleases {
			p, ok := indexedPolicies[key][release]
			if !ok {
				// is it a release-specific-less key?
				p, ok = indexedPolicies[key][""]
				// it doesn’t exist for this release and is release specific, skip
				if !ok {
					continue
				}
				// consider it for the "all" release
				release = "all"
			}

			// we have one policy at least on this release
			delete(noPoliciesOn, p.Release)

			// every elements should have the same type of policy and class
			if !first {
				if class != p.Class {
					return nil, fmt.Errorf("%s is of different class between releases. Got %q and %q", key, class, p.Class)
				}
				if typePol != p.Type {
					return nil, fmt.Errorf("%s is of different policy type between releases. Got %q and %q", key, typePol, p.Type)
				}
			}
			class = p.Class
			typePol = p.Type

			// Handle metas

			if len(p.MetaEnabled) == 0 {
				p.MetaEnabled = p.Meta
			}
			if len(p.MetaDisabled) == 0 {
				p.MetaDisabled = p.Meta
			}
			metasEnabled[release] = p.MetaEnabled
			// ensure we don’t serialize nil object to null but {}
			if metasEnabled[release] == nil {
				metasEnabled[release] = make(map[string]string)
			}
			metasDisabled[release] = p.MetaDisabled
			if metasDisabled[release] == nil {
				metasDisabled[release] = make(map[string]string)
			}

			if supportedOn == "" {
				if release != "all" {
					supportedOn = gotext.Get("Supported on %s %s", g.distroID, release)
				}
			} else {
				supportedOn = fmt.Sprintf("%s, %s", supportedOn, release)
			}

			if !first {
				if p.Default != defaultString {
					differentDefaultsBetweenReleases = true
				}
			}
			defaultString = p.Default

			defaults = append(defaults, gotext.Get("- Default for %s: %s", release, p.Default))

			if release > highestRelease {
				highestRelease = release
			}

			releasesElements[release] = p
			first = false
		}

		// No key attached to this release
		if highestRelease == "" {
			continue
		}

		// assign "all" elements and default to highest release description
		releasesElements["all"] = releasesElements[highestRelease]
		// match all metas to the highest release
		metasEnabled["all"] = metasEnabled[highestRelease]
		metasDisabled["all"] = metasDisabled[highestRelease]
		explainText := releasesElements["all"].ExplainText

		// Keep only all if there is one supported release on this key
		if len(releasesElements) == 2 {
			delete(releasesElements, highestRelease)
		}

		// Extends description
		explainText = fmt.Sprintf("%s\n\n- Type: %s\n- Key: %s", explainText, releasesElements["all"].Type, releasesElements["all"].Key)

		// Display all the default per release if there is at least 1 different
		// otherwise display only 1 defaut for all the releases

		// defaultVal is already ordered per release as we iterated previously
		if differentDefaultsBetweenReleases {
			explainText = fmt.Sprintf("%s\n%s", explainText, strings.Join(defaults, "\n"))
		} else if defaultString != "" {
			// All defaults are the same and not empty
			explainText = fmt.Sprintf("%s\n%s", explainText, gotext.Get("- Default: %s", defaultString))
		}

		explainText = gotext.Get("%s\n\nNote:", explainText)
		var note string
		if releasesElements["all"].Note != "" {
			note = releasesElements["all"].Note
		} else {
			switch releasesElements["all"].Meta["strategy"] {
			case entry.StrategyAppend:
				note = defaultAppendNote
			default:
				note = defaultOverrideNote
			}
		}
		explainText = fmt.Sprintf("%s %s", explainText, note)

		// supportedOn can be empty if no release is specified in the policy definition
		// In this case we don't want to print redundant newlines
		if supportedOn != "" {
			explainText = fmt.Sprintf("%s\n\n%s.", explainText, supportedOn)
		}

		// Mention if any of the policies require Ubuntu Pro
		// Currently this only applies to non-dconf policies
		if typePol != dconfPolicyType {
			explainText = fmt.Sprintf("%s\n\n%s", explainText, gotext.Get("An Ubuntu Pro subscription on the client is required to apply this policy."))
		}

		// prepare meta for the whole policy
		metaEnabled, err := json.Marshal(metasEnabled)
		if err != nil {
			return nil, errors.New(gotext.Get("failed to marshal enabled meta data"))
		}
		// We can’t have metaEnabled or metaDisabled being strictly equals:
		// some AD servers thinks they that disabled means
		// that the key is enabled (matching only on values, no **del set)
		if reflect.DeepEqual(metasEnabled, metasDisabled) {
			metasDisabled["DISABLED"] = make(map[string]string)
		}
		metaDisabled, err := json.Marshal(metasDisabled)
		if err != nil {
			return nil, errors.New(gotext.Get("failed to marshal disabled meta data"))
		}

		mergedPolicies[key] = mergedPolicy{
			Key:              fmt.Sprintf(`%s\%s\%s`, keyPrefix, typePol, strings.ReplaceAll(strings.TrimPrefix(key, "/"), "/", `\`)),
			Class:            class,
			MetaEnabled:      string(metaEnabled),
			MetaDisabled:     string(metaDisabled),
			ExplainText:      explainText,
			ReleasesElements: releasesElements,
		}
	}

	// Ensure that every release have at least one policy attached, or this is an user error
	if len(noPoliciesOn) > 0 {
		var releases []string
		for r := range noPoliciesOn {
			releases = append(releases, r)
		}
		return nil, errors.New(gotext.Get("some releases have no policies attached to them while being listed in categories: %v", releases))
	}

	// 2. Inflate policies in categories, keep policy order from category list

	var inflatePolicies func(cat category, mergedPolicies map[string]mergedPolicy) (expandedCategory, error)
	inflatePolicies = func(cat category, mergedPolicies map[string]mergedPolicy) (expandedCategory, error) {
		var policies []mergedPolicy

		if cat.DefaultPolicyClass == "" {
			return expandedCategory{}, errors.New(gotext.Get("%s needs a default policy class", cat.DisplayName))
		}
		defaultPolicyClass, err := common.ValidClass(cat.DefaultPolicyClass)
		if err != nil {
			return expandedCategory{}, err
		}

		var prefix string
		if cat.Prefix != "" {
			prefix = strings.TrimRight(cat.Prefix, "/")
		}

		for _, p := range cat.Policies {
			pol, ok := mergedPolicies[p]
			if !ok {
				err := errors.New(gotext.Get("policy %s referenced in %q does not exist in any supported releases", p, cat.DisplayName))
				if allowMissingKeys {
					log.Warning(context.Background(), err)
					continue
				}
				return expandedCategory{}, err
			}
			if pol.Class == "" {
				pol.Class = defaultPolicyClass
			}
			// inject prefix before type of policy
			if prefix != "" {
				pol.Key = strings.Replace(pol.Key, keyPrefix, keyPrefix+`\`+prefix, 1)
			}
			policies = append(policies, pol)
			delete(unattachedPolicies, p)
		}

		ec := expandedCategory{
			DisplayName: cat.DisplayName,
			Parent:      cat.Parent,
			Policies:    policies,
		}

		for _, child := range cat.Children {
			child, err := inflatePolicies(child, mergedPolicies)
			if err != nil {
				return expandedCategory{}, err
			}
			ec.Children = append(ec.Children, child)
		}
		return ec, nil
	}

	// Inflate from root categories
	var expandedCategories []expandedCategory
	for _, cat := range categories {
		c, err := inflatePolicies(cat, mergedPolicies)
		if err != nil {
			return nil, err
		}
		expandedCategories = append(expandedCategories, c)
	}

	// Check that all policies are at least attached once
	if len(unattachedPolicies) > 0 {
		return nil, errors.New(gotext.Get("the following policies have not been assigned to a category: %v", unattachedPolicies))
	}

	return expandedCategories, nil
}

// ADMX/ADML Generation

type categoryForADMX struct {
	DisplayName string
	Parent      string
}

type policyForADMX struct {
	mergedPolicy
	ParentCategory string
}

// HasOptions returns if any policy element has an element type, and so, we need to show an option.
func (p policyForADMX) HasOptions() bool {
	var hasElementType bool
	for _, ep := range p.ReleasesElements {
		if ep.ElementType == "" {
			continue
		}
		hasElementType = true
	}

	return hasElementType
}

// GetOrderedPolicyElements returns all the policy elements order by release in decreasing order.
func (p policyForADMX) GetOrderedPolicyElements() []common.ExpandedPolicy {
	var policies []common.ExpandedPolicy

	// Order releases by decreasing order
	var releases []string
	for rel := range p.ReleasesElements {
		releases = append(releases, rel)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(releases)))

	for i, rel := range releases {
		if i == 0 {
			allPol := p.ReleasesElements["all"]
			allPol.Release = "all"
			policies = append(policies, allPol)
		}

		// "all" is first
		if rel == "all" {
			continue
		}

		policies = append(policies, p.ReleasesElements[rel])
	}
	return policies
}

// Make a Regex to say we only want letters and numbers.
var re = regexp.MustCompile("[^a-zA-Z0-9]+")

func (g generator) toID(key string, s ...string) string {
	key = strings.TrimPrefix(key, strings.ReplaceAll(adcommon.KeyPrefix, "/", `\`)+`\`+g.distroID)
	r := g.distroID

	for _, e := range s {
		r += re.ReplaceAllString(cases.Title(language.Und, cases.NoLower).String(e), "")
	}
	return r + re.ReplaceAllString(cases.Title(language.Und, cases.NoLower).String(key), "")
}

func (g generator) expandedCategoriesToADMX(expandedCategories []expandedCategory, dest string) (err error) {
	defer decorate.OnError(&err, gotext.Get("can't generate ADMX files"))

	var inputCategories []categoryForADMX
	var inputPolicies []policyForADMX
	for _, p := range expandedCategories {
		cat, pol := g.collectCategoriesPolicies(p, "")
		inputCategories = append(inputCategories, cat...)
		inputPolicies = append(inputPolicies, pol...)
	}

	input := struct {
		DistroID   string
		Categories []categoryForADMX
		Policies   []policyForADMX
	}{g.distroID, inputCategories, inputPolicies}

	if err := os.MkdirAll(dest, 0750); err != nil {
		return errors.New(gotext.Get("can't create destination directory for AD policies: %v", err))
	}

	funcMap := template.FuncMap{
		"toID": g.toID,
	}

	// Create admx

	f, err := os.Create(filepath.Join(dest, g.distroID+".admx"))
	if err != nil {
		return errors.New(gotext.Get("can't create admx file: %v", err))
	}
	defer decorate.LogFuncOnError(f.Close)
	t := template.Must(template.New("admx.template").Funcs(funcMap).Parse(admxTemplate))
	err = t.Execute(f, input)
	if err != nil {
		return err
	}

	// Create adml

	f, err = os.Create(filepath.Join(dest, g.distroID+".adml"))
	if err != nil {
		return errors.New(gotext.Get("can't create admx file: %v", err))
	}
	defer decorate.LogFuncOnError(f.Close)
	t = template.Must(template.New("adml.template").Funcs(funcMap).Parse(admlTemplate))
	err = t.Execute(f, input)
	if err != nil {
		return err
	}

	return nil
}

func expandedCategoriesToMD(expandedCategories []expandedCategory, rootDest string, currentRelPath string) (err error) {
	computerDest, userDest := filepath.Join(rootDest, "Computer Policies", currentRelPath), filepath.Join(rootDest, "User Policies", currentRelPath)
	// bootstrap first directories
	if currentRelPath == "." {
		for _, dest := range []string{rootDest, computerDest, userDest} {
			if dest != rootDest {
				if err := os.RemoveAll(dest); err != nil {
					return err
				}
			}
			if err := os.Mkdir(dest, 0700); err != nil {
				if dest == rootDest && errors.Is(err, os.ErrExist) {
					continue
				}
				return err
			}
		}
	}

	for _, ec := range expandedCategories {
		// Directories: create both paths.
		computerCategoryDir, userCategoryDir := filepath.Join(computerDest, ec.DisplayName), filepath.Join(userDest, ec.DisplayName)
		for _, p := range []string{computerCategoryDir, userCategoryDir} {
			if err := os.Mkdir(p, 0700); err != nil {
				return err
			}
		}

		// This is a list of policies in the current directory.
		for _, p := range ec.Policies {
			dest := computerCategoryDir
			if p.Class == "User" {
				dest = userCategoryDir
			}
			polDetails := p.ReleasesElements["all"]

			input := struct {
				Location       string
				Key            string
				DisplayName    string
				ExplainText    string
				ElementType    string
				Class          string
				RangeValuesMin string
				RangeValuesMax string
				Choices        []string
			}{
				strings.ReplaceAll(
					strings.TrimLeft(filepath.Join(dest, filepath.Base(polDetails.DisplayName)), rootDest),
					"/", " -> "),
				p.Key,
				polDetails.DisplayName,
				strings.ReplaceAll(
					strings.ReplaceAll(
						strings.TrimSpace(strings.TrimPrefix(p.ExplainText, "-")),
						"[", "`["),
					"]", "]`"),
				string(polDetails.ElementType),
				p.Class,
				polDetails.RangeValues.Min,
				polDetails.RangeValues.Max,
				polDetails.Choices,
			}

			f, err := os.Create(filepath.Join(dest, filepath.Base(polDetails.Key)) + ".md")
			if err != nil {
				return errors.New(gotext.Get("can't create md file: %v", err))
			}
			defer decorate.LogFuncOnError(f.Close)
			t := template.Must(template.New("doc policy").Parse(docPolicyTemplate))
			err = t.Execute(f, input)
			if err != nil {
				return err
			}
		}

		// Expand children categories.
		if err := expandedCategoriesToMD(ec.Children, rootDest, filepath.Join(currentRelPath, ec.DisplayName)); err != nil {
			return err
		}

		// Remove any folders that are still empty after the expansion of children categories and policies
		// (the leaves will be removed first, and so children empty categories are already purged).
		for _, p := range []string{computerCategoryDir, userCategoryDir} {
			if err := removeDirIfEmpty(p); err != nil {
				return err
			}
		}
	}

	// Remove root directories if they are empty
	if currentRelPath == "." {
		for _, p := range []string{computerDest, userDest, rootDest} {
			if err := removeDirIfEmpty(p); err != nil {
				return err
			}
		}
	}

	return nil
}

func removeDirIfEmpty(p string) error {
	children, err := os.ReadDir(p)
	if err != nil {
		return err
	}
	if len(children) > 0 {
		return nil
	}
	return os.Remove(p)
}

func (g generator) collectCategoriesPolicies(category expandedCategory, parent string) ([]categoryForADMX, []policyForADMX) {
	if parent == "" {
		parent = category.Parent
	}
	cat := categoryForADMX{
		DisplayName: category.DisplayName,
		Parent:      parent,
	}
	categories := []categoryForADMX{cat}
	catID := g.toID(cat.DisplayName)

	var policies []policyForADMX
	// Collect now directly attached policies
	for _, p := range category.Policies {
		policies = append(policies, policyForADMX{
			mergedPolicy:   p,
			ParentCategory: catID,
		})
	}

	// Collect children categories and policies
	for _, c := range category.Children {
		chidren, childrenpol := g.collectCategoriesPolicies(c, catID)
		categories = append(categories, chidren...)
		policies = append(policies, childrenpol...)
	}

	return categories, policies
}

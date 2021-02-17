/*
admxgen generates admx and adml from a category and multiple policies per release

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
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"text/template"

	"github.com/ubuntu/adsys/internal/decorate"
	"github.com/ubuntu/adsys/internal/i18n"
	policiesPkg "github.com/ubuntu/adsys/internal/policies"
	"github.com/ubuntu/adsys/internal/policies/ad/admxgen/common"
)

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
	Policies           []string
	Children           []category
}

type mergedPolicy struct {
	Key string
	// Merge of all explainText, defaults, supportedOn
	ExplainText string
	// Merge of all metas
	Meta string
	// Single class convenience (all ExpandedPolicy should match)
	Class string

	ReleasesElements map[string]common.ExpandedPolicy
}

type generator struct {
	distroID          string
	supportedReleases []string
}

func (g generator) generateExpandedCategories(categories []category, policies []common.ExpandedPolicy) (ep []expandedCategory, err error) {
	defer decorate.OnError(&err, i18n.G("can't generate expanded categories"))

	// noPoliciesOn is a map to attest that each release was assigned at least one property
	noPoliciesOn := make(map[string]struct{})
	for _, r := range g.supportedReleases {
		noPoliciesOn[r] = struct{}{}
	}

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

	mergedPolicies := make(map[string]mergedPolicy)
	for key := range indexedPolicies {
		// supportedReleases is ordered with latest being newest.

		var supportedOn, class, highestRelease, defaultString, typePol string
		var defaults []string
		var differentDefaultsBetweenReleases bool
		metas := make(map[string]string)
		releasesElements := make(map[string]common.ExpandedPolicy)
		first := true
		for _, release := range g.supportedReleases {
			p, ok := indexedPolicies[key][release]
			// if it doesn’t exist for this release, skip
			if !ok {
				continue
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

			metas[release] = p.Meta
			if supportedOn == "" {
				supportedOn = fmt.Sprintf(i18n.G("Supported on %s %s"), g.distroID, release)
			} else {
				supportedOn = fmt.Sprintf("%s, %s", supportedOn, release)
			}

			if !first {
				if p.Default != defaultString {
					differentDefaultsBetweenReleases = true
				}
			}
			defaultString = p.Default

			defaults = append(defaults, fmt.Sprintf(i18n.G("- Default for %s: %s"), release, p.Default))

			if release > highestRelease {
				highestRelease = release
			}

			releasesElements[release] = p
			first = false
		}

		// assign "all" elements and default to higest release description
		var explainText string
		if highestRelease != "" {
			releasesElements["all"] = releasesElements[highestRelease]
			metas["all"] = releasesElements["all"].Meta
			explainText = releasesElements["all"].ExplainText
		}

		// Keep only all if there is one supported release on this key
		if len(releasesElements) == 2 {
			delete(releasesElements, highestRelease)
		}

		// Display all the default per release if there is at least 1 different
		// otherwise display only 1 defaut for all the releases

		// defaultVal is already ordered per release as we iterated previously
		if differentDefaultsBetweenReleases {
			explainText = fmt.Sprintf("%s\n\n%s", explainText, strings.Join(defaults, "\n"))
		} else {
			explainText = fmt.Sprintf("%s\n\n%s", explainText, fmt.Sprintf(i18n.G("Default: %s"), defaultString))
		}

		explainText = fmt.Sprintf(i18n.G("%s\nNote: default system value is used for \"Not Configured\" and enforced if \"Disabled\"."), explainText)
		explainText = fmt.Sprintf("%s\n\n%s", explainText, supportedOn)

		// prepare meta for the whole policy
		meta, err := json.Marshal(metas)
		if err != nil {
			return nil, errors.New(i18n.G("failed to marshal meta data"))
		}

		mergedPolicies[key] = mergedPolicy{
			Key:              fmt.Sprintf(`%s\%s\%s\%s`, strings.ReplaceAll(policiesPkg.KeyPrefix, "/", `\`), g.distroID, typePol, strings.ReplaceAll(strings.TrimPrefix(key, "/"), "/", `\`)),
			Class:            class,
			Meta:             string(meta),
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
		return nil, fmt.Errorf(i18n.G("some releases have no policies attached to them while being listed in categories: %v"), releases)
	}

	// 2. Inflate policies in categories, keep policy order from category list

	var inflatePolicies func(cat category, mergedPolicies map[string]mergedPolicy) (expandedCategory, error)
	inflatePolicies = func(cat category, mergedPolicies map[string]mergedPolicy) (expandedCategory, error) {
		var policies []mergedPolicy

		if cat.DefaultPolicyClass == "" {
			return expandedCategory{}, fmt.Errorf(i18n.G("%s needs a default policy class"), cat.DisplayName)
		}
		defaultPolicyClass, err := common.ValidClass(cat.DefaultPolicyClass)
		if err != nil {
			return expandedCategory{}, err
		}

		for _, p := range cat.Policies {
			pol, ok := mergedPolicies[p]
			if !ok {
				return expandedCategory{}, fmt.Errorf(i18n.G("policy %s referenced in %q does not exist in any supported releases"), p, cat.DisplayName)
			}
			if pol.Class == "" {
				pol.Class = defaultPolicyClass
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
		return nil, fmt.Errorf(i18n.G("the following policies have been assigned to a category: %v"), unattachedPolicies)
	}

	return expandedCategories, nil
}

// ADMX/ADML Generation

type categoryForADMX struct {
	DisplayName string
	Parent      string
}

type policyForADMX struct {
	common.ExpandedPolicy
	ParentCategory string

	// override to not use the ones from ExpandedPolicy. Should be kept empty for admx
	Release string
	Type    string
}

// Make a Regex to say we only want letters and numbers
var re = regexp.MustCompile("[^a-zA-Z0-9]+")

func (g generator) toID(prefix, s string) string {
	s = strings.TrimPrefix(s, strings.ReplaceAll(policiesPkg.KeyPrefix, "/", `\`)+`\`+g.distroID)
	return g.distroID + re.ReplaceAllString(strings.Title(prefix)+strings.Title(s), "")
}

func (g generator) expandedCategoriesToADMX(expandedCategories []expandedCategory, dest string) (err error) {
	defer decorate.OnError(&err, i18n.G("can't generate ADMX files"))

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

	if err := os.MkdirAll(dest, 0755); err != nil {
		return fmt.Errorf(i18n.G("can't create destination directory for AD policies: %v"), err)
	}

	funcMap := template.FuncMap{
		"toID": g.toID,
	}
	_, curF, _, ok := runtime.Caller(0)
	if !ok {
		return errors.New(i18n.G("can't determine current file"))
	}
	dir := filepath.Dir(curF)

	// Create admx

	f, err := os.Create(filepath.Join(dest, g.distroID+".admx"))
	if err != nil {
		return fmt.Errorf(i18n.G("can't create admx file: %v"), err)
	}
	defer f.Close()
	t := template.Must(template.New("admx.template").Funcs(funcMap).ParseFiles(filepath.Join(dir, "admx.template")))
	err = t.Execute(f, input)
	if err != nil {
		return err
	}

	// Create adml

	f, err = os.Create(filepath.Join(dest, g.distroID+".adml"))
	if err != nil {
		return fmt.Errorf(i18n.G("can't create admx file: %v"), err)
	}
	defer f.Close()
	t = template.Must(template.New("adml.template").Funcs(funcMap).ParseFiles(filepath.Join(dir, "adml.template")))
	err = t.Execute(f, input)
	if err != nil {
		return err
	}

	return nil
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
	catID := g.toID("", cat.DisplayName)

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

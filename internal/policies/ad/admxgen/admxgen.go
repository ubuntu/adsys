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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"

	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/ad/admxgen/common"
)

// expandedCategories generation

type expandedCategory struct {
	DisplayName string
	Parent      string
	Policies    []common.ExpandedPolicy
	Children    []expandedCategory `yaml:",omitempty"`
}

type category struct {
	DisplayName        string
	Parent             string
	DefaultPolicyClass string
	Policies           []string
	Children           []category
}

type generator struct {
	distroID          string
	supportedReleases []string
}

func (g generator) generateExpandedCategories(categories []category, policies []common.ExpandedPolicy) ([]expandedCategory, error) {
	supportedReleaseNum := len(g.supportedReleases)

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

	mergedPolicies := make(map[string]common.ExpandedPolicy)
	for key, policies := range indexedPolicies {
		// cross releases, handle supported on and defaults
		var writeSupportedOn bool
		if len(policies) != supportedReleaseNum {
			writeSupportedOn = true
		}
		// supportedReleases is ordered with latest being newest.
		// Those are the descriptions which wins.
		var supportedOn []string
		var typePol, displayName, explainText, meta, class string
		var elementType common.WidgetType

		type defaultVal struct {
			value   string
			release string
		}
		var defaults []defaultVal

		for _, release := range g.supportedReleases {
			p, ok := indexedPolicies[key][release]
			// if it doesn’t exist for this release, skip
			if !ok {
				continue
			}

			// we have one policy at least on this release
			delete(noPoliciesOn, p.Release)

			// meta, type, class or elementtype is different -> error
			if meta != "" && meta != p.Meta {
				return nil, fmt.Errorf("%s is of different meta between releases. Got %q and %q", key, meta, p.Meta)
			}
			if typePol != "" && typePol != p.Type {
				return nil, fmt.Errorf("%s is of different policy type between releases. Got %q and %q", key, typePol, p.Type)
			}
			if class != "" && class != p.Class {
				return nil, fmt.Errorf("%s is of different class between releases. Got %q and %q", key, class, p.Class)
			}
			if elementType != "" && elementType != p.ElementType {
				return nil, fmt.Errorf("%s is of different element type between releases. Got %q and %q", key, elementType, p.ElementType)
			}

			typePol = p.Type
			displayName = p.DisplayName
			if writeSupportedOn {
				supportedOn = append(supportedOn, fmt.Sprintf(i18n.G("- Supported on %s"), release))
			}

			explainText = p.ExplainText
			elementType = p.ElementType
			meta = p.Meta
			class = p.Class

			defaults = append(defaults, defaultVal{value: p.Default, release: release})
		}

		// Display all the default per release if there is at least 1 different
		// otherwise display only 1 defaut for all the releases
		var defaultString string
		var perReleaseDefault []string
		// defaultVal is already ordered per release as we iterated previously
		for _, d := range defaults {
			perReleaseDefault = append(perReleaseDefault, fmt.Sprintf(i18n.G("Default for %s %s: %s"), g.distroID, d.release, d.value))

			if defaultString != "" && d.value != defaultString {
				defaultString = "PERRELEASE"
				continue
			}
			defaultString = d.value
		}
		if defaultString == "PERRELEASE" {
			explainText = fmt.Sprintf("%s\n\n%s", explainText, strings.Join(perReleaseDefault, "\n"))
		} else {
			explainText = fmt.Sprintf("%s\n\n%s", explainText, fmt.Sprintf(i18n.G("Default: %s"), defaultString))
		}
		explainText = fmt.Sprintf(i18n.G(`%s\nNote: default system value is used for "Not Configured" and enforced if "Disabled".`), explainText)

		// Display supportedOn if there is one different from others
		if len(supportedOn) != 0 {
			explainText = fmt.Sprintf("%s\n\n%s", explainText, strings.Join(supportedOn, "\n"))
		}

		mergedPolicies[key] = common.ExpandedPolicy{
			Key:         fmt.Sprintf(`Software\%s\%s\%s`, g.distroID, typePol, strings.ReplaceAll(key, "/", `\`)),
			DisplayName: displayName,
			ExplainText: explainText,
			ElementType: elementType,
			Meta:        meta,
			Class:       class,
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

	var inflatePolicies func(cat category, mergedPolicies map[string]common.ExpandedPolicy) (expandedCategory, error)
	inflatePolicies = func(cat category, mergedPolicies map[string]common.ExpandedPolicy) (expandedCategory, error) {
		var policies []common.ExpandedPolicy

		for _, p := range cat.Policies {
			pol, ok := mergedPolicies[p]
			if !ok {
				return expandedCategory{}, fmt.Errorf(i18n.G("policy %s referenced in %q does not exist"), p, cat.DisplayName)
			}
			if pol.Class == "" {
				pol.Class = cat.DefaultPolicyClass
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
	Key            string
	DisplayName    string
	ParentCategory string
	ExplainText    string
	ElementType    common.WidgetType
	Meta           string
	Class          string
	SupportedOn    string
}

func (g generator) toID(prefix, n string) string {
	return g.distroID + strings.Title(prefix) + strings.ReplaceAll(strings.Title(n), " ", "")
}

func (g generator) expandedCategoriesToADMX(expandedCategories []expandedCategory, dest string) error {
	var inputCategories []categoryForADMX
	var inputPolicies []policyForADMX
	for _, p := range expandedCategories {
		cat, pol := g.collectCategoriesPolicies(p, "")
		inputCategories = append(inputCategories, cat...)
		inputPolicies = append(inputPolicies, pol...)
	}

	input := struct {
		Categories []categoryForADMX
		Policies   []policyForADMX
	}{inputCategories, inputPolicies}

	if err := os.MkdirAll(dest, 0755); err != nil {
		return fmt.Errorf(i18n.G("can't create destination directory for AD policies: %v"), err)
	}

	funcMap := template.FuncMap{
		"toID": g.toID,
		"base": filepath.Base,
		"dir":  filepath.Dir,
	}
	_, curF, _, ok := runtime.Caller(0)
	if !ok {
		return errors.New(i18n.G("can't determine current file"))
	}
	dir := filepath.Dir(curF)

	// Create admx

	f, err := os.Create(filepath.Join(dest, "adsys.admx"))
	if err != nil {
		return fmt.Errorf(i18n.G("can't create admx file: %v"), err)
	}
	defer f.Close()
	t := template.Must(template.New("admx.template").Funcs(funcMap).ParseFiles(filepath.Join(dir, "admx.template")))
	err = t.Execute(f, input)
	if err != nil {
		return fmt.Errorf(i18n.G("couldn't generate admx: %v"), err)
	}

	// Create adml

	f, err = os.Create(filepath.Join(dest, "adsys.adml"))
	if err != nil {
		return fmt.Errorf(i18n.G("can't create admx file: %v"), err)
	}
	defer f.Close()
	t = template.Must(template.New("adml.template").Funcs(funcMap).ParseFiles(filepath.Join(dir, "adml.template")))
	err = t.Execute(f, input)
	if err != nil {
		return fmt.Errorf(i18n.G("couldn't generate adml: %v"), err)
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
			Key:            p.Key,
			DisplayName:    p.DisplayName,
			ParentCategory: catID,
			ExplainText:    p.ExplainText,
			ElementType:    p.ElementType,
			Meta:           p.Meta,
			Class:          p.Class,
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

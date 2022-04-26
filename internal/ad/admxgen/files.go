package admxgen

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ubuntu/adsys/internal/ad/admxgen/common"
	"github.com/ubuntu/adsys/internal/ad/admxgen/dconf"
	adcommon "github.com/ubuntu/adsys/internal/ad/common"
	"github.com/ubuntu/adsys/internal/decorate"
	"github.com/ubuntu/adsys/internal/i18n"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

//go:embed admx.template
var admxTemplate string

//go:embed adml.template
var admlTemplate string

// Expand will expand any policies on the system into a list of expanded policies.
func Expand(src, dst, root, currentSession string) error {
	release, err := adcommon.GetVersionID(root)
	if err != nil {
		return err
	}

	if _, err = os.Stat(src); err != nil {
		return fmt.Errorf(i18n.G("failed to access definition files: %w"), err)
	}
	// Expand policies for all supported yaml files
	files, err := filepath.Glob(filepath.Join(src, "*.yaml"))
	if err != nil {
		return fmt.Errorf(i18n.G("failed to read list of definition files: %w"), err)
	}

	expandedPoliciesStream := make(chan []common.ExpandedPolicy, len(files))
	var g errgroup.Group
	for _, f := range files {
		f := f
		g.Go(func() error {
			t := strings.TrimSuffix(strings.ToLower(filepath.Base(f)), ".yaml")
			if t == "categories" {
				return nil
			}
			data, err := os.ReadFile(f)
			if err != nil {
				return err
			}

			switch t {
			case "dconf":
				var policies []dconf.Policy
				if err = yaml.Unmarshal(data, &policies); err != nil {
					return err
				}

				ep, err := dconf.Generate(policies, release, root, currentSession)
				if err != nil {
					return err
				}
				expandedPoliciesStream <- ep
			default:
				var policies []common.ExpandedPolicy
				if err = yaml.Unmarshal(data, &policies); err != nil {
					return err
				}

				// any release means that we want it for all releases with overrides
				for i, p := range policies {
					if p.Release != "any" {
						continue
					}
					policies[i].Release = release
				}

				expandedPoliciesStream <- policies
			}

			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}
	close(expandedPoliciesStream)

	var expandedPolicies []common.ExpandedPolicy
	for ep := range expandedPoliciesStream {
		expandedPolicies = append(expandedPolicies, ep...)
	}

	// Write expanded policy file
	data, err := yaml.Marshal(expandedPolicies)
	if err != nil {
		return fmt.Errorf("expanded policy format is incorrect: %w", err)
	}
	if err := os.MkdirAll(dst, 0750); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dst, release+".yaml"), data, 0600); err != nil {
		return err
	}

	return nil
}

type categoryFileStruct struct {
	DistroID          string
	SupportedReleases []string
	Categories        []category
}

// Generate creates and merge all policies into ADMX/ADML files.
func Generate(categoryDefinition, src, dst string, autoDetectReleases, allowMissingKeys bool) error {
	// Load all expanded categories
	policies, catfs, err := loadDefinitions(categoryDefinition, src)
	if err != nil {
		return err
	}

	supportedReleases := catfs.SupportedReleases
	if autoDetectReleases {
		supportedReleases = nil
		files, err := os.ReadDir(src)
		if err != nil {
			return fmt.Errorf("can't read source directory: %w", err)
		}
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), ".yaml") {
				continue
			}
			n := strings.TrimSuffix(f.Name(), ".yaml")
			supportedReleases = append(supportedReleases, n)
		}
	}

	g := generator{
		distroID:          catfs.DistroID,
		supportedReleases: supportedReleases,
	}
	ec, err := g.generateExpandedCategories(catfs.Categories, policies, allowMissingKeys)
	if err != nil {
		return err
	}
	err = g.expandedCategoriesToADMX(ec, dst)
	if err != nil {
		return err
	}

	return nil
}

func loadDefinitions(categoryDefinition, src string) (ep []common.ExpandedPolicy, cfs categoryFileStruct, err error) {
	defer decorate.OnError(&err, i18n.G("can't load category definition"))

	var nilCategoryFileStruct categoryFileStruct

	f, err := os.ReadDir(src)
	if err != nil {
		return nil, nilCategoryFileStruct, err
	}
	var epNames []string
	for _, n := range f {
		epNames = append(epNames, n.Name())
	}
	sort.Strings(epNames)

	var policies, p []common.ExpandedPolicy
	for _, n := range epNames {
		f := filepath.Join(src, n)
		d, err := os.ReadFile(f)
		if err != nil {
			return nil, nilCategoryFileStruct, err
		}
		err = yaml.Unmarshal(d, &p)
		if err != nil {
			return nil, nilCategoryFileStruct, fmt.Errorf("trying to load %s: %w", f, err)
		}
		policies = append(policies, p...)
	}

	// Load categories and meta
	var catfs categoryFileStruct
	catsDef, err := os.ReadFile(categoryDefinition)
	if err != nil {
		return nil, nilCategoryFileStruct, err
	}
	err = yaml.Unmarshal(catsDef, &catfs)
	if err != nil {
		return nil, nilCategoryFileStruct, fmt.Errorf("trying to load %s: %w", categoryDefinition, err)
	}

	return policies, catfs, nil
}

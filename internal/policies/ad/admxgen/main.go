package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/ubuntu/adsys/internal/policies/ad/admxgen/common"
	"github.com/ubuntu/adsys/internal/policies/ad/admxgen/dconf"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v2"
)

/*
Mode 1: pour tous les yaml dans desf sauf (category) generate 1 expanded policy file
admxgen expand rep_in rep_out
Mode 2: pour tous les expanded policy generes, generate adml/admx from category.yaml
admxgen adm category.yaml rep_expanded(former rep_out) rep_out
*/

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: %s [COMMAND] [ARGS] ...
Generate ADMX and intermediary working files from a list of policy definition
files

Commands:
  expand SOURCE DEST [-root PATH] [-current-session SESSION_NAME]
	Generates an intermediary policy definition file into DEST directory from
	all the policy definition files in SOURCE directory, using the correct
	decoder.
	The generated definition file will be of the form
	expanded_policies.RELEASE.yaml
	-root is the root filesystem path to use. Default to /.
	-current-session is the current session to consider for dconf per-session
	overrides. Default to "".

  admx CATEGORIES_DEF.yaml SOURCE DEST
	Collects all intermediary policy definition files in SOURCE directory to
	create admx and adml templates in DEST, based on CATEGORIES_DEF.yaml.
`, filepath.Base(os.Args[0]))
	}

	flagRoot := flag.String("root", "/", "")
	flagCurrentSession := flag.String("current-session", "", "")

	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		log.Error("Missing mandatory argument")
		flag.Usage()
		os.Exit(1)
	}
	switch strings.ToLower(args[0]) {
	case "expand":
		if len(args) != 3 {
			log.Error("Command expand is missing mandatory option(s)")
			flag.Usage()
			os.Exit(1)
		}
		if err := expand(args[1], args[2], *flagRoot, *flagCurrentSession); err != nil {
			log.Fatal(fmt.Errorf("command expand failed with %w", err))
			os.Exit(1)
		}
	case "admx":
		if len(args) != 4 {
			log.Error("Command admx is missing mandatory options(s)")
			flag.Usage()
			os.Exit(1)
		}
		if err := admx(args[1], args[2], args[3]); err != nil {
			log.Fatal(fmt.Errorf("command admx failed with %w", err))
			os.Exit(1)
		}
	default:
		log.Errorf("Unknown command: %s", args[0])
		flag.Usage()
		os.Exit(1)
	}
}

func expand(src, dst, root, currentSession string) error {
	// Get release
	releaseFile := filepath.Join(root, "etc/os-release")

	file, err := os.Open(releaseFile)
	if err != nil {
		return err
	}
	defer file.Close()

	var release string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if !strings.HasPrefix(scanner.Text(), "VERSION_ID=") {
			continue
		}
		release = strings.ReplaceAll(strings.TrimPrefix(scanner.Text(), "VERSION_ID="), `"`, "")
		break
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if release == "" {
		return fmt.Errorf("can't read VERSION_ID from %s", releaseFile)
	}

	// Expand policies for all supported yaml files
	files, err := ioutil.ReadDir(src)
	if err != nil {
		return err
	}
	expandedPoliciesStream := make(chan []common.ExpandedPolicy, len(files))
	var g errgroup.Group
	for _, f := range files {
		f := f
		g.Go(func() error {
			t := strings.TrimSuffix(strings.ToLower(filepath.Base(f.Name())), ".yaml")
			if t == "categories" {
				return nil
			}
			data, err := ioutil.ReadFile(filepath.Join(src, f.Name()))
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
				return fmt.Errorf("unsupported policy type: %s", t)
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
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}
	if err := ioutil.WriteFile(filepath.Join(dst, release+".yaml"), data, 0644); err != nil {
		return err
	}

	return nil
}

type categoryFileStruct struct {
	DistroID          string
	SupportedReleases []string
	Categories        []category
}

func admx(categoryDefinition, src, dst string) error {
	// Load all expanded categories
	f, err := ioutil.ReadDir(src)
	if err != nil {
		return err
	}
	var epNames []string
	for _, n := range f {
		epNames = append(epNames, n.Name())
	}
	sort.Strings(epNames)

	var policies, p []common.ExpandedPolicy
	for _, n := range epNames {
		d, err := ioutil.ReadFile(filepath.Join(src, n))
		if err != nil {
			return err
		}
		err = yaml.Unmarshal(d, &p)
		if err != nil {
			return err
		}
		policies = append(policies, p...)
	}

	// Load categories and meta
	var catfs categoryFileStruct
	catsDef, err := ioutil.ReadFile(categoryDefinition)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(catsDef, &catfs)
	if err != nil {
		return err
	}

	g := generator{
		distroID:          catfs.DistroID,
		supportedReleases: catfs.SupportedReleases,
	}
	ec, err := g.generateExpandedCategories(catfs.Categories, policies)
	if err != nil {
		return fmt.Errorf("can't generate expanded categories: %w", err)
	}
	err = g.expandedCategoriesToADMX(ec, dst)
	if err != nil {
		return fmt.Errorf("can't generate ADMX templates: %w", err)
	}

	return nil
}

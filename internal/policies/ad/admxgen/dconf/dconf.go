// Package dconf generates expanded policies from the dconf schemas available related to the given root directory.
package dconf

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/ad/admxgen/common"
	"gopkg.in/ini.v1"
)

// Policy represents a policy entry used to generate an ADMX
type Policy struct {
	ObjectPath string
	Schema     string
	Class      string
}

// schemasPath is the path to the directory that contains dconf schemas and overrides
const schemasPath = "usr/share/glib-2.0/schemas/"

type foo struct {
	w common.WidgetType
	d string
}

var (
	schemaTypeToMetadata = map[string]struct {
		widgetType common.WidgetType
		emptyValue string
	}{
		"s":  {common.WidgetTypeText, ""},
		"as": {common.WidgetTypeText, "[]"},
		"b":  {common.WidgetTypeBool, "false"},
		"i":  {common.WidgetTypeDecimal, "0"},
	}
)

// Generate creates a set of exapanded policies from a list of policies and
// dconf schemas available on the machine
func Generate(policies []Policy, release string, root, currentSessions string) ([]common.ExpandedPolicy, error) {
	s, d, err := loadSchemasFromDisk(filepath.Join(root, schemasPath), currentSessions)
	if err != nil {
		return nil, err
	}

	expandedPolicies, err := inflateToExpandedPolicies(policies, release, currentSessions, s, d)
	if err != nil {
		return nil, err
	}

	return expandedPolicies, nil
}

func inflateToExpandedPolicies(policies []Policy, release, currentSessions string, schemas map[string]schemaEntry, defaultsForPath map[string]string) ([]common.ExpandedPolicy, error) {
	var r []common.ExpandedPolicy

	for _, policy := range policies {
		index := policy.ObjectPath
		// relocatable path
		if policy.Schema != "" {
			index = filepath.Join(policy.Schema, filepath.Base(policy.ObjectPath))
		}
		s, ok := schemas[index]
		if !ok {
			log.Warningf("dconf entry %q is not available on this machine", index)
			continue
		}

		// consider :SESSION
		var defaultVal string
		var found bool
		if currentSessions != "" {
			currentSessions += ":" // Add empty the last session override
		}
		for _, session := range strings.Split(currentSessions, ":") {
			schema := s.Schema
			if session != "" {
				schema = fmt.Sprintf("%s:%s", schema, session)
			}
			defaultVal, found = defaultsForPath[filepath.Join(schema, filepath.Base(policy.ObjectPath))]
			if found {
				break
			}
		}
		// relocatable path without override, take the default from the schema
		if !found {
			defaultVal = s.DefaultRelocatable
		}

		var desc []string
		for _, d := range strings.Split(strings.TrimSpace(s.Description), "\n") {
			desc = append(desc, strings.TrimSpace(d))
		}

		ep := common.ExpandedPolicy{
			Key:         policy.ObjectPath,
			DisplayName: s.Summary,
			ExplainText: strings.Join(desc, " "),
			Class:       policy.Class,
			Release:     release,
			Default:     defaultVal,
		}

		m, ok := schemaTypeToMetadata[s.Type]
		if !ok {
			return nil, fmt.Errorf("listed type %q is not supported in schemaTypeToMetadata. Please add it", s.Type)
		}
		ep.ElementType = m.widgetType
		ep.Meta = fmt.Sprintf(`"%s": {"meta": "%s", "default": "%s"}`, filepath.Base(policy.ObjectPath), s.Type, m.emptyValue)

		r = append(r, ep)
	}
	return r, nil
}

// default are separated in a different map as defaults can be different for different object path from the same schema.
// it is thus indexed only by object path.
type schemaEntry struct {
	Schema             string
	ObjectPath         string // Relocatable schemas don’t have object path
	Type               string
	Summary            string
	Description        string
	DefaultRelocatable string
}

// schemaList represents the list of glib2.0 schemas loaded into memory.
type schemaList struct {
	//XMLName xml.Name `xml:"schemalist"`
	Enum []struct {
		ID    string `xml:"id,attr"`
		Value []struct {
			Nick  string  `xml:"nick,attr"`
			Value float32 `xml:"value,attr"`
		} `xml:"value"`
	} `xml:"enum"`
	Schema []struct {
		ID   string `xml:"id,attr"`
		Path string `xml:"path,attr"`
		Key  []struct {
			Name        string `xml:"name,attr"`
			Type        string `xml:"type,attr"`
			Enum        string `xml:"enum,attr"`
			Default     string `xml:"default"`
			Summary     string `xml:"summary"`
			Description string `xml:"description"`
			Range       struct {
				Min float32 `xml:"min,attr"`
				Max float32 `xml:"max,attr"`
			} `xml:"range"`
			Choices []struct {
				Value string `xml:"value,attr"`
			} `xml:"choices>choice"`
		} `xml:"key"`
	} `xml:"schema"`
}

func loadSchemasFromDisk(path string, currentSessions string) (entries map[string]schemaEntry, defaultsForPath map[string]string, err error) {
	entries = make(map[string]schemaEntry)
	defaultsForPath = make(map[string]string)

	// load schemas
	schemas, err := filepath.Glob(filepath.Join(path, "*.gschema.xml"))
	if err != nil {
		return nil, nil, fmt.Errorf(i18n.G("failed to read list of schemas: %w"), err)
	}

	for _, p := range schemas {
		f, err := os.Open(p)
		if err != nil {
			return nil, nil, fmt.Errorf(i18n.G("cannot open file: %w"), err)
		}
		defer f.Close()

		d, err := ioutil.ReadAll(f)
		if err != nil {
			return nil, nil, fmt.Errorf(i18n.G("cannot read schema data: %w"), err)
		}

		var sl schemaList
		if err := xml.Unmarshal(d, &sl); err != nil {
			log.Warningf("%s is an invalid schema: %v", p, err)
			continue
		}

		for _, s := range sl.Schema {
			var relocatable bool
			if s.Path == "" {
				relocatable = true
			}

			for _, k := range s.Key {
				objectPath := filepath.Join(s.Path, k.Name)
				index := objectPath
				if relocatable {
					objectPath = ""
					index = filepath.Join(s.ID, k.Name)
				}

				e := schemaEntry{
					Schema:      s.ID,
					ObjectPath:  objectPath, // Relocatable schemas don’t have object path
					Type:        k.Type,
					Summary:     k.Summary,
					Description: k.Description,
				}

				if relocatable {
					e.DefaultRelocatable = k.Default
				} else {
					defaultsForPath[filepath.Join(e.Schema, filepath.Base(e.ObjectPath))] = k.Default
				}

				entries[index] = e
			}
		}
	}

	// Load override files to override defaults
	overrides, err := filepath.Glob(filepath.Join(path, "*.gschema.override"))
	if err != nil {
		return nil, nil, fmt.Errorf(i18n.G("failed to read overrides files: %w"), err)
	}

	sort.Strings(overrides)
	for _, o := range overrides {
		c, err := ini.Load(o)
		if err != nil {
			log.Warningf("%s is an invalid override file: %v", o, err)
			continue
		}
		for _, s := range c.Sections() {
			for _, k := range s.Keys() {
				defaultsForPath[filepath.Join(s.Name(), k.Name())] = k.Value()
			}
		}
	}

	return entries, defaultsForPath, nil
}

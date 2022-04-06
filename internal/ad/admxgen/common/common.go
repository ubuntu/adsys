// Package common defines the data structures used to generate ADMX templates from policy definition files
package common

import (
	"fmt"

	"github.com/ubuntu/adsys/internal/i18n"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const (
	// WidgetTypeText will use the text widget type.
	WidgetTypeText WidgetType = "text"
	// WidgetTypeMultiText will use the multitext widget type.
	WidgetTypeMultiText WidgetType = "multiText"
	// WidgetTypeBool will use a checkbox.
	WidgetTypeBool WidgetType = "boolean"
	// WidgetTypeDecimal will use a decimal input.
	WidgetTypeDecimal WidgetType = "decimal"
	// WidgetTypeLongDecimal will use a unsigned int input.
	WidgetTypeLongDecimal WidgetType = "longDecimal"
	// WidgetTypeDropdownList will use the dropdown for selection between a fixed set of values.
	WidgetTypeDropdownList WidgetType = "dropdownList"
)

// WidgetType is the type of the component that is displayed in the GPO settings dialog.
type WidgetType string

// DecimalRange represents the range of an integer value.
type DecimalRange struct {
	Min string `yaml:",omitempty"`
	Max string `yaml:",omitempty"`
}

// ExpandedPolicy is the result of inflating a policy of a given type to a generic one, having all needed elements for a given release.
type ExpandedPolicy struct {
	Key          string
	DisplayName  string
	ExplainText  string
	ElementType  WidgetType
	Meta         map[string]string `yaml:",omitempty"`
	MetaEnabled  map[string]string `yaml:",omitempty"`
	MetaDisabled map[string]string `yaml:",omitempty"`
	Class        string            `yaml:",omitempty"`
	Default      string
	Note         string `yaml:",omitempty"`

	// optional
	Choices []string `yaml:",omitempty"`

	// optional per type elements
	// decimal
	RangeValues DecimalRange `yaml:",omitempty"`

	Release string `yaml:",omitempty"`
	Type    string `yaml:",omitempty"` // dconf, install…
}

// GetDefaultForADM returns the default matching the policy elements default rules.
func (p ExpandedPolicy) GetDefaultForADM() string {
	switch p.ElementType {
	case WidgetTypeDropdownList:
		for i, e := range p.Choices {
			if e == p.Default {
				return fmt.Sprintf("%d", i)
			}
		}
		return "0"
	default:
		return p.Default
	}
}

// ValidClass returns a valid, capitalized class. It will error out if it can’t match the input as valid class.
func ValidClass(class string) (string, error) {
	c := cases.Title(language.Und, cases.NoLower).String(class)

	if c != "" && c != "User" && c != "Machine" {
		return "", fmt.Errorf(i18n.G("invalid class %q"), class)
	}

	return c, nil
}

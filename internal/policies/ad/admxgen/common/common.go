// Package common defines the data structures used to generate ADMX templates from policy definition files
package common

import (
	"fmt"
	"strings"

	"github.com/ubuntu/adsys/internal/i18n"
)

const (
	// WidgetTypeText will use the text widget type
	WidgetTypeText WidgetType = "text"
	// WidgetTypeMultiText will use the multitext widget type
	WidgetTypeMultiText WidgetType = "multitext"
	// WidgetTypeBool will use a checkbox
	WidgetTypeBool WidgetType = "boolean"
	// WidgetTypeDecimal will use a decimal input
	WidgetTypeDecimal WidgetType = "decimal"
	// WidgetTypeLongDecimal will use a unsigned int input
	WidgetTypeLongDecimal WidgetType = "longDecimal"
	// WidgetTypeDropdownList will use the dropdown for selection between a fixed set of values
	WidgetTypeDropdownList WidgetType = "dropdownList"
)

// WidgetType is the type of the component that is displayed in the GPO settings dialog
type WidgetType string

// DecimalRange represents the range of an integer value
type DecimalRange struct {
	Min string `yaml:",omitempty"`
	Max string `yaml:",omitempty"`
}

// ExpandedPolicy is the common result of inflating a policy of a given type to a generic one, having all needed elements.
type ExpandedPolicy struct {
	Key         string
	DisplayName string
	ExplainText string
	ElementType WidgetType
	Meta        string
	Class       string
	Default     string

	// optional
	Choices []string `yaml:",omitempty"`

	// optional per type elements
	// decimal
	RangeValues DecimalRange `yaml:",omitempty"`

	// those are unused in expandedCategories
	Release string `yaml:",omitempty"`
	Type    string `yaml:",omitempty"` // dconf, install…
}

// ValidClass returns a valid, capitalized class. It will error out if it can’t match the input as valid class
func ValidClass(class string) (string, error) {
	c := strings.Title(class)

	if c != "" && c != "User" && c != "Machine" {
		return "", fmt.Errorf(i18n.G("invalid class %q"), class)
	}

	return c, nil
}

// Package common defines the data structures used to generate ADMX templates from policy definition files
package common

const (
	// WidgetTypeText will use the text widget type
	WidgetTypeText WidgetType = "text"
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

// Package common defines the data structures used to generate ADMX templates from policy definition files
package common

const (
	// WidgetTypeText will use the text widget type
	WidgetTypeText WidgetType = "Text"
	// WidgetTypeBool will use a checkbox
	WidgetTypeBool WidgetType = "Bool"
	// WidgetTypeDecimal will use a decimal input
	WidgetTypeDecimal WidgetType = "Decimal"
)

// WidgetType is the type of the component that is displayed in the GPO settings dialog
type WidgetType string

// ExpandedPolicy is the common result of inflating a policy of a given type to a generic one, having all needed elements.
type ExpandedPolicy struct {
	Key         string
	DisplayName string
	ExplainText string
	ElementType WidgetType
	Meta        string
	Class       string

	// those are unused in expandedCategories
	Default string `yaml:",omitempty"`
	Release string `yaml:",omitempty"`
	Type    string `yaml:",omitempty"` // dconf, install…
}

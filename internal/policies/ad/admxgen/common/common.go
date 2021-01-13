package common

const (
	// WidgetTypeText is the text format of the widget type
	WidgetTypeText    WidgetType = "Text"
	WidgetTypeBool    WidgetType = "Bool"
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
	Default string
	Release string
}

package inventory

// State represents the state of the inventory.
type State string

//nolint:revive // These are self-explanatory.
const (
	Null State = ""

	BaseVMCreated   State = "base_vm_created"
	TemplateCreated State = "template_created"

	PackageBuilt      State = "package_built"
	ClientProvisioned State = "client_provisioned"
	ADProvisioned     State = "ad_provisioned"
	Deprovisioned     State = "deprovisioned"
)

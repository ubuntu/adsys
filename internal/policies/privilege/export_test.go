package privilege

// WithPolicyKitSystemDir sets the directory where the default policykit files are stored.
func WithPolicyKitSystemDir(dir string) func(*option) {
	return func(o *option) {
		o.policyKitSystemDir = dir
	}
}

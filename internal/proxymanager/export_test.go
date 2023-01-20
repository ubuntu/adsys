package proxymanager

// WithEnvironmentConfigPath overrides the default environment config path.
func WithEnvironmentConfigPath(path string) func(o *options) {
	return func(o *options) {
		o.environmentConfigPath = path
	}
}

// WithAptConfigPath overrides the default APT config path.
func WithAptConfigPath(path string) func(o *options) {
	return func(o *options) {
		o.aptConfigPath = path
	}
}

package apparmor

// WithApparmorParserCmd allows to mock the apparmor_parser call.
func WithApparmorParserCmd(cmd []string) Option {
	return func(o *options) {
		o.apparmorParserCmd = cmd
	}
}

// WithLoadedPoliciesFile overrides the default location for the loaded policies file.
func WithLoadedPoliciesFile(path string) Option {
	return func(o *options) {
		o.loadedPoliciesFile = path
	}
}

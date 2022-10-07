package apparmor

// WithApparmorParserCmd allows to mock the apparmor_parser call.
func WithApparmorParserCmd(cmd []string) Option {
	return func(o *options) {
		o.apparmorParserCmd = cmd
	}
}

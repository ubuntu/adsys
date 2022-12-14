package winbind

// WithKinitCmd specifies a personalized kinit command for the backend to use.
func WithKinitCmd(cmd []string) Option {
	return func(o *options) {
		o.kinitCmd = cmd
	}
}

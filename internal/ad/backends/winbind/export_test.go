package winbind

// WithKinitCmd specifies a personalized kinit command for the backend to use.
func WithKinitCmd(cmd []string) Option {
	return func(o *options) {
		o.kinitCmd = cmd
	}
}

// WithHostname specifies a personalized hostname for kinit to use when getting
// the Kerberos cached credential.
func WithHostname(hostname string) Option {
	return func(o *options) {
		o.hostname = hostname
	}
}

package ad

func withoutKerberos() Option {
	return func(o *options) error {
		o.withoutKerberos = true
		return nil
	}
}

func withGPOListCmd(cmd []string) Option {
	return func(o *options) error {
		o.gpoListCmd = cmd
		return nil
	}
}

// WithVersionID specifies a personalized release id.
func WithVersionID(versionID string) Option {
	return func(o *options) error {
		o.versionID = versionID
		return nil
	}
}

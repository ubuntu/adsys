package ad

func withoutKerberos() func(o *options) error {
	return func(o *options) error {
		o.withoutKerberos = true
		return nil
	}
}

func withGPOListCmd(cmd []string) func(o *options) error {
	return func(o *options) error {
		o.gpoListCmd = cmd
		return nil
	}
}

// WithVersionID specifies a personalized release id
func WithVersionID(versionID string) func(o *options) error {
	return func(o *options) error {
		o.versionID = versionID
		return nil
	}
}

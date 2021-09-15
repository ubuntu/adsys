package adsysservice

// WithMockAuthorizer specifies a personalized authorizer.
func WithMockAuthorizer(auth authorizerer) func(o *options) error {
	return func(o *options) error {
		o.authorizer = auth
		return nil
	}
}

// WithSSSdConf specifies a personalized sssd.conf.
func WithSSSdConf(p string) func(o *options) error {
	return func(o *options) error {
		o.sssdConf = p
		return nil
	}
}

// Option type exported for tests.
type Option = option

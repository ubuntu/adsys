package adsysservice

func withSssdConf(sssdConf string) option {
	return func(o *options) error {
		o.sssdConf = sssdConf
		return nil
	}
}

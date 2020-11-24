package ad

func withRunDir(runDir string) func(o *options) error {
	return func(o *options) error {
		o.runDir = runDir
		return nil
	}
}

func withCacheDir(cacheDir string) func(o *options) error {
	return func(o *options) error {
		o.cacheDir = cacheDir
		return nil
	}
}

func withoutKerberos() func(o *options) error {
	return func(o *options) error {
		o.withoutKerberos = true
		return nil
	}
}

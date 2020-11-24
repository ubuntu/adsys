package ad

import (
	"errors"
)

var (
	WithRunDir      = withRunDir
	WithCacheDir    = withCacheDir
	WithoutKerberos = withoutKerberos
	WithKinitCmd    = withKinitCmd
	WithGPOListCmd  = withGPOListCmd
)

func (ad *AD) GpoCacheDir() string {
	return ad.gpoCacheDir
}
func (ad *AD) Krb5CacheDir() string {
	return ad.krb5CacheDir
}

type MockKinit struct {
	Failing bool
}

func (m MockKinit) CombinedOutput() ([]byte, error) {
	if m.Failing {
		return []byte("My error message on stderr"), errors.New("Exit 1")
	}
	return nil, nil
}

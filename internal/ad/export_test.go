package ad

var (
	WithoutKerberos = withoutKerberos
	WithGPOListCmd  = withGPOListCmd
)

func (ad *AD) GpoCacheDir() string {
	return ad.gpoCacheDir
}
func (ad *AD) PoliciesCacheDir() string {
	return ad.policiesCacheDir
}
func (ad *AD) Krb5CacheDir() string {
	return ad.krb5CacheDir
}

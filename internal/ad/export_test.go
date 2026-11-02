package ad

var (
	WithoutKerberos = withoutKerberos
	WithGPOListCmd  = withGPOListCmd
)

func (ad *AD) SysvolCacheDir() string {
	return ad.sysvolCacheDir
}
func (ad *AD) PoliciesCacheDir() string {
	return ad.policiesCacheDir
}
func (ad *AD) Krb5CacheDir() string {
	return ad.krb5CacheDir
}

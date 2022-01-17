package ad

var (
	WithoutKerberos = withoutKerberos
	WithGPOListCmd  = withGPOListCmd
)

func (ad *AD) GpoCacheDir() string {
	return ad.gpoCacheDir
}
func (ad *AD) GpoRulesCacheDir() string {
	return ad.gpoRulesCacheDir
}
func (ad *AD) Krb5CacheDir() string {
	return ad.krb5CacheDir
}

package proxymanager

// Config is the exported proxy configuration type for users of the proxymanager API.
type Config struct {
	HTTPProxy  string
	HTTPSProxy string
	FTPProxy   string
	SocksProxy string
	NoProxy    string
}

// useGlobalHTTPProxy returns true if only HTTP proxy is set, signaling global
// use of the HTTP proxy.
func (c Config) useGlobalHTTPProxy() bool {
	if c.HTTPProxy != "" && c.HTTPSProxy == "" && c.FTPProxy == "" && c.SocksProxy == "" {
		return true
	}
	return false
}

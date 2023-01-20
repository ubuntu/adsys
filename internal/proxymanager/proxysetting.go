package proxymanager

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/ubuntu/adsys/internal/decorate"
	"github.com/ubuntu/adsys/internal/i18n"
)

const (
	allProxy   = "all"
	noProxy    = "no"
	httpProxy  = "http"
	httpsProxy = "https"
	ftpProxy   = "ftp"
	socksProxy = "socks"
)

// var supportedAptProtocols = []string{httpProxy, httpsProxy, ftpProxy}

type proxySetting struct {
	protocol   string
	escapedURL string // scheme://host:port, including escaped user:password if available, verbatim if no_proxy

	url *url.URL
}

func setConfig(config Config) (proxies []proxySetting, err error) {
	defer decorate.OnError(&err, i18n.G("couldn't set proxy configuration"))

	if config.useGlobalHTTPProxy() {
		config.HTTPSProxy = config.HTTPProxy
		config.FTPProxy = config.HTTPProxy
		config.SocksProxy = config.HTTPProxy

		setting, err := newSetting(allProxy, config.HTTPProxy)
		if err != nil {
			return nil, err
		}
		proxies = append(proxies, *setting)
	}

	if config.HTTPProxy != "" {
		setting, err := newSetting(httpProxy, config.HTTPProxy)
		if err != nil {
			return nil, err
		}
		proxies = append(proxies, *setting)
	}
	if config.HTTPSProxy != "" {
		setting, err := newSetting(httpsProxy, config.HTTPSProxy)
		if err != nil {
			return nil, err
		}
		proxies = append(proxies, *setting)
	}
	if config.FTPProxy != "" {
		setting, err := newSetting(ftpProxy, config.FTPProxy)
		if err != nil {
			return nil, err
		}
		proxies = append(proxies, *setting)
	}
	if config.SocksProxy != "" {
		setting, err := newSetting(socksProxy, config.SocksProxy)
		if err != nil {
			return nil, err
		}
		proxies = append(proxies, *setting)
	}
	if config.NoProxy != "" {
		setting, err := newSetting(noProxy, config.NoProxy)
		if err != nil {
			return nil, err
		}
		proxies = append(proxies, *setting)
	}

	return proxies, nil
}

func newSetting(protocol string, uri string) (p *proxySetting, err error) {
	defer decorate.OnError(&err, i18n.G("couldn't create proxy setting"))

	// noProxy is a special case and we don't need to parse it
	if protocol == noProxy {
		return &proxySetting{protocol: protocol, escapedURL: uri}, nil
	}
	// Ideally we would've handled this after calling url.Parse, by checking the
	// Scheme attribute, but it's not reliable in case we parse an URI like
	// "example.com:8000" and "example.com" is treated as a scheme because of
	// the colon in the URI.
	if !strings.Contains(uri, "://") {
		return nil, fmt.Errorf("missing scheme in proxy URI %q", uri)
	}

	uri = escapeURLUsername(uri)
	parsedURL, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	var host string
	if parsedURL.User != nil {
		host = parsedURL.User.String() + "@"
	}
	host += parsedURL.Host
	escapedURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, host)

	return &proxySetting{
		escapedURL: escapedURL,
		protocol:   protocol,
		url:        parsedURL,
	}, nil
}

func (p proxySetting) envString() string {
	// Return both uppercase and lowercase environment variables for
	// compatibility with different tools
	return fmt.Sprintf(`%s_PROXY=%s
%s_proxy=%s
`,
		strings.ToUpper(p.protocol), p.escapedURL,
		p.protocol, p.escapedURL)
}

// func (p proxySetting) aptString() string {
// 	if !slices.Contains(supportedAptProtocols, p.protocol) {
// 		return ""
// 	}

// 	return "TODO"
// }

func escapeURLUsername(uri string) string {
	// Attempt to unescape the string first, discarding any error
	// At best, this prevents us from escaping the URL multiple times
	// At worst, the URL is not affected (we will treat % signs as part of the
	// credentials and escape them later)
	uri, _ = url.PathUnescape(uri)

	// Regexp to check if the URI contains credentials
	r := regexp.MustCompile(`^\w+://(?:(?P<credentials>.*:?.*)@)[a-zA-Z0-9.-]+(:[0-9]+)?/?$`)
	matchIndex := r.SubexpIndex("credentials")
	matches := r.FindStringSubmatch(uri)
	if len(matches) >= matchIndex {
		creds := matches[matchIndex]
		user, password, found := strings.Cut(creds, ":")
		if found {
			return strings.Replace(uri, creds, url.UserPassword(user, password).String(), 1)
		}
		return strings.Replace(uri, creds, url.PathEscape(user), 1)
	}

	return uri
}

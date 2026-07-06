package certificate

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	krb5pkg "github.com/oiweiwei/go-msrpc/ssp/krb5"
	krbconfig "github.com/oiweiwei/gokrb5.fork/v9/config"
)

func newKerberosClientConfig(server, fallbackRealm string) (*krbconfig.Config, error) {
	krb5Conf := krb5pkg.NewConfig()
	conf := krb5Conf.GetKRB5Config()
	if conf == nil {
		conf = krbconfig.New()
	}
	if err := ensureKDCDiscovery(conf, server, fallbackRealm); err != nil {
		return nil, err
	}
	return conf, nil
}

func newRPCKrb5Config(ccachePath, server, fallbackRealm string) (*krb5pkg.Config, error) {
	krb5Conf := krb5pkg.NewConfig()
	krb5Conf.CCachePath = ccachePath
	krb5Conf.AnyServiceClassSPN = false
	conf := krb5Conf.GetKRB5Config()
	if conf == nil {
		conf = krbconfig.New()
		krb5Conf.KRB5Config = conf
	}
	if err := ensureKDCDiscovery(conf, server, fallbackRealm); err != nil {
		return nil, err
	}
	return krb5Conf, nil
}

func ensureKDCDiscovery(conf *krbconfig.Config, server, fallbackRealm string) error {
	realm := kerberosServiceRealm(conf, server, fallbackRealm)
	if conf == nil || conf.LibDefaults.DNSLookupKDC || realmHasConfiguredKDC(conf, realm) {
		return nil
	}
	configPath := krb5ConfigPath()
	if krb5ConfigExplicitlyDisablesDNSLookupKDC(configPath) {
		return fmt.Errorf("kerberos configuration %s explicitly sets dns_lookup_kdc = false, but no KDC is configured for realm %s; add a kdc entry under [realms] for %s, or enable dns_lookup_kdc and ensure _kerberos SRV records exist for the realm", configPath, displayRealm(realm), displayRealm(realm))
	}
	conf.LibDefaults.DNSLookupKDC = true
	return nil
}

func realmHasConfiguredKDC(conf *krbconfig.Config, realm string) bool {
	if conf == nil {
		return false
	}
	if realm == "" {
		realm = conf.LibDefaults.DefaultRealm
	}
	for _, r := range conf.Realms {
		if r.Realm == realm && len(r.KDC) > 0 {
			return true
		}
	}
	return false
}

func kerberosServiceRealm(conf *krbconfig.Config, server, fallbackRealm string) string {
	if conf == nil {
		return fallbackRealm
	}
	if host := strings.ToLower(tlsServerName(server)); host != "" {
		if realm := conf.ResolveRealm(host); realm != "" {
			return realm
		}
	}
	if fallbackRealm != "" {
		return fallbackRealm
	}
	return conf.LibDefaults.DefaultRealm
}

func krb5ConfigPath() string {
	if path := os.Getenv("KRB5_CONFIG"); path != "" {
		return path
	}
	return krb5pkg.DefaultKRB5ConfPath
}

func krb5ConfigExplicitlyDisablesDNSLookupKDC(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	inLibdefaults := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(stripKrb5ConfigComment(scanner.Text()))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			end := strings.Index(line, "]")
			if end < 0 {
				inLibdefaults = false
				continue
			}
			section := strings.TrimSpace(line[1:end])
			inLibdefaults = strings.EqualFold(section, "libdefaults")
			continue
		}
		if !inLibdefaults {
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "dns_lookup_kdc") {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "false", "no", "n", "0":
			return true
		default:
			return false
		}
	}
	return false
}

func stripKrb5ConfigComment(line string) string {
	if idx := strings.IndexAny(line, "#;"); idx >= 0 {
		return line[:idx]
	}
	return line
}

func displayRealm(realm string) string {
	if realm == "" {
		return "<unknown>"
	}
	return realm
}

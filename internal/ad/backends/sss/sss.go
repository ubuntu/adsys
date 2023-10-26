// Package sss is the sssd backend for fetching AD active configuration and online status.
package sss

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/godbus/dbus/v5"
	"github.com/ubuntu/adsys/internal/ad/backends"
	"github.com/ubuntu/adsys/internal/consts"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/decorate"
	"gopkg.in/ini.v1"
)

// SSS is the backend object with domain and DC information.
type SSS struct {
	domain              string
	domainDbus          dbus.BusObject
	serverFQDN          string
	staticServerFQDN    string
	hostKrb5CCName      string
	defaultDomainSuffix string

	config Config
}

// Config for sss backend.
type Config struct {
	Conf     string `mapstructure:"config"`
	CacheDir string `mapstructure:"cache_dir"`
}

// New returns a sss backend loaded from Config.
func New(ctx context.Context, c Config, bus *dbus.Conn) (s SSS, err error) {
	defer decorate.OnError(&err, i18n.G("can't get domain configuration from %+v"), c)

	log.Debug(ctx, "Loading SSS configuration for AD backend")

	if c.Conf == "" {
		c.Conf = consts.DefaultSSSConf
	}
	if c.CacheDir == "" {
		c.CacheDir = consts.DefaultSSSCacheDir
	}

	cfg, err := ini.Load(c.Conf)
	if err != nil {
		return SSS{}, err
	}
	defaultDomainSuffix := cfg.Section("sssd").Key("default_domain_suffix").String()

	// Take first domain as domain for machine and all users
	sssdDomain := strings.Split(cfg.Section("sssd").Key("domains").String(), ",")[0]
	if sssdDomain == "" {
		return SSS{}, errors.New(i18n.G("failed to find default sssd domain in sssd.conf"))
	}
	domain := cfg.Section(fmt.Sprintf("domain/%s", sssdDomain)).Key("ad_domain").String()
	if domain == "" {
		return SSS{}, fmt.Errorf(i18n.G("could not find AD domain name corresponding to %q"), sssdDomain)
	}

	if defaultDomainSuffix == "" {
		defaultDomainSuffix = domain
	}

	domainDbus := bus.Object(consts.SSSDDbusRegisteredName,
		dbus.ObjectPath(filepath.Join(consts.SSSDDbusBaseObjectPath, domainToObjectPath(domain))))

	// Server FQDN
	staticServerFQDN := cfg.Section(fmt.Sprintf("domain/%s", sssdDomain)).Key("ad_server").String()
	if staticServerFQDN != "" {
		staticServerFQDN = strings.TrimPrefix(staticServerFQDN, "ldap://")
	}

	// local machine sssd krb5 cache
	hostKrb5CCName := filepath.Join(c.CacheDir, "ccache_"+strings.ToUpper(domain))

	return SSS{
		domain:              domain,
		domainDbus:          domainDbus,
		serverFQDN:          staticServerFQDN,
		staticServerFQDN:    staticServerFQDN,
		hostKrb5CCName:      hostKrb5CCName,
		defaultDomainSuffix: defaultDomainSuffix,

		config: c,
	}, nil
}

// Domain returns current server domain.
func (sss SSS) Domain() string {
	return sss.domain
}

// ServerFQDN returns current server FQDN.
// It returns first any static configuration. If nothing is found, it will fetch the active server from sssd.
// If the dynamic lookup worked, but there is still no server FQDN found (for instance, backend
// if offline), the error raised is of type ErrorNoActiveServer.
func (sss SSS) ServerFQDN(ctx context.Context) (serverFQDN string, err error) {
	defer decorate.OnError(&err, i18n.G("error while trying to look up AD server address on SSSD for %q"), sss.domain)

	if sss.staticServerFQDN != "" {
		return sss.staticServerFQDN, nil
	}
	log.Debugf(ctx, "Triggering autodiscovery of AD server triggered because sssd.conf does not provide an ad_server for %q", sss.domain)

	// Try to update from SSSD the current active AD server
	if err := sss.domainDbus.Call(consts.SSSDDbusInterface+".ActiveServer", 0, "AD").Store(&serverFQDN); err != nil {
		return "", err
	}
	if serverFQDN == "" {
		return "", backends.ErrNoActiveServer
	}

	return strings.TrimPrefix(serverFQDN, "ldap://"), nil
}

// HostKrb5CCName returns the absolute path of the machine krb5 ticket.
func (sss SSS) HostKrb5CCName() (string, error) {
	return sss.hostKrb5CCName, nil
}

// DefaultDomainSuffix returns current default domain suffix.
func (sss SSS) DefaultDomainSuffix() string {
	return sss.defaultDomainSuffix
}

// IsOnline refresh and returns if we are online.
func (sss SSS) IsOnline() (bool, error) {
	var online bool
	if err := sss.domainDbus.Call(consts.SSSDDbusInterface+".IsOnline", 0).Store(&online); err != nil {
		return false, fmt.Errorf(i18n.G("failed to retrieve offline state from SSSD: %v"), err)
	}
	return online, nil
}

// Config returns a stringified configuration for SSSD backend.
func (sss SSS) Config() string {
	return fmt.Sprintf(`Current backend is SSSD
Configuration: %s
Cache: %s`, sss.config.Conf, sss.config.CacheDir)
}

// domainToObjectPath converts a potential dbus object path string to valid hexadecimal-based equivalent as encoded
// in sssd.
// The separator in the domain is converted too.
func domainToObjectPath(s string) string {
	var r string
	for _, c := range s {
		if (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') || c == '_' {
			r += string(c)
			continue
		}
		r = fmt.Sprintf("%s_%02x", r, c)
	}
	return r
}

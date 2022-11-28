// Package winbind is the winbind backend for fetching AD active configuration and online status.
package winbind

/*
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include <wbclient.h>

char *get_domain_name() {
  // Get domain name
  wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
  struct wbcInterfaceDetails *info;

  wbc_status = wbcInterfaceDetails(&info);
  if (wbc_status != WBC_ERR_SUCCESS || info->dns_domain == NULL) {
    return NULL;
  }
  return strdup(info->dns_domain);
}

char *get_dc_name(char *domain) {
  // Get DC name from domain name
  wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
  struct wbcDomainControllerInfo *dc_info = NULL;

  wbc_status = wbcLookupDomainController(domain, WBC_LOOKUP_DC_DS_REQUIRED, &dc_info);
  if (wbc_status != WBC_ERR_SUCCESS || dc_info->dc_name == NULL) {
    return NULL;
  }
  return strdup(dc_info->dc_name);
}

bool is_online(char *domain) {
  wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
  struct wbcDomainInfo *info = NULL;

  wbc_status = wbcDomainInfo(domain, &info);
  if (wbc_status != WBC_ERR_SUCCESS) {
    return false;
  }
  return !(info->domain_flags & WBC_DOMINFO_DOMAIN_OFFLINE);
}
*/
// #cgo pkg-config: wbclient
import "C"
import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/ubuntu/adsys/internal/decorate"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
)

// Winbind is the backend object with domain and url information.
type Winbind struct {
	staticServerURL     string
	domain              string
	defaultDomainSuffix string
	hostKrb5CCNAME      string

	config Config
}

// Config for winbind backend
type Config struct {
	ADServer string `mapstructure:"ad_server"` // bypass winbind and use this server
	ADDomain string `mapstructure:"ad_domain"` // bypass domain name detection and use this domain
}

// New returns a winbind backend loaded from Config.
func New(ctx context.Context, c Config) (w Winbind, err error) {
	defer decorate.OnError(&err, i18n.G("can't get domain configuration from %+v"), c)

	log.Debug(ctx, "Loading Winbind configuration for AD backend")

	if c.ADDomain == "" {
		c.ADDomain, err = domainName()
		if err != nil {
			return Winbind{}, err
		}
	}

	// TODO local machine krb5cc
	hostKrb5CCNAME := ""

	return Winbind{
		staticServerURL:     c.ADServer,
		domain:              c.ADDomain,
		defaultDomainSuffix: c.ADDomain,
		hostKrb5CCNAME:      hostKrb5CCNAME,
		config:              c,
	}, nil
}

// Domain returns current server domain.
func (w Winbind) Domain() string {
	return w.domain
}

// HostKrb5CCNAME returns the absolute path of the machine krb5 ticket.
func (w Winbind) HostKrb5CCNAME() string {
	return w.hostKrb5CCNAME
}

// DefaultDomainSuffix returns current default domain suffix.
func (w Winbind) DefaultDomainSuffix() string {
	return w.defaultDomainSuffix
}

// ServerURL returns current server URL.
// It returns first any static configuration. If nothing is found, it will fetch
// the active server from winbind.
func (w Winbind) ServerURL(ctx context.Context) (serverURL string, err error) {
	defer decorate.OnError(&err, i18n.G("error while trying to look up AD server address on winbind"))

	if w.staticServerURL != "" && !strings.HasPrefix(w.staticServerURL, "ldap://") {
		return fmt.Sprintf("ldap://%s", w.staticServerURL), nil
	}

	log.Debugf(ctx, "Triggering autodiscovery of AD server because winbind configuration does not provide an ad_server for %q", w.domain)
	dc, err := dcName(w.domain)
	if err != nil {
		return "", err
	}
	dc = strings.TrimPrefix(dc, `\\`)

	return fmt.Sprintf("ldap://%s", dc), nil
}

// Config returns a stringified configuration for Winbind backend.
func (w Winbind) Config() string {
	return "Current backend is Winbind"
}

// IsOnline refresh and returns if we are online.
func (w Winbind) IsOnline() (bool, error) {
	cDomain := C.CString(w.domain)
	defer C.free(unsafe.Pointer(cDomain))
	return bool(C.is_online(cDomain)), nil
}

func domainName() (string, error) {
	dc := C.get_domain_name()
	if dc == nil {
		return "", errors.New(i18n.G("could not get domain name"))
	}
	defer C.free(unsafe.Pointer(dc))
	return C.GoString(dc), nil
}

func dcName(domain string) (string, error) {
	cDomain := C.CString(domain)
	defer C.free(unsafe.Pointer(cDomain))
	dc := C.get_dc_name(cDomain)
	if dc == nil {
		return "", fmt.Errorf(i18n.G("could not get domain controller name for domain %q"), domain)
	}
	defer C.free(unsafe.Pointer(dc))
	return C.GoString(dc), nil
}

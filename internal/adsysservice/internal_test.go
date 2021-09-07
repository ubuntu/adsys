package adsysservice

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestLoadServerInfo(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		sssdconf            string
		domain              string
		url                 string
		defaultDomainSuffix string

		wantDomain              string
		wantURL                 string
		wantDefaultDomainSuffix string
		wantErr                 bool
	}{
		"return directly url and domain if provided":                        {domain: "MyDomain", url: "MyCustomURL", wantDomain: "MyDomain", wantURL: "MyCustomURL"},
		"return directly url, domain and default domain suffix if provided": {domain: "MyDomain", url: "MyCustomURL", defaultDomainSuffix: "MyDefaultDomainSuffix", wantDomain: "MyDomain", wantURL: "MyCustomURL", wantDefaultDomainSuffix: "MyDefaultDomainSuffix"},

		"return domain directly and url from sssd.conf":                        {domain: "MyDomain", wantDomain: "MyDomain", wantURL: "MyURL"},
		"return url directly and domain from sssd.conf":                        {url: "MyURL", wantDomain: "MyDomain", wantURL: "MyURL"},
		"return url and domain from sssd.conf":                                 {wantDomain: "MyDomain", wantURL: "MyURL"},
		"return default domain suffix from sssd.conf":                          {sssdconf: "default_domain_suffix_sssd.conf", domain: "MyDomain", url: "MyURL", wantDomain: "MyDomain", wantURL: "MyURL", wantDefaultDomainSuffix: "mydomain.biz"},
		"return domain if set directly and no url if no sssd.conf":             {sssdconf: "/unexisting", domain: "MyDomain", wantDomain: "MyDomain", wantURL: "", wantDefaultDomainSuffix: ""},
		"return domain and url without default domain suffix and no sssd.conf": {sssdconf: "/unexisting", domain: "MyDomain", url: "MyURL", wantDomain: "MyDomain", wantURL: "MyURL", wantDefaultDomainSuffix: ""},
		"return domain and default domain suffix without url and no sssd.conf": {sssdconf: "/unexisting", domain: "MyDomain", defaultDomainSuffix: "MyDefaultDomainSuffix", wantDomain: "MyDomain", wantURL: "", wantDefaultDomainSuffix: "MyDefaultDomainSuffix"},

		"return url directly ad_domain from sssd.conf":                  {sssdconf: "addomain_differs_sssd.conf", url: "MyURL", wantDomain: "CustomADDomain", wantURL: "MyURL"},
		"return ad_domain and url from sssd.conf":                       {sssdconf: "addomain_differs_sssd.conf", wantDomain: "CustomADDomain", wantURL: "MyURL"},
		"return ad_domain and url by only providing our domain section": {sssdconf: "no_sssd_section_sssd.conf", domain: "MyDomain", wantDomain: "ADDomain", wantURL: "MyURL"},
		"return provided default domain suffix directly from sssd.conf": {sssdconf: "default_domain_suffix_sssd.conf", domain: "MyDomain", url: "MyURL", wantDomain: "MyDomain", wantURL: "MyURL", wantDefaultDomainSuffix: "mydomain.biz"},
		"skip missing url in sssdconf":                                  {sssdconf: "no_adserver_sssd.conf", domain: "MyDomain", wantDomain: "MyDomain", wantURL: ""},

		// Error cases
		"error on missing domain and no sssdconf":           {url: "MyURL", sssdconf: "/unexisting", wantErr: true},
		"error on missing url/domain and no sssdconf":       {sssdconf: "/unexisting", wantErr: true},
		"error when no sssd section and no domain provided": {sssdconf: "no_sssd_section_sssd.conf", url: "MyURL", wantErr: true},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if tc.sssdconf == "" {
				tc.sssdconf = "default_sssd.conf"
			}
			tc.sssdconf = filepath.Join("testdata", tc.sssdconf)

			gotURL, gotDomain, gotDefaultDomainSuffix, err := loadServerInfo(tc.sssdconf, tc.url, tc.domain, tc.defaultDomainSuffix)
			if tc.wantErr {
				require.NotNil(t, err, "loadServerInfo should return an error")
				return
			}
			require.NoError(t, err, "loadServerInfo shouldn’t return an error")

			assert.Equal(t, tc.wantDomain, gotDomain, "return domain as expected")
			assert.Equal(t, tc.wantURL, gotURL, "return URL as expected")
			assert.Equal(t, tc.wantDefaultDomainSuffix, gotDefaultDomainSuffix, "return DefaultDomainPolicy as expected")
		})
	}
}

func TestMain(m *testing.M) {
	defer testutils.StartLocalSystemBus()()
	m.Run()
}

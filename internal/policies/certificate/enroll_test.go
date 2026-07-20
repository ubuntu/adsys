package certificate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	krbcredentials "github.com/oiweiwei/gokrb5.fork/v9/credentials"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/nametype"
	"github.com/oiweiwei/gokrb5.fork/v9/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRPCCredentialFromCCache(t *testing.T) {
	t.Parallel()

	ccache := &krbcredentials.CCache{
		DefaultPrincipal: krbcredentials.Principal{
			Realm:         "ADSYSTEST.COM",
			PrincipalName: types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "resolute-ad-client$"),
		},
		Credentials: []*krbcredentials.Credential{{}},
	}

	cred, err := rpcCredentialFromCCache(ccache)
	require.NoError(t, err)
	require.NotNil(t, cred)

	assert.Equal(t, "resolute-ad-client$", cred.UserName())
	assert.Equal(t, "ADSYSTEST.COM", cred.DomainName())
	assert.Same(t, ccache, cred.CCache())
}

func TestRPCCredentialFromCCacheRequiresPrincipal(t *testing.T) {
	t.Parallel()

	_, err := rpcCredentialFromCCache(&krbcredentials.CCache{})
	require.Error(t, err)
	assert.ErrorContains(t, err, "missing client principal")
}

func TestRPCCredentialFromCCacheRequiresCredentials(t *testing.T) {
	t.Parallel()

	_, err := rpcCredentialFromCCache(&krbcredentials.CCache{
		DefaultPrincipal: krbcredentials.Principal{
			Realm:         "ADSYSTEST.COM",
			PrincipalName: types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "resolute-ad-client$"),
		},
	})
	require.Error(t, err)
	assert.ErrorContains(t, err, "no credentials in Kerberos credential cache")
}

func TestNewRPCKrb5ConfigEnablesDNSLookupKDCWhenUnsetAndRealmHasNoKDC(t *testing.T) {
	krb5ConfPath := filepath.Join(t.TempDir(), "krb5.conf")
	require.NoError(t, os.WriteFile(krb5ConfPath, []byte(
		"[libdefaults]\n default_realm = ADSYSTEST.COM\n"), 0600))
	t.Setenv("KRB5_CONFIG", krb5ConfPath)

	const ccachePath = "/run/adsys/krb5cc/machine"
	conf, err := newRPCKrb5Config(ccachePath, "ca.adsystest.com", "ADSYSTEST.COM")
	require.NoError(t, err)
	require.NotNil(t, conf)

	assert.Equal(t, ccachePath, conf.CCachePath, "ccache path should be wired into the RPC config")

	krb5Conf := conf.GetKRB5Config()
	require.NotNil(t, krb5Conf, "underlying krb5 config should be populated")
	assert.True(t, krb5Conf.LibDefaults.DNSLookupKDC, "DNS-based KDC discovery must be enabled when the realm has no configured KDC")
	assert.False(t, conf.AnyServiceClassSPN, "RPC must request the exact host service ticket instead of reusing a cached same-host ticket for another service class")
}

func TestNewRPCKrb5ConfigRejectsExplicitDNSLookupKDCFalseWithoutConfiguredKDC(t *testing.T) {
	krb5ConfPath := filepath.Join(t.TempDir(), "krb5.conf")
	require.NoError(t, os.WriteFile(krb5ConfPath, []byte(
		"[libdefaults]\n default_realm = ADSYSTEST.COM\n dns_lookup_kdc = false\n"), 0600))
	t.Setenv("KRB5_CONFIG", krb5ConfPath)

	conf, err := newRPCKrb5Config("/run/adsys/krb5cc/machine", "ca.adsystest.com", "ADSYSTEST.COM")
	require.Error(t, err)
	assert.Nil(t, conf)
	assert.ErrorContains(t, err, "dns_lookup_kdc = false")
	assert.ErrorContains(t, err, "no KDC is configured for realm ADSYSTEST.COM")
	assert.ErrorContains(t, err, "add a kdc entry")
}

func TestNewRPCKrb5ConfigPreservesExplicitDNSLookupKDCFalseWithConfiguredKDC(t *testing.T) {
	krb5ConfPath := filepath.Join(t.TempDir(), "krb5.conf")
	require.NoError(t, os.WriteFile(krb5ConfPath, []byte(`[libdefaults]
 default_realm = ADSYSTEST.COM
 dns_lookup_kdc = false

[realms]
 ADSYSTEST.COM = {
  kdc = dc.adsystest.com
 }
`), 0600))
	t.Setenv("KRB5_CONFIG", krb5ConfPath)

	conf, err := newRPCKrb5Config("/run/adsys/krb5cc/machine", "ca.adsystest.com", "ADSYSTEST.COM")
	require.NoError(t, err)
	require.NotNil(t, conf)

	krb5Conf := conf.GetKRB5Config()
	require.NotNil(t, krb5Conf)
	assert.False(t, krb5Conf.LibDefaults.DNSLookupKDC, "explicit KDC configuration should not be overridden")
}

func TestNewRPCKrb5ConfigUsesServiceRealmInKDCError(t *testing.T) {
	krb5ConfPath := filepath.Join(t.TempDir(), "krb5.conf")
	require.NoError(t, os.WriteFile(krb5ConfPath, []byte(`[libdefaults]
 default_realm = ADSYSTEST.COM
 dns_lookup_kdc = false

[realms]
 ADSYSTEST.COM = {
  kdc = dc.adsystest.com
 }

[domain_realm]
 .ca.example.com = CAREALM.COM
`), 0600))
	t.Setenv("KRB5_CONFIG", krb5ConfPath)

	_, err := newRPCKrb5Config("/run/adsys/krb5cc/machine", "server.ca.example.com", "ADSYSTEST.COM")
	require.Error(t, err)
	assert.ErrorContains(t, err, "realm CAREALM.COM")
}

func TestNewKerberosClientConfigHonorsKRB5Config(t *testing.T) {
	krb5ConfPath := filepath.Join(t.TempDir(), "krb5.conf")
	require.NoError(t, os.WriteFile(krb5ConfPath, []byte(`[libdefaults]
 default_realm = CUSTOM.COM
 dns_lookup_kdc = false

[realms]
 CUSTOM.COM = {
  kdc = dc.custom.com
 }
`), 0600))
	t.Setenv("KRB5_CONFIG", krb5ConfPath)

	conf, err := newKerberosClientConfig("ca.custom.com", "CUSTOM.COM")
	require.NoError(t, err)
	require.NotNil(t, conf)

	assert.Equal(t, "CUSTOM.COM", conf.LibDefaults.DefaultRealm)
	assert.False(t, conf.LibDefaults.DNSLookupKDC)
}

func TestRPCClientErrorExplainsInvalidChecksum(t *testing.T) {
	err := rpcClientError("ca.example.com", "host/ca.example.com", errors.New("bind: bind: invalid checksum"))

	assert.ErrorContains(t, err, "Kerberos RPC bind for SPN host/ca.example.com was rejected with invalid checksum")
	assert.ErrorContains(t, err, "registered on the CA server account")
	assert.ErrorContains(t, err, "not duplicated")
	assert.ErrorContains(t, err, "realm mapping")
}

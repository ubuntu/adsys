package certificate

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"

	icertpassage "github.com/oiweiwei/go-msrpc/msrpc/icpr/icertpassage/v0"
	krbcredentials "github.com/oiweiwei/gokrb5.fork/v9/credentials"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/nametype"
	"github.com/oiweiwei/gokrb5.fork/v9/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRawRequestShapes(t *testing.T) {
	t.Parallel()

	_, csrPEM, err := generateKeyAndCSR("host.example.com", 2048)
	require.NoError(t, err)

	t.Run("submit", func(t *testing.T) {
		t.Parallel()
		requester := &rpcRequester{request: func(_ context.Context, server string, request *icertpassage.CertServerRequestRequest) (*icertpassage.CertServerRequestResponse, error) {
			assert.Equal(t, "ca01.example.com", server)
			assert.Equal(t, uint32(crInPKCS10|crInBinary), request.Flags)
			assert.Equal(t, "Example Issuing CA", request.Authority)
			assert.Zero(t, request.RequestID)
			require.NotNil(t, request.Request)
			require.NotEmpty(t, request.Request.Buffer)
			assert.Equal(t, uint32(len(request.Request.Buffer)), request.Request.Length) //nolint:gosec // Test CSR is tiny.
			_, err := x509.ParseCertificateRequest(request.Request.Buffer)
			require.NoError(t, err)
			require.NotNil(t, request.Attributes)
			assert.Equal(t, uint32(len(request.Attributes.Buffer)), request.Attributes.Length) //nolint:gosec // Test attributes are tiny.
			assert.Equal(t, "CertificateTemplate:Machine", decodeUTF16(request.Attributes.Buffer))
			assert.Equal(t, []byte{0, 0}, request.Attributes.Buffer[len(request.Attributes.Buffer)-2:])
			return &icertpassage.CertServerRequestResponse{
				Disposition: uint32(DispositionPending),
				RequestID:   73,
			}, nil
		}}

		response, err := requester.Submit(context.Background(), SubmitRequest{
			Server: "ca01.example.com", CAName: "Example Issuing CA", Template: "Machine", CSRPEM: csrPEM,
		})
		require.NoError(t, err)
		assert.Equal(t, DispositionPending, response.Disposition)
		assert.Equal(t, uint32(73), response.RequestID)
	})

	t.Run("poll", func(t *testing.T) {
		t.Parallel()
		requester := &rpcRequester{request: func(_ context.Context, server string, request *icertpassage.CertServerRequestRequest) (*icertpassage.CertServerRequestResponse, error) {
			assert.Equal(t, "ca01.example.com", server)
			assert.Zero(t, request.Flags)
			assert.Equal(t, "Example Issuing CA", request.Authority)
			assert.Equal(t, uint32(73), request.RequestID)
			assert.Nil(t, request.Request)
			assert.Nil(t, request.Attributes)
			return &icertpassage.CertServerRequestResponse{
				Disposition: uint32(DispositionPending),
				RequestID:   73,
			}, nil
		}}

		response, err := requester.Poll(context.Background(), PollRequest{
			Server: "ca01.example.com", CAName: "Example Issuing CA", RequestID: 73,
		})
		require.NoError(t, err)
		assert.Equal(t, DispositionPending, response.Disposition)
		assert.Equal(t, uint32(73), response.RequestID)
	})
}

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

	conf, err := newKerberosClientConfig(context.Background(), "ca.custom.com", "CUSTOM.COM")
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

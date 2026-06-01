package certificate

import (
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

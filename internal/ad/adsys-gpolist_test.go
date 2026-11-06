package ad_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestAdsysGPOList(t *testing.T) {
	coverageOn := testutils.PythonCoverageToGoFormat(t, "adsys-gpolist", false)
	adsysGPOListcmd := "./adsys-gpolist"
	if coverageOn {
		adsysGPOListcmd = "adsys-gpolist"
	}

	// Setup samba mock
	p, err := filepath.Abs("../testutils/admock")
	require.NoError(t, err, "Setup: Failed to get current absolute path for mock")
	t.Setenv("PYTHONPATH", p)
	t.Setenv("ADSYS_TESTS_MOCK_SMBDOMAIN", "gpoonly.com")

	tests := map[string]struct {
		url                  string
		accountName          string
		objectClass          string
		krb5ccNameState      string
		transport            string
		createTLSCA          bool
		tlsCRLFile           bool
		createTLSCRL         bool
		relativeTLSCA        bool
		relativeTLSCRL       bool
		nonPEMTLSCA          bool
		nonPEMTLSCRL         bool
		expectedTransport    string
		startTLSUnsupported  bool
		failLDAPParameter    string
		simulatedSamDBStatus string
		simulatedGCStatus    string

		wantErr         bool
		wantReturnCode  int
		wantErrContains string
	}{
		"Return one gpo": {
			accountName: "UserAtRoot@GPOONLY.COM",
		},

		"Return hierarchy": {
			accountName: "RnDUser@GPOONLY.COM",
		},
		"Multiple GPOs in same OU": {
			accountName: "RnDUserDep1@GPOONLY.COM",
		},

		"Machine GPOs": {
			accountName: "hostname1",
			objectClass: "computer",
		},

		"Disabled GPOs": {
			accountName: "RnDUserDep3@GPOONLY.COM",
		},

		// Empty GPOs return an empty bytes field or a space depending on the client
		// so we need to test both.
		"No GPO on OU - bytes": {
			accountName: "UserNoGPO@GPOONLY.COM",
		},

		"No GPO on OU - string": {
			accountName: "UserNoGPOString@GPOONLY.COM",
		},

		// Filtering cases
		"Filter user only GPOs": {
			accountName: "hostname2",
			objectClass: "computer",
		},
		"Filter machine only GPOs": {
			accountName: "RnDUserDep7@GPOONLY.COM",
		},

		// Forced GPOs and inheritance handling
		"Forced GPO are first by reverse order": {
			accountName: "RndUserSubDep2ForcedPolicy@GPOONLY.COM",
		},
		"Block inheritance": {
			accountName: "RnDUserWithBlockedInheritance@GPOONLY.COM",
		},
		"Forced GPO and blocked inheritance": {
			accountName: "RnDUserWithBlockedInheritanceAndForcedPolicies@GPOONLY.COM",
		},

		// Access cases
		"Security descriptor missing ignores GPO": { // AD is doing that for windows client
			accountName: "RnDUserDep4@GPOONLY.COM",
		},
		// An access check that errors out (rather than cleanly denying) still means
		// the GPO is inaccessible, so AD skips it -- it must not abort the refresh.
		"Security descriptor access failure ignores GPO": {
			accountName: "RnDUserDep5@GPOONLY.COM",
		},
		"Security descriptor access denied ignores GPO": {
			accountName: "RnDUserDep6@GPOONLY.COM",
		},
		"Security descriptor accepted is for another user": {
			accountName: "RnDUserDep8@GPOONLY.COM",
		},

		// A universal group defined in the parent domain of the forest is only
		// visible through the Global Catalog tokenGroups expansion. This is the
		// multi-domain case that used to crash the script (issue #1358).
		"Cross-domain universal group membership applies its GPO": {
			accountName: "ChildUserWithParentGroup@GPOONLY.COM",
		},

		// A GPO scoped to a domain-local group applies only because the domain
		// controller tokenGroups (which include domain-local membership) are
		// unioned with the Global Catalog's. The Global Catalog alone omits
		// domain-local groups, which used to deny the GPO and abort the refresh.
		"Domain-local group membership applies its GPO": {
			accountName: "UserWithDomainLocalGroup@GPOONLY.COM",
		},

		// The object's token grants no read on the GPO: AD skips it, so the
		// script must skip it too instead of failing the whole refresh.
		"Read access denied skips GPO": {
			accountName: "UserReadDenied@GPOONLY.COM",
		},

		// user_session() raises in a multi-domain forest (the LDAP referral
		// crash). The script must fall back to assembling the token from
		// tokenGroups and still resolve the GPO, instead of aborting.
		"Falls back to tokenGroups when user_session crashes": {
			accountName: "UserSessionReferralFallback@GPOONLY.COM",
		},

		// The fallback must add the primary group (Domain Computers) that
		// tokenGroups omits, otherwise a GPO scoped to it -- as computer GPOs
		// commonly are -- would be wrongly skipped for child-domain objects.
		"Fallback adds the primary group to the token": {
			accountName: "UserPrimaryGroupFallback@GPOONLY.COM",
		},

		// Read and apply are scoped to World, granted only by the default
		// well-known SIDs injected into the token. Regresses if build_token
		// stops adding them (access check would deny every GPO read).
		"Default token SIDs grant access to Everyone-scoped GPO": {
			accountName: "UserEveryone@GPOONLY.COM",
		},

		// Wide read access must not imply application: World may read the GPO
		// but is denied the apply right, so it must be filtered out.
		"Everyone read access does not imply GPO application": {
			accountName: "UserEveryoneDenied@GPOONLY.COM",
		},

		"No gPOptions fallbacks to 0": {
			accountName: "UserNogPOptions@GPOONLY.COM",
		},

		"KRB5CCNAME without FILE: is supported by the samba bindings": {
			accountName:     "UserAtRoot@GPOONLY.COM",
			krb5ccNameState: "invalidenvformat",
		},

		// Special object name cases
		"No @ in user name returns the same thing": {
			accountName: "UserAtRoot",
		},
		"Computers truncated at 15 characters": {
			accountName: "hostnameWithTruncatedLongName",
			objectClass: "computer",
		},
		"Long computer name, not truncated": {
			accountName: "hostnameWithLongName",
			objectClass: "computer",
		},
		"LDAPS connects to the DC and Global Catalog over TLS": {
			accountName:       "UserSessionReferralFallback@GPOONLY.COM",
			transport:         "ldaps",
			createTLSCA:       true,
			expectedTransport: "ldaps",
		},
		"LDAPS failure does not fall back to LDAP": {
			url:               "NT_STATUS_CONNECTION_REFUSED",
			accountName:       "UserAtRoot@GPOONLY.COM",
			transport:         "ldaps",
			createTLSCA:       true,
			expectedTransport: "ldaps",
			wantReturnCode:    2,
			wantErr:           true,
			wantErrContains:   "NT_STATUS_CONNECTION_REFUSED",
		},
		"Strict TLS mode configures the CRL": {
			accountName:       "UserAtRoot@GPOONLY.COM",
			transport:         "ldaps",
			createTLSCA:       true,
			tlsCRLFile:        true,
			createTLSCRL:      true,
			expectedTransport: "ldaps",
		},
		"StartTLS configures Samba TLS wrapping": {
			accountName:       "UserSessionReferralFallback@GPOONLY.COM",
			transport:         "starttls",
			createTLSCA:       true,
			expectedTransport: "starttls",
		},

		// Error cases
		"Error on no network": {
			url:            "NT_STATUS_NETWORK_UNREACHABLE",
			accountName:    "UserAtRoot@GPOONLY.COM",
			wantReturnCode: 2,
			wantErr:        true,
		},
		"Error on unreachable ldap host": {
			url:            "NT_STATUS_HOST_UNREACHABLE",
			accountName:    "UserAtRoot@GPOONLY.COM",
			wantReturnCode: 2,
			wantErr:        true,
		},
		"Error on ldap connection refused": {
			url:            "NT_STATUS_CONNECTION_REFUSED",
			accountName:    "UserAtRoot@GPOONLY.COM",
			wantReturnCode: 2,
			wantErr:        true,
		},
		"Error on machine with no ldap": {
			url:            "NT_STATUS_OBJECT_NAME_NOT_FOUND",
			accountName:    "UserAtRoot@GPOONLY.COM",
			wantReturnCode: 2,
			wantErr:        true,
		},
		"Unknown session-open status is a connection failure": {
			url:            "NT_STATUS_INVALID_PARAMETER",
			accountName:    "UserAtRoot@GPOONLY.COM",
			wantReturnCode: 2,
			wantErr:        true,
		},
		"Unsupported transport is a configuration error": {
			accountName:     "UserAtRoot@GPOONLY.COM",
			transport:       "unknown",
			wantReturnCode:  4,
			wantErr:         true,
			wantErrContains: "Unsupported LDAP transport",
		},
		"Missing CA bundle is a configuration error": {
			accountName:       "UserAtRoot@GPOONLY.COM",
			transport:         "ldaps",
			expectedTransport: "ldaps",
			wantReturnCode:    4,
			wantErr:           true,
			wantErrContains:   "TLS CA bundle",
		},
		"Missing CRL file is a configuration error": {
			accountName:       "UserAtRoot@GPOONLY.COM",
			transport:         "ldaps",
			createTLSCA:       true,
			tlsCRLFile:        true,
			expectedTransport: "ldaps",
			wantReturnCode:    4,
			wantErr:           true,
			wantErrContains:   "TLS CRL file",
		},
		"Relative CA bundle path is a configuration error": {
			accountName:       "UserAtRoot@GPOONLY.COM",
			transport:         "ldaps",
			relativeTLSCA:     true,
			expectedTransport: "ldaps",
			wantReturnCode:    4,
			wantErr:           true,
			wantErrContains:   "must be absolute",
		},
		"Relative CRL path is a configuration error": {
			accountName:       "UserAtRoot@GPOONLY.COM",
			transport:         "ldaps",
			createTLSCA:       true,
			tlsCRLFile:        true,
			relativeTLSCRL:    true,
			expectedTransport: "ldaps",
			wantReturnCode:    4,
			wantErr:           true,
			wantErrContains:   "must be absolute",
		},
		"Non-PEM CA bundle is a configuration error": {
			accountName:       "UserAtRoot@GPOONLY.COM",
			transport:         "ldaps",
			createTLSCA:       true,
			nonPEMTLSCA:       true,
			expectedTransport: "ldaps",
			wantReturnCode:    4,
			wantErr:           true,
			wantErrContains:   "must be PEM encoded",
		},
		"Non-PEM CRL is a configuration error": {
			accountName:       "UserAtRoot@GPOONLY.COM",
			transport:         "ldaps",
			createTLSCA:       true,
			tlsCRLFile:        true,
			createTLSCRL:      true,
			nonPEMTLSCRL:      true,
			expectedTransport: "ldaps",
			wantReturnCode:    4,
			wantErr:           true,
			wantErrContains:   "must be PEM encoded",
		},
		"StartTLS on unsupported Samba is a configuration error": {
			accountName:         "UserAtRoot@GPOONLY.COM",
			transport:           "starttls",
			createTLSCA:         true,
			expectedTransport:   "starttls",
			startTLSUnsupported: true,
			wantReturnCode:      4,
			wantErr:             true,
			wantErrContains:     "requires Samba 4.21 or later",
		},
		"Invalid TLS parameter setup is a configuration error": {
			accountName:       "UserAtRoot@GPOONLY.COM",
			transport:         "ldaps",
			createTLSCA:       true,
			expectedTransport: "ldaps",
			failLDAPParameter: "tls cafile",
			wantReturnCode:    4,
			wantErr:           true,
			wantErrContains:   "could not configure Samba LDAP TLS option",
		},
		"TLS parameter mix failure is a configuration error": {
			accountName:          "UserAtRoot@GPOONLY.COM",
			transport:            "ldaps",
			createTLSCA:          true,
			expectedTransport:    "ldaps",
			simulatedSamDBStatus: "NT_STATUS_INVALID_PARAMETER_MIX",
			wantReturnCode:       4,
			wantErr:              true,
			wantErrContains:      "NT_STATUS_INVALID_PARAMETER_MIX",
		},
		"TLS trust file access status is a configuration error": {
			accountName:          "UserAtRoot@GPOONLY.COM",
			transport:            "ldaps",
			createTLSCA:          true,
			expectedTransport:    "ldaps",
			simulatedSamDBStatus: "NT_STATUS_CANT_ACCESS_DOMAIN_INFO",
			wantReturnCode:       4,
			wantErr:              true,
			wantErrContains:      "NT_STATUS_CANT_ACCESS_DOMAIN_INFO",
		},
		"TLS verification failure is a connection error": {
			accountName:          "UserAtRoot@GPOONLY.COM",
			transport:            "ldaps",
			createTLSCA:          true,
			expectedTransport:    "ldaps",
			simulatedSamDBStatus: "TLS certificate verification failed",
			wantReturnCode:       2,
			wantErr:              true,
			wantErrContains:      "TLS certificate verification failed",
		},
		"TLS configuration failure on optional Global Catalog is fatal": {
			accountName:       "UserSessionReferralFallback@GPOONLY.COM",
			transport:         "ldaps",
			createTLSCA:       true,
			expectedTransport: "ldaps",
			simulatedGCStatus: "NT_STATUS_INVALID_PARAMETER_MIX",
			wantReturnCode:    4,
			wantErr:           true,
			wantErrContains:   "NT_STATUS_INVALID_PARAMETER_MIX",
		},

		"Error on non existent account": {
			accountName:    "nonexistent@GPOONLY.COM",
			wantReturnCode: 1,
			wantErr:        true,
		},
		"Error on account lookup transport failure": {
			accountName:    "connectionDropDuringAccountLookup@GPOONLY.COM",
			wantReturnCode: 2,
			wantErr:        true,
		},
		"Error on user requested but found machine": {
			accountName:    "hostname1",
			objectClass:    "user",
			wantReturnCode: 1,
			wantErr:        true,
		},
		"Error on computer requested but found user": {
			accountName:    "UserAtRoot@GPOONLY.COM",
			objectClass:    "computer",
			wantReturnCode: 1,
			wantErr:        true,
		},
		"Error invalid GPO link": {
			accountName:    "UserInvalidLink@GPOONLY.COM",
			wantReturnCode: 3,
			wantErr:        true,
		},
		"Error on post-connect GPO query transport failure": {
			accountName:    "UserTransportErrorDuringGPOQuery@GPOONLY.COM",
			wantReturnCode: 2,
			wantErr:        true,
		},

		"Error on KRB5CCNAME unset": {
			accountName:     "UserAtRoot@GPOONLY.COM",
			krb5ccNameState: "unset",
			wantReturnCode:  2,
			wantErr:         true,
		},
		"Error on invalid ticket": {
			accountName:     "UserAtRoot@GPOONLY.COM",
			krb5ccNameState: "invalid",
			wantReturnCode:  2,
			wantErr:         true,
		},
		"Error on dangling ticket symlink": {
			accountName:     "UserAtRoot@GPOONLY.COM",
			krb5ccNameState: "dangling",
			wantReturnCode:  2,
			wantErr:         true,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if tc.objectClass == "" {
				tc.objectClass = "user"
			}
			if tc.url == "" {
				tc.url = "adcontroller.example.com"
			}
			expectedTransport := tc.expectedTransport
			if expectedTransport == "" {
				expectedTransport = "ldap"
			}
			t.Setenv("ADSYS_TESTS_EXPECT_LDAP_TRANSPORT", expectedTransport)
			t.Setenv("ADSYS_TESTS_STARTTLS_SUPPORTED", map[bool]string{true: "0", false: "1"}[tc.startTLSUnsupported])
			t.Setenv("ADSYS_TESTS_FAIL_LDAP_PARAMETER", tc.failLDAPParameter)
			t.Setenv("ADSYS_TESTS_SAMDB_STATUS", tc.simulatedSamDBStatus)
			t.Setenv("ADSYS_TESTS_GC_STATUS", tc.simulatedGCStatus)

			// Ticket creation for mock
			if tc.krb5ccNameState == "unset" {
				t.Setenv("KRB5CCNAME", "")
			} else {
				krb5dir, tempErr := filepath.Abs(t.TempDir())
				require.NoError(t, tempErr, "Setup: could not resolve the temporary Kerberos directory")
				krb5file := filepath.Join(krb5dir, "krb5file")
				krb5symlink := filepath.Join(krb5dir, "krb5symlink")
				content := "Some data for the mock"
				if tc.krb5ccNameState == "invalid" {
					content = "Some invalid ticket content for the mock"
				}
				if tc.krb5ccNameState != "dangling" {
					err = os.WriteFile(krb5file, []byte(content), 0600)
					require.NoError(t, err, "Setup: could not set create krb5file")
				}

				err = os.Symlink(krb5file, krb5symlink)
				require.NoError(t, err, "Setup: could not set krb5 file adsys symlink")

				krb5ccname := fmt.Sprintf("FILE:%s", krb5symlink)
				if tc.krb5ccNameState == "invalidenvformat" {
					krb5ccname = krb5symlink
				}

				t.Setenv("KRB5CCNAME", krb5ccname)
			}

			var tlsCAPath, tlsCRLPath string
			if tc.transport != "" {
				tlsDir := t.TempDir()
				tlsCAPath = filepath.Join(tlsDir, "ca.pem")
				if tc.relativeTLSCA {
					tlsCAPath = "ad-ca.pem"
				}
				if tc.createTLSCA && !tc.relativeTLSCA {
					ca := []byte("-----BEGIN CERTIFICATE-----\nmock CA\n-----END CERTIFICATE-----\n")
					if tc.nonPEMTLSCA {
						ca = []byte("not a PEM CA bundle")
					}
					err = os.WriteFile(tlsCAPath, ca, 0600)
					require.NoError(t, err, "Setup: could not create mock TLS CA file")
				}
				if tc.tlsCRLFile {
					tlsCRLPath = filepath.Join(tlsDir, "crl.pem")
					if tc.relativeTLSCRL {
						tlsCRLPath = "ad-crl.pem"
					}
					if tc.createTLSCRL && !tc.relativeTLSCRL {
						crl := []byte("-----BEGIN X509 CRL-----\nmock CRL\n-----END X509 CRL-----\n")
						if tc.nonPEMTLSCRL {
							crl = []byte("DER CRL")
						}
						err = os.WriteFile(tlsCRLPath, crl, 0600)
						require.NoError(t, err, "Setup: could not create mock TLS CRL file")
					}
				}
			}

			cmdArgs := []string{"--objectclass", tc.objectClass, tc.url, tc.accountName}
			if tc.transport != "" {
				cmdArgs = append(cmdArgs, "--transport", tc.transport, "--tls-cafile", tlsCAPath)
				if tc.tlsCRLFile {
					cmdArgs = append(cmdArgs, "--tls-crlfile", tlsCRLPath)
				}
			}
			// #nosec G204: we control the command line name and only change it for tests
			cmd := exec.Command(adsysGPOListcmd, cmdArgs...)
			got, err := cmd.CombinedOutput()
			if tc.wantErr {
				require.Error(t, err, "adsys-gpostlist should have failed but didn’t")
				assert.Equal(t, tc.wantReturnCode, cmd.ProcessState.ExitCode(), "adsys-gpolist returns expected exit code")
				if tc.wantErrContains != "" {
					assert.Contains(t, string(got), tc.wantErrContains, "adsys-gpolist reports the expected diagnostic")
				}
				return
			}
			require.NoErrorf(t, err, "adsys-gpostlist should exit successfully: %v", string(got))
			assert.Equal(t, tc.wantReturnCode, cmd.ProcessState.ExitCode(), "adsys-gpostlist returns expected exit code")

			want := testutils.LoadWithUpdateFromGolden(t, string(got))
			require.Equal(t, want, string(got), "adsys-gpolist expected output")
		})
	}
}

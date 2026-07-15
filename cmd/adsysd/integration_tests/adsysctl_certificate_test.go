package adsys_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertList(t *testing.T) {
	tests := map[string]struct {
		enrollment       string
		enrolled         bool
		daemonNotStarted bool
		jsonFormat       bool

		wantErr      bool
		wantInOutput string
	}{
		"List with no enrolled certificates":   {enrollment: "ldap", wantInOutput: "No certificates are enrolled"},
		"List an enrolled certificate":         {enrollment: "ldap", enrolled: true, wantInOutput: "healthy"},
		"List an enrolled certificate as json": {enrollment: "ldap", enrolled: true, jsonFormat: true, wantInOutput: "\"health\": \"healthy\""},

		// The cepces method is managed by certmonger/getcert, not adsys.
		"List errors on cepces method": {enrollment: "cepces", wantErr: true},

		// Error cases
		"Error on daemon not responding": {enrollment: "ldap", daemonNotStarted: true, wantErr: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			dbusAnswer(t, "polkit_yes")

			adsysDir := t.TempDir()
			conf := createConf(t, confWithAdsysDir(adsysDir), confWithCertEnrollment(tc.enrollment))
			if !tc.daemonNotStarted {
				defer runDaemon(t, conf)()
			}

			if tc.enrolled {
				writeEnrolledState(t, adsysDir, time.Now().Add(365*24*time.Hour))
			}

			args := []string{"certificate", "list"}
			if tc.jsonFormat {
				args = append(args, "--format", "json")
			}
			out, err := runClient(t, conf, args...)
			if tc.wantErr {
				require.Error(t, err, "client should exit with an error")
				return
			}
			require.NoError(t, err, "client should exit with no error")
			assert.Contains(t, out, tc.wantInOutput, "output should contain expected content")
		})
	}
}

func TestCertStatus(t *testing.T) {
	tests := map[string]struct {
		enrollment string
		enrolled   bool
		expired    bool
		nickname   string

		wantErr      bool
		wantInOutput string
	}{
		"Status of a healthy certificate": {enrollment: "ldap", enrolled: true, wantInOutput: "healthy"},
		"Status by nickname":              {enrollment: "ldap", enrolled: true, nickname: "Example-CA.Machine", wantInOutput: "healthy"},

		// A non-healthy certificate makes the command exit with an error (non-zero code).
		"Status of an expired certificate errors":    {enrollment: "ldap", enrolled: true, expired: true, wantErr: true},
		"Status of unknown nickname errors":          {enrollment: "ldap", enrolled: true, nickname: "does-not-exist", wantErr: true},
		"Status with no enrolled certificate errors": {enrollment: "ldap", wantErr: true},
		"Status errors on cepces method":             {enrollment: "cepces", wantErr: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			dbusAnswer(t, "polkit_yes")

			adsysDir := t.TempDir()
			conf := createConf(t, confWithAdsysDir(adsysDir), confWithCertEnrollment(tc.enrollment))
			defer runDaemon(t, conf)()

			if tc.enrolled {
				notAfter := time.Now().Add(365 * 24 * time.Hour)
				if tc.expired {
					notAfter = time.Now().Add(-24 * time.Hour)
				}
				writeEnrolledState(t, adsysDir, notAfter)
			}

			args := []string{"certificate", "status"}
			if tc.nickname != "" {
				args = append(args, tc.nickname)
			}
			out, err := runClient(t, conf, args...)
			if tc.wantErr {
				require.Error(t, err, "client should exit with an error")
				return
			}
			require.NoError(t, err, "client should exit with no error")
			assert.Contains(t, out, tc.wantInOutput, "output should contain expected content")
		})
	}
}

func TestCertValidationErrors(t *testing.T) {
	tests := map[string]struct {
		args []string
	}{
		"Renew without nickname or all":  {args: []string{"certificate", "renew"}},
		"Renew with nickname and all":    {args: []string{"certificate", "renew", "foo", "--all"}},
		"Remove without force":           {args: []string{"certificate", "remove", "foo"}},
		"Remove without nickname or all": {args: []string{"certificate", "remove", "--force"}},
		"List with unknown format":       {args: []string{"certificate", "list", "--format", "bogus"}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			dbusAnswer(t, "polkit_yes")

			conf := createConf(t, confWithCertEnrollment("ldap"))
			defer runDaemon(t, conf)()

			_, err := runClient(t, conf, tc.args...)
			require.Error(t, err, "client should reject invalid arguments")
		})
	}
}

func TestCertRenewNotAuthorized(t *testing.T) {
	dbusAnswer(t, "polkit_no")

	conf := createConf(t, confWithCertEnrollment("ldap"))
	defer runDaemon(t, conf)()

	_, err := runClient(t, conf, "certificate", "renew", "--all")
	require.Error(t, err, "renew is a privileged action and should be denied")
}

func TestCertVerify(t *testing.T) {
	tests := map[string]struct {
		enrolled bool
		expired  bool

		wantErr      bool
		wantInOutput string
	}{
		// The enrolled leaf is signed by the CA whose root is in the trust
		// state, so an offline verification passes on every axis.
		"Verify a valid certificate passes": {enrolled: true, wantInOutput: "PASS"},

		// An expired certificate fails validity, so the command exits with an error.
		"Verify an expired certificate fails": {enrolled: true, expired: true, wantErr: true},

		"Verify with no enrolled certificate errors": {wantErr: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			dbusAnswer(t, "polkit_yes")

			adsysDir := t.TempDir()
			conf := createConf(t, confWithAdsysDir(adsysDir), confWithCertEnrollment("ldap"))
			defer runDaemon(t, conf)()

			if tc.enrolled {
				notAfter := time.Now().Add(365 * 24 * time.Hour)
				if tc.expired {
					notAfter = time.Now().Add(-24 * time.Hour)
				}
				writeEnrolledState(t, adsysDir, notAfter)
			}

			out, err := runClient(t, conf, "certificate", "verify")
			if tc.wantErr {
				require.Error(t, err, "client should exit with an error")
				return
			}
			require.NoError(t, err, "client should exit with no error")
			assert.Contains(t, out, tc.wantInOutput, "output should contain expected content")
		})
	}
}

// writeEnrolledState lays down an on-disk enrollment state (CA, leaf certificate,
// private key and state JSON) for the current machine so that certificate
// commands operate on real data. notAfter controls the leaf certificate expiry.
func writeEnrolledState(t *testing.T, adsysDir string, notAfter time.Time) {
	t.Helper()

	host, err := os.Hostname()
	require.NoError(t, err, "Setup: should retrieve hostname")
	objectName, _, _ := strings.Cut(host, ".")
	domain := "example.com"

	stateDir := filepath.Join(adsysDir, "lib")
	globalTrustDir := filepath.Join(adsysDir, "share", "ca-certificates")
	certsDir := filepath.Join(stateDir, "certs")
	privDir := filepath.Join(stateDir, "private", "certs")
	require.NoError(t, os.MkdirAll(certsDir, 0750), "Setup: create certs dir")
	require.NoError(t, os.MkdirAll(privDir, 0700), "Setup: create private certs dir")
	require.NoError(t, os.MkdirAll(globalTrustDir, 0750), "Setup: create global trust dir")

	caName := "Example-CA"
	template := "Machine"
	nickname := caName + "." + template

	// Self-signed CA.
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Setup: generate CA key")
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: caName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err, "Setup: create CA certificate")
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err, "Setup: parse CA certificate")
	rootPath := filepath.Join(certsDir, caName+"_0.crt")
	writePEMFile(t, rootPath, "CERTIFICATE", caDER)
	symlink := filepath.Join(globalTrustDir, caName+"_0.crt")
	require.NoError(t, os.Symlink(rootPath, symlink), "Setup: symlink root CA")

	// Leaf certificate signed by the CA.
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Setup: generate leaf key")
	cn := objectName + "." + domain
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{cn},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err, "Setup: create leaf certificate")
	certPath := filepath.Join(certsDir, nickname+".crt")
	keyPath := filepath.Join(privDir, nickname+".key")
	writePEMFile(t, certPath, "CERTIFICATE", leafDER)
	leafKeyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	require.NoError(t, err, "Setup: marshal leaf key")
	writePEMFile(t, keyPath, "PRIVATE KEY", leafKeyDER)

	state := map[string]any{
		"object_name": objectName,
		"domain":      domain,
		"updated_at":  time.Now().Format(time.RFC3339),
		"cas": []map[string]any{{
			"name":       caName,
			"hostname":   "ca." + domain,
			"root_certs": []string{rootPath},
			"symlinks":   []string{symlink},
			"templates": []map[string]any{{
				"nickname":  nickname,
				"template":  template,
				"key_file":  keyPath,
				"cert_file": certPath,
			}},
		}},
	}
	data, err := json.MarshalIndent(state, "", "  ")
	require.NoError(t, err, "Setup: marshal state")
	require.NoError(t, os.WriteFile(filepath.Join(certsDir, "state_"+objectName+".json"), data, 0600), "Setup: write state file")
}

func writePEMFile(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	require.NoError(t, os.WriteFile(path, data, 0600), "Setup: write PEM file %s", path)
}

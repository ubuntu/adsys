package client

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys"
)

func TestExitCodeForHealth(t *testing.T) {
	tests := map[string]struct {
		health adsys.CertHealth
		want   int
	}{
		"Healthy is 0":             {adsys.CertHealth_CERT_HEALTH_HEALTHY, 0},
		"Missing is 2":             {adsys.CertHealth_CERT_HEALTH_MISSING, 2},
		"Expired is 3":             {adsys.CertHealth_CERT_HEALTH_EXPIRED, 3},
		"Due for renewal is 4":     {adsys.CertHealth_CERT_HEALTH_DUE_RENEWAL, 4},
		"Key mismatch is 5":        {adsys.CertHealth_CERT_HEALTH_KEY_MISMATCH, 5},
		"Unparseable is 5":         {adsys.CertHealth_CERT_HEALTH_UNPARSEABLE, 5},
		"Not yet valid is 6":       {adsys.CertHealth_CERT_HEALTH_NOT_YET_VALID, 6},
		"Unspecified is generic 1": {adsys.CertHealth_CERT_HEALTH_UNSPECIFIED, 1},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, exitCodeForHealth(tc.health), "unexpected exit code for health")
		})
	}
}

func TestHealthString(t *testing.T) {
	assert.Equal(t, "healthy", healthString(adsys.CertHealth_CERT_HEALTH_HEALTHY))
	assert.Equal(t, "due_renewal", healthString(adsys.CertHealth_CERT_HEALTH_DUE_RENEWAL))
	assert.Equal(t, "key_mismatch", healthString(adsys.CertHealth_CERT_HEALTH_KEY_MISMATCH))
	assert.Equal(t, "not_yet_valid", healthString(adsys.CertHealth_CERT_HEALTH_NOT_YET_VALID))
	assert.Equal(t, "unknown", healthString(adsys.CertHealth(99)), "out-of-range health should be unknown")
}

func TestRenderVerifyText(t *testing.T) {
	clean := &adsys.CertVerifyResult{
		Nickname: "TestCA.Machine", ChainOk: true, ValidityOk: true, KeyMatchOk: true,
	}
	checked := &adsys.CertVerifyResult{
		Nickname: "TestCA.Machine", ChainOk: true, ValidityOk: true, KeyMatchOk: true,
		RevocationChecked: true,
	}
	revoked := &adsys.CertVerifyResult{
		Nickname: "TestCA.Machine", ChainOk: true, ValidityOk: true, KeyMatchOk: true,
		RevocationChecked: true, Revoked: true,
	}
	broken := &adsys.CertVerifyResult{Nickname: "TestCA.Machine", ValidityOk: true, KeyMatchOk: true}

	tests := map[string]struct {
		result *adsys.CertVerifyResult
		online bool

		want       bool
		wantOutput string
	}{
		"Offline verification passes without a revocation check": {
			result: clean, want: true, wantOutput: "PASS",
		},
		"Online verification passes when the revocation check completed": {
			result: checked, want: true, wantOutput: "PASS",
		},
		"Online verification is indeterminate without a revocation check": {
			result: clean, online: true, wantOutput: "UNKNOWN",
		},
		"Revoked certificate fails": {
			result: revoked, online: true, wantOutput: "FAIL",
		},
		"Broken chain fails": {
			result: broken, wantOutput: "FAIL",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			out := captureStdout(t, func() bool { return renderVerifyText(tc.result, tc.online) })
			assert.Equal(t, tc.want, out.ok, "unexpected verification outcome")
			assert.Contains(t, out.text, tc.wantOutput, "unexpected reported result")
		})
	}
}

type verifyOutput struct {
	ok   bool
	text string
}

// captureStdout runs render and returns its result along with what it printed.
func captureStdout(t *testing.T, render func() bool) verifyOutput {
	t.Helper()

	r, w, err := os.Pipe()
	require.NoError(t, err, "Setup: can not create pipe")
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	ok := render()
	require.NoError(t, w.Close(), "Teardown: can not close pipe")

	var b bytes.Buffer
	_, err = io.Copy(&b, r)
	require.NoError(t, err, "Teardown: can not read captured output")
	return verifyOutput{ok: ok, text: b.String()}
}

func TestExitError(t *testing.T) {
	e := &exitError{code: 4, msg: ""}
	assert.Equal(t, 4, e.ExitCode(), "ExitCode should return the code")
	assert.Empty(t, e.Error(), "empty message should not be logged")
}

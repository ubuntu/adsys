package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
	assert.Equal(t, "unknown", healthString(adsys.CertHealth(99)), "out-of-range health should be unknown")
}

func TestExitError(t *testing.T) {
	e := &exitError{code: 4, msg: ""}
	assert.Equal(t, 4, e.ExitCode(), "ExitCode should return the code")
	assert.Empty(t, e.Error(), "empty message should not be logged")
}

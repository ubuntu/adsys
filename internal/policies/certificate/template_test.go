package certificate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMachineTemplateEligibilityGates(t *testing.T) {
	t.Parallel()

	base := templateAttrs{
		Name:                   "Machine",
		MinKeySize:             2048,
		Present:                true,
		Flags:                  templateFlagMachine,
		SchemaVersion:          2,
		SchemaVersionPresent:   true,
		EnrollmentFlags:        enrollmentFlagAutoEnroll,
		EnrollmentFlagsPresent: true,
		SecurityDescriptor:     aclNullDACL(),
	}
	v1 := base
	v1.SchemaVersion = 0
	v1.SchemaVersionPresent = false
	v1.EnrollmentFlags = 0
	v1.EnrollmentFlagsPresent = false
	v1.Flags |= templateFlagAutoEnroll

	tests := map[string]struct {
		mutate func(*templateAttrs)
		input  templateAttrs
		want   bool
	}{
		"Common v2 machine template": {want: true},
		"Common v1 machine template": {input: v1, want: true},
		"Not a machine template": {
			mutate: func(attrs *templateAttrs) { attrs.Flags &^= templateFlagMachine },
		},
		"CA template": {
			mutate: func(attrs *templateAttrs) { attrs.Flags |= templateFlagCA },
		},
		"Cross CA template": {
			mutate: func(attrs *templateAttrs) { attrs.Flags |= templateFlagCrossCA },
		},
		"Manager approval required": {
			mutate: func(attrs *templateAttrs) { attrs.EnrollmentFlags |= enrollmentFlagPendAllRequests },
			want:   true,
		},
		"Interaction required": {
			mutate: func(attrs *templateAttrs) { attrs.EnrollmentFlags |= enrollmentFlagUserInteraction },
		},
		"RA signature": {
			mutate: func(attrs *templateAttrs) { attrs.RASignatureCount = 1 },
		},
		"Private key archival": {
			mutate: func(attrs *templateAttrs) { attrs.PrivateKeyFlags |= privateKeyFlagRequireArchival },
		},
		"Subject supplied": {
			mutate: func(attrs *templateAttrs) { attrs.CertificateNameFlags |= nameFlagEnrolleeSuppliesSubject },
		},
		"Subject alternative name supplied": {
			mutate: func(attrs *templateAttrs) { attrs.CertificateNameFlags |= nameFlagEnrolleeSuppliesSubjectAlt },
		},
		"Unsupported schema": {
			mutate: func(attrs *templateAttrs) { attrs.SchemaVersion = 5 },
		},
		"v2 missing enrollment flags": {
			mutate: func(attrs *templateAttrs) { attrs.EnrollmentFlagsPresent = false },
		},
		"v2 autoenrollment disabled": {
			mutate: func(attrs *templateAttrs) { attrs.EnrollmentFlags = 0 },
		},
		"v2 contradictory legacy flag": {
			mutate: func(attrs *templateAttrs) {
				attrs.Flags |= templateFlagAutoEnroll
				attrs.EnrollmentFlags = 0
			},
		},
		"v1 contradictory enrollment flag": {
			input: v1,
			mutate: func(attrs *templateAttrs) {
				attrs.EnrollmentFlagsPresent = true
				attrs.EnrollmentFlags = 0
			},
		},
		"Malformed LDAP values": {
			mutate: func(attrs *templateAttrs) { attrs.ValidationError = "flags is malformed" },
		},
		"Missing security descriptor": {
			mutate: func(attrs *templateAttrs) { attrs.SecurityDescriptor = nil },
		},
		"Unsupported ECDSA provider": {
			mutate: func(attrs *templateAttrs) { attrs.DefaultCSPs = []string{"Microsoft Platform ECDSA Provider"} },
		},
		"Unknown provider fails closed": {
			mutate: func(attrs *templateAttrs) { attrs.DefaultCSPs = []string{"Contoso Future Provider"} },
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			attrs := base
			if tc.input.Name != "" {
				attrs = tc.input
			}
			if tc.mutate != nil {
				tc.mutate(&attrs)
			}
			got, reason := machineTemplateEligible(attrs, machineToken{})
			assert.Equal(t, tc.want, got)
			if !tc.want {
				assert.NotEmpty(t, reason)
			}
		})
	}
}

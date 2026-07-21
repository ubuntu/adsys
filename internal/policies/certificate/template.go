package certificate

import (
	"context"
	"fmt"
	"strings"

	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
)

const (
	templateFlagAutoEnroll uint32 = 0x00000020
	templateFlagMachine    uint32 = 0x00000040
	templateFlagCA         uint32 = 0x00000080
	templateFlagCrossCA    uint32 = 0x00000800

	enrollmentFlagPending         uint32 = 0x00000002
	enrollmentFlagAutoEnroll      uint32 = 0x00000020
	enrollmentFlagUserInteraction uint32 = 0x00000100

	privateKeyFlagRequireArchival uint32 = 0x00000001

	nameFlagEnrolleeSuppliesSubject    uint32 = 0x00000001
	nameFlagEnrolleeSuppliesSubjectAlt uint32 = 0x00010000
)

func machineTemplateEligible(attrs templateAttrs, token machineToken) (bool, string) {
	if !attrs.Present {
		return false, "template object was not returned by LDAP"
	}
	if attrs.ValidationError != "" {
		return false, attrs.ValidationError
	}
	if attrs.Flags&templateFlagMachine == 0 {
		return false, "template is not a machine template"
	}
	if attrs.Flags&(templateFlagCA|templateFlagCrossCA) != 0 {
		return false, "CA and cross-CA templates are unsupported"
	}

	generalAutoEnroll := attrs.Flags&templateFlagAutoEnroll != 0
	enrollmentAutoEnroll := attrs.EnrollmentFlags&enrollmentFlagAutoEnroll != 0
	switch {
	case !attrs.SchemaVersionPresent || attrs.SchemaVersion == 1:
		if attrs.EnrollmentFlagsPresent && generalAutoEnroll != enrollmentAutoEnroll {
			return false, "v1 autoenrollment flags are contradictory"
		}
		if !generalAutoEnroll {
			return false, "v1 template is not marked for autoenrollment"
		}
	case attrs.SchemaVersion >= 2 && attrs.SchemaVersion <= 4:
		if !attrs.EnrollmentFlagsPresent {
			return false, "v2-v4 template is missing msPKI-Enrollment-Flag"
		}
		if generalAutoEnroll && !enrollmentAutoEnroll {
			return false, "template autoenrollment flags are contradictory"
		}
		if !enrollmentAutoEnroll {
			return false, "template is not marked for autoenrollment"
		}
	default:
		return false, fmt.Sprintf("template schema version %d is unsupported", attrs.SchemaVersion)
	}

	if attrs.EnrollmentFlags&enrollmentFlagPending != 0 {
		return false, "pending certificate requests are not supported"
	}
	if attrs.EnrollmentFlags&enrollmentFlagUserInteraction != 0 {
		return false, "template requires user interaction"
	}
	if attrs.RASignatureCount != 0 {
		return false, "template requires authorized signatures"
	}
	if attrs.PrivateKeyFlags&privateKeyFlagRequireArchival != 0 {
		return false, "private-key archival is not supported"
	}
	if attrs.CertificateNameFlags&(nameFlagEnrolleeSuppliesSubject|nameFlagEnrolleeSuppliesSubjectAlt) != 0 {
		return false, "enrollee-supplied subject names are not supported"
	}
	if !supportsRSAProvider(attrs.DefaultCSPs) {
		return false, "template restricts enrollment to an unsupported non-RSA provider"
	}

	enroll, autoEnroll, err := templateAutoEnrollRights(attrs.SecurityDescriptor, token)
	if err != nil {
		return false, fmt.Sprintf("template security descriptor is unsafe: %v", err)
	}
	if !enroll {
		return false, "machine token is not granted Enroll"
	}
	if !autoEnroll {
		return false, "machine token is not granted AutoEnroll"
	}
	return true, ""
}

func supportsRSAProvider(providers []string) bool {
	if len(providers) == 0 {
		return true
	}
	hasKnownRSAProvider := false
	for _, provider := range providers {
		normalized := strings.ToLower(provider)
		switch {
		case strings.Contains(normalized, "rsa"),
			strings.Contains(normalized, "software key storage provider"),
			strings.Contains(normalized, "schannel cryptographic provider"),
			strings.Contains(normalized, "enhanced cryptographic provider"),
			strings.Contains(normalized, "base cryptographic provider"),
			strings.Contains(normalized, "strong cryptographic provider"):
			hasKnownRSAProvider = true
		}
	}
	return hasKnownRSAProvider
}

func filterMachineAutoEnrollmentTemplates(ctx context.Context, cas []certAuthority, attrsByName map[string]templateAttrs, token machineToken) []certAuthority {
	filtered := make([]certAuthority, 0, len(cas))
	for _, ca := range cas {
		eligibleTemplates := make([]string, 0, len(ca.Templates))
		for _, name := range ca.Templates {
			attrs, ok := attrsByName[name]
			if !ok {
				log.Warningf(ctx, "Skipping published certificate template %s on CA %s: template attributes were not returned", name, ca.Name)
				continue
			}
			eligible, reason := machineTemplateEligible(attrs, token)
			if !eligible {
				log.Debugf(ctx, "Skipping published certificate template %s on CA %s: %s", name, ca.Name, reason)
				continue
			}
			eligibleTemplates = append(eligibleTemplates, name)
		}
		if len(eligibleTemplates) == 0 {
			log.Debugf(ctx, "CA %s has no machine autoenrollment-authorized templates", ca.Name)
			continue
		}
		ca.Templates = eligibleTemplates
		filtered = append(filtered, ca)
	}
	return filtered
}

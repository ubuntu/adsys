package definitions

import (
	"embed"
	"fmt"

	"github.com/ubuntu/adsys/internal/decorate"
	"github.com/ubuntu/adsys/internal/i18n"
)

//go:embed policy/*
var definitions embed.FS

// GetPolicies returns admx and adml content for the given type t of policies
func GetPolicies(format, distroID string) (admx string, adml string, err error) {
	decorate.OnError(&err, i18n.G("can't get policy definition file"))

	admxData, err := definitions.ReadFile(fmt.Sprintf("policy/%s/%s/%s.admx", distroID, format, distroID))
	if err != nil {
		return "", "", err
	}

	admlData, err := definitions.ReadFile(fmt.Sprintf("policy/%s/%s/%s.adml", distroID, format, distroID))
	if err != nil {
		return "", "", err
	}

	return string(admxData), string(admlData), nil
}

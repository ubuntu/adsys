package ad

import (
	"fmt"

	"github.com/ubuntu/adsys/internal/decorate"
	"github.com/ubuntu/adsys/internal/i18n"
	policydefinitions "github.com/ubuntu/adsys/policies"
)

// GetPolicyDefinitions returns admx and adml content for the given type t of policies
func GetPolicyDefinitions(format, distroID string) (admx string, adml string, err error) {
	decorate.OnError(&err, i18n.G("can't get policy definition file"))

	admxData, err := policydefinitions.All.ReadFile(fmt.Sprintf("%s/%s/%s.admx", distroID, format, distroID))
	if err != nil {
		return "", "", err
	}

	admlData, err := policydefinitions.All.ReadFile(fmt.Sprintf("%s/%s/%s.adml", distroID, format, distroID))
	if err != nil {
		return "", "", err
	}

	return string(admxData), string(admlData), nil
}

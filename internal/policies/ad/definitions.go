package ad

import (
	"context"
	"fmt"

	"github.com/ubuntu/adsys/internal/decorate"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	policydefinitions "github.com/ubuntu/adsys/policies"
)

// GetPolicyDefinitions returns admx and adml content for the given type t of policies.
func GetPolicyDefinitions(ctx context.Context, format, distroID string) (admx string, adml string, err error) {
	decorate.OnError(&err, i18n.G("can't get policy definition file"))

	log.Debugf(ctx, "GetPolicyDefinitions for %q (%q)", distroID, format)

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

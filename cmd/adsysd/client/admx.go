package client

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/adsysservice"
	"github.com/ubuntu/adsys/internal/config"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
)

func (a *App) installAdmx() {
	var distro *string
	mainCmd := &cobra.Command{
		Use:       "admx lts-only|all",
		Short:     i18n.G("Dump windows policy definitions"),
		ValidArgs: []string{"lts-only", "all"},
		Args:      cobra.ExactValidArgs(1),
		RunE:      func(cmd *cobra.Command, args []string) error { return a.getPolicyDefinitions(args[0], *distro) },
	}
	distro = mainCmd.Flags().StringP("distro", "", config.DistroID, i18n.G("distro for which to retrieve policy definition."))
	a.rootCmd.AddCommand(mainCmd)
}

// getPolicyDefinitions writes policy definitions files returns the current server and client versions.
func (a App) getPolicyDefinitions(format, distroID string) (err error) {
	client, err := adsysservice.NewClient(a.config.Socket, a.getTimeout())
	if err != nil {
		return err
	}
	defer client.Close()

	stream, err := client.DumpPoliciesDefinitions(a.ctx, &adsys.DumpPolicyDefinitionsRequest{
		Format:   format,
		DistroID: distroID,
	})
	if err != nil {
		return err
	}

	var admxContent, admlContent string
	for {
		r, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		admxContent, admlContent = r.GetAdmx(), r.GetAdml()
		if admxContent != "" && admlContent != "" {
			break
		}
	}

	admx, adml := fmt.Sprintf("%s.admx", distroID), fmt.Sprintf("%s.adml", distroID)
	log.Infof(context.Background(), "Saving %s and %s", admx, adml)
	if err := os.WriteFile(admx, []byte(admxContent), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(adml, []byte(admlContent), 0755); err != nil {
		return err
	}

	return nil
}

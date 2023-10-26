package client

import (
	"context"
	"fmt"

	"github.com/charmbracelet/glamour"
	"github.com/leonelquinteros/gotext"
	"github.com/spf13/cobra"
	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/adsysservice"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
)

func (a *App) installDoc() {
	docCmd := &cobra.Command{
		Use:   "doc [CHAPTER]",
		Short: gotext.Get("Documentation"),
		Args:  cobra.MaximumNArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) != 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			client, err := adsysservice.NewClient(a.config.Socket, a.getTimeout())
			if err != nil {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			defer client.Close()
			stream, err := client.ListDoc(a.ctx, &adsys.Empty{})
			if err != nil {
				log.Errorf(context.Background(), "could not connect to adsysd: %v", err)
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			r, err := stream.Recv()
			if err != nil {
				log.Errorf(context.Background(), "could not receive shell completion message: %v", err)
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return r.GetChapters(), cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var chapter string
			if len(args) > 0 {
				chapter = args[0]
			}
			return a.getDocumentation(chapter)
		},
	}

	a.rootCmd.AddCommand(docCmd)
}

func (a *App) getDocumentation(chapter string) error {
	client, err := adsysservice.NewClient(a.config.Socket, a.getTimeout())
	if err != nil {
		return err
	}
	defer client.Close()

	stream, err := client.GetDoc(a.ctx, &adsys.GetDocRequest{Chapter: chapter})
	if err != nil {
		return err
	}

	content, err := singleMsg(stream)
	if err != nil {
		return err
	}

	// Transform stdout content
	r, err := glamour.NewTermRenderer(glamour.WithEnvironmentConfig())
	if err != nil {
		return err
	}
	out, err := r.Render(content)
	if err != nil {
		return err
	}

	fmt.Print(out)

	return nil
}

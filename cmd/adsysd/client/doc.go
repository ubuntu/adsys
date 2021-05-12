package client

import (
	"fmt"

	"github.com/charmbracelet/glamour"
	"github.com/spf13/cobra"
	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/adsysservice"
	"github.com/ubuntu/adsys/internal/i18n"
)

func (a *App) installDoc() {
	var raw *bool
	docCmd := &cobra.Command{
		Use:   "doc [CHAPTER]",
		Short: i18n.G("Documentation"),
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var chapter string
			if len(args) > 0 {
				chapter = args[0]
			}
			return a.renderDocumentation(chapter, *raw)
		},
	}
	raw = docCmd.Flags().BoolP("raw", "r", false, i18n.G("do not render markup."))

	a.rootCmd.AddCommand(docCmd)
}

func (a *App) renderDocumentation(chapter string, raw bool) error {
	client, err := adsysservice.NewClient(a.config.Socket, a.getTimeout())
	if err != nil {
		return err
	}
	defer client.Close()

	var stream recver
	if chapter == "" {
		stream, err = client.ListDoc(a.ctx, &adsys.ListDocRequest{Raw: raw})
	} else {
		stream, err = client.GetDoc(a.ctx, &adsys.GetDocRequest{Chapter: chapter})
	}
	if err != nil {
		return err
	}

	content, err := singleMsg(stream)
	if err != nil {
		return err
	}

	out := content
	if !raw {
		r, err := glamour.NewTermRenderer(glamour.WithEnvironmentConfig())
		if err != nil {
			return err
		}
		out, err = r.Render(content)
		if err != nil {
			return err
		}
	}
	fmt.Print(out)

	return nil
}

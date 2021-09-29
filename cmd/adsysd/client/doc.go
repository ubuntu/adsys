package client

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/glamour"
	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/html"
	"github.com/gomarkdown/markdown/parser"
	"github.com/spf13/cobra"
	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/doc"
	"github.com/ubuntu/adsys/internal/adsysservice"
	"github.com/ubuntu/adsys/internal/i18n"
)

func (a *App) installDoc() {
	var format, dest *string
	docCmd := &cobra.Command{
		Use:   "doc [CHAPTER]",
		Short: i18n.G("Documentation"),
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
			stream, err := client.ListDoc(a.ctx, &adsys.ListDocRequest{Raw: true})
			if err != nil {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			list, err := singleMsg(stream)
			if err != nil {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}

			return strings.Split(list, "\n"), cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var chapter string
			if len(args) > 0 {
				chapter = args[0]
			}
			return a.getDocumentation(chapter, *format, *dest)
		},
	}
	format = docCmd.Flags().StringP("format", "f", "markdown", i18n.G("Format type (markdown, raw or html)."))
	dest = docCmd.Flags().StringP("dest", "d", "", i18n.G("Write documentation file(s) to this directory."))

	a.rootCmd.AddCommand(docCmd)
}

func (a *App) getDocumentation(chapter, format, dest string) error {
	if format != "markdown" && format != "raw" && format != "html" {
		return fmt.Errorf("format can only be markdown, raw or html. Got %q", format)
	}

	client, err := adsysservice.NewClient(a.config.Socket, a.getTimeout())
	if err != nil {
		return err
	}
	defer client.Close()

	var stream recver
	var withHeader bool
	if dest != "" {
		stream, err = client.GetDoc(a.ctx, &adsys.GetDocRequest{Chapter: chapter})
		withHeader = true
	} else if chapter == "" {
		stream, err = client.ListDoc(a.ctx, &adsys.ListDocRequest{Raw: false})
	} else {
		stream, err = client.GetDoc(a.ctx, &adsys.GetDocRequest{Chapter: chapter})
		withHeader = true
	}
	if err != nil {
		return err
	}

	content, err := singleMsg(stream)
	if err != nil {
		return err
	}

	for _, out := range strings.Split(content, doc.SplitFilesToken) {
		if len(out) == 0 {
			continue
		}
		var filename string
		if withHeader {
			d := strings.SplitN(out, "\n", 2)
			filename, out = d[0], d[1]
		}

		var ext string
		switch format {
		case "markdown":
			// Transform stdout content
			if dest == "" {
				r, err := glamour.NewTermRenderer(glamour.WithEnvironmentConfig())
				if err != nil {
					return err
				}
				out, err = r.Render(out)
				if err != nil {
					return err
				}
			}
			ext = ".md"
		case "html":
			extensions := parser.CommonExtensions | parser.AutoHeadingIDs
			parser := parser.NewWithExtensions(extensions)
			htmlFlags := html.CommonFlags | html.HrefTargetBlank | html.TOC | html.CompletePage
			opts := html.RendererOptions{Flags: htmlFlags}
			renderer := html.NewRenderer(opts)
			out = string(markdown.ToHTML([]byte(out), parser, renderer))
			ext = ".html"
		default:
		}

		// Write directly on stdout
		if dest == "" {
			fmt.Print(out)
			continue
		}

		// Dump documentation in a directory
		if err = os.MkdirAll(dest, 0750); err != nil {
			return fmt.Errorf(i18n.G("can't create %q"), dest)
		}
		if err := os.WriteFile(filepath.Join(dest, filename+ext), []byte(out), 0600); err != nil {
			return fmt.Errorf(i18n.G("can't write documentation chapter %q: %v"), filename+ext, err)
		}
	}

	return nil
}

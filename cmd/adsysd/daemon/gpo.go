package daemon

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/mvo5/libsmbclient-go"
	"github.com/spf13/cobra"
	"github.com/ubuntu/adsys/internal/cmdhandler"
	"github.com/ubuntu/adsys/internal/i18n"
	"golang.org/x/sync/errgroup"
)

func (a *App) installGPOHelpers() {
	mainCmd := &cobra.Command{
		Use:    "gpo COMMAND",
		Short:  i18n.G("AD gpo management"),
		Args:   cmdhandler.SubcommandsRequiredWithSuggestions,
		RunE:   cmdhandler.NoCmd,
		Hidden: true,
	}
	a.rootCmd.AddCommand(mainCmd)

	cmd := &cobra.Command{
		Use:   "fetch url directory gpo [gpo...]",
		Short: i18n.G("Fetch all gpos content in directory from AD on url"),
		Args:  cobra.MinimumNArgs(3),
		RunE:  func(cmd *cobra.Command, args []string) error { return fetch(args[0], args[1], args[2:]) },
	}
	mainCmd.AddCommand(cmd)
}

func fetch(url, dest string, gpos []string) error {
	if _, err := os.Stat(dest); err != nil {
		return fmt.Errorf("%q does not exist", dest)
	}

	g := new(errgroup.Group)
	for _, gpo := range gpos {
		gpo := gpo
		g.Go(func() error {
			dest := filepath.Join(dest, gpo)
			client := libsmbclient.New()
			client.SetUseKerberos()

			// smb://<server>/sysvol/<domain>/Policies/<GPO>

			// don’t use filepath.Join() to avoid stripping smb://
			baseURL := url + "/" + /*"Policies"*/ gpo

			// TODO: look for dest/GPT.INI and compare with version on AD to decide if we redownload or not

			// read local

			// read remote

			// compare version

			return downloadRecursive(client, baseURL, dest)
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("One or more error while fetching GPOs: %v", err)
	}

	return nil
}

func downloadRecursive(client *libsmbclient.Client, url string, dest string) error {
	d, err := client.Opendir(url)
	if err != nil {
		log.Fatal(err)
	}
	defer d.Closedir()

	if err := os.MkdirAll(dest, 0700); err != nil {
		return fmt.Errorf("can't create %q", dest)
	}

	for {
		dirent, err := d.Readdir()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if dirent.Name == "." || dirent.Name == ".." {
			continue
		}

		entityURL := url + "/" + dirent.Name
		entityDest := filepath.Join(dest, dirent.Name)

		if dirent.Type == libsmbclient.SmbcFile {
			f, err := client.Open(entityURL, 0, 0)
			if err != nil {
				return err
			}
			defer f.Close()
			// Read() is on *libsmbclient.File, not libsmbclient.File
			pf := &f
			data, err := ioutil.ReadAll(pf)

			if err := ioutil.WriteFile(entityDest, data, 0700); err != nil {
				return err
			}
		} else if dirent.Type == libsmbclient.SmbcDir {
			err := downloadRecursive(client, entityURL, entityDest)
			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("unsupported type %q for entry %s", dirent.Type, dirent.Name)
		}
	}
	return nil
}

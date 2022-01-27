package ad

/*
System

On startup (after sssd) or refresh:
Create a ticket from keytab:
$ kinit 'ad-desktop-1$@EXAMPLE.COM' -k -c /run/adsys/krb5cc/<FQDN>
<download call for host>

User

* On login pam_sss sets KRB5CCNAME
Client passes KRB5CCNAME to daemon
Daemon verifies that it matches the uid of the caller
Creates a symlink in /run/adsys/krb5cc/username -> /tmp/krb5cc_…
<download call for user>:

* On refresh:
systemd system unit timer
List all /run/adsys/krb5cc/
Check the symlink is not dangling
Check the user is still logged in (loginctl?)
For each logged in user (sequentially):
- <download call for user>

<download call>
  mutex for download
  set KRB5CCNAME
  download all GPO concurrently
  unset KRB5CCNAME
  release mutex

*/

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/mvo5/libsmbclient-go"
	"github.com/ubuntu/adsys/internal/decorate"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/smbsafe"
	"golang.org/x/sync/errgroup"
)

/*
fetch downloads a list of gpos from a url for a given kerberosTicket and stores the downloaded files in dest.
In addition, assetsURL is always refreshed if not empty.
Each gpo entry must be a gpo, with a name, url of the form: smb://<server>/SYSVOL/<AD domain>/<GPO_ID> and mutex.
If krb5Ticket is empty, no authentication is done on samba.
This should not be called concurrently.
*/
func (ad *AD) fetch(ctx context.Context, krb5Ticket string, gpos map[string]string, assetsURL string) (err error) {
	defer decorate.OnError(&err, i18n.G("can't download all gpos"))

	// protect env variable and map creation
	ad.fetchMu.Lock()
	defer ad.fetchMu.Unlock()

	// Set kerberos ticket.
	const krb5TicketEnv = "KRB5CCNAME"
	oldKrb5Ticket := os.Getenv(krb5TicketEnv)
	if err := os.Setenv(krb5TicketEnv, krb5Ticket); err != nil {
		return err
	}
	defer func() {
		if err := os.Setenv(krb5TicketEnv, oldKrb5Ticket); err != nil {
			log.Errorf(ctx, "Couln't restore initial value for %s: %v", krb5Ticket, err)
		}
	}()

	client := libsmbclient.New()
	defer client.Close()
	// When testing we cannot use kerberos without a real kerberos server
	// So we don't use kerberos in this case
	if !ad.withoutKerberos {
		client.SetUseKerberos()
	}

	var errg errgroup.Group
	for name, url := range gpos {
		g, ok := ad.gpos[name]
		if !ok {
			ad.gpos[name] = &gpo{
				name: name,
				url:  url,
				mu:   &sync.RWMutex{},
			}
			g = ad.gpos[name]
		}
		errg.Go(func() (err error) {
			defer decorate.OnError(&err, i18n.G("can't download GPO %q"), g.name)

			smbsafe.WaitSmb()
			defer smbsafe.DoneSmb()

			log.Debugf(ctx, "Analyzing GPO %q", g.name)

			dest := filepath.Join(ad.gpoCacheDir, filepath.Base(g.url))

			// Look at GPO version and compare with the one on AD to decide if we redownload or not
			shouldDownload, err := gpoNeedsDownload(ctx, client, g, dest)
			if err != nil {
				return err
			}
			if !shouldDownload {
				return nil
			}

			log.Infof(ctx, "Downloading GPO %q", g.name)
			g.mu.Lock()
			defer g.mu.Unlock()
			g.testConcurrent = true

			return download(ctx, client, g.url, dest, false)
		})
	}

	// Also, refresh data assets. We are protected by ad main mutex.
	errg.Go(func() (err error) {
		defer decorate.OnError(&err, i18n.G("can't download data directory"))

		if assetsURL == "" {
			return nil
		}
		destDir := filepath.Join(ad.gpoCacheDir, "assets")
		log.Infof(ctx, "Downloading assets to %q", destDir)

		return download(ctx, client, assetsURL, destDir, true)
	})

	if err := errg.Wait(); err != nil {
		return fmt.Errorf("one or more error while fetching GPOs: %w", err)
	}

	return nil
}

func gpoNeedsDownload(ctx context.Context, client *libsmbclient.Client, g *gpo, localPath string) (updateNeeded bool, err error) {
	defer decorate.OnError(&err, i18n.G("can't check if %s needs refreshing"), g.name)

	g.mu.RLock()
	defer g.mu.RUnlock()

	var localVersion, remoteVersion int
	gptIniPath := filepath.Join(localPath, "GPT.INI")
	if f, err := os.Open(filepath.Clean(gptIniPath)); err == nil {
		defer decorate.LogFuncOnErrorContext(ctx, f.Close)

		if localVersion, err = getGPOVersion(f); err != nil {
			log.Warningf(ctx, "Invalid local GPT.INI for %s: %v\nDownloading GPO…", g.name, err)
		}
	}

	f, err := client.Open(fmt.Sprintf("%s/GPT.INI", g.url), 0, 0)
	if err != nil {
		return false, err
	}
	defer f.Close()
	// Read() is on *libsmbclient.File, not libsmbclient.File
	pf := &f
	if remoteVersion, err = getGPOVersion(pf); err != nil {
		return false, err
	}

	if localVersion >= remoteVersion {
		return false, nil
	}

	return true, nil
}

func getGPOVersion(r io.Reader) (version int, err error) {
	defer decorate.OnError(&err, i18n.G("invalid remote GPT.INI"))

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		t := scanner.Text()
		if strings.HasPrefix(t, "Version=") {
			version, err := strconv.Atoi(strings.TrimPrefix(t, "Version="))
			if err != nil {
				return 0, fmt.Errorf("version is not an int: %w", err)
			}
			return version, nil
		}
	}

	return 0, errors.New("version not found")
}

// download will dl in a temporary directory and only commit it if fully downloaded without any errors.
// If url is a file, it will download it.
// missingOk allows to not error out on url not present on server.
func download(ctx context.Context, client *libsmbclient.Client, url, dest string, missingOK bool) (err error) {
	defer decorate.OnError(&err, i18n.G("download %q failed"), url)

	smbsafe.WaitSmb()
	defer smbsafe.DoneSmb()

	// Check if we have a file or a directory
	d, errOpenDir := client.Opendir(url)
	if errOpenDir != nil {
		f, errOpenFile := client.Open(url, 0, 0)
		if errOpenFile != nil {
			if err := os.RemoveAll(dest); err != nil {
				return err
			}

			if missingOK {
				log.Warningf(ctx, "%s not present on server", url)
				return nil
			}
			return errOpenDir
		}
		defer f.Close()

		// Download the file directly to dest
		pf := &f
		data, err := io.ReadAll(pf)
		if err != nil {
			return err
		}
		g, err := os.CreateTemp(filepath.Dir(dest), fmt.Sprintf("%s.*", filepath.Base(dest)))
		if err != nil {
			return err
		}
		defer g.Close()
		if _, err := g.Write(data); err != nil {
			return err
		}
		g.Close()
		return os.Rename(g.Name(), dest)
	}

	// It is a directory: recursive download
	if err := d.Closedir(); err != nil {
		return fmt.Errorf(i18n.G("could not close directory: %v"), err)
	}

	tmpdest, err := os.MkdirTemp(filepath.Dir(dest), fmt.Sprintf("%s.*", filepath.Base(dest)))
	if err != nil {
		return err
	}
	// Always to try remove temporary directory, so that in case of any failures, it’s not left behind
	defer func() {
		if err := os.RemoveAll(tmpdest); err != nil {
			log.Info(ctx, i18n.G("Could not clean up temporary directory:"), err)
		}
	}()
	if err := downloadRecursive(ctx, client, url, tmpdest); err != nil {
		return err
	}
	// Remove previous download content
	if err := os.RemoveAll(dest); err != nil {
		return err
	}
	// Rename temporary directory to final location
	if err := os.Rename(tmpdest, dest); err != nil {
		return err
	}
	return nil
}

func downloadRecursive(ctx context.Context, client *libsmbclient.Client, url, dest string) error {
	d, err := client.Opendir(url)
	if err != nil {
		return err
	}
	defer func() {
		if err := d.Closedir(); err != nil {
			log.Info(ctx, "Could not close directory:", err)
		}
	}()

	if err := os.MkdirAll(dest, 0700); err != nil {
		return fmt.Errorf("can't create %q", dest)
	}

	for {
		dirent, err := d.Readdir()
		if errors.Is(err, io.EOF) {
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

		switch dirent.Type {
		case libsmbclient.SmbcFile:
			log.Debugf(ctx, i18n.G("Downloading %s"), entityURL)
			f, err := client.Open(entityURL, 0, 0)
			if err != nil {
				return err
			}
			defer f.Close()
			// Read() is on *libsmbclient.File, not libsmbclient.File
			pf := &f
			data, err := io.ReadAll(pf)
			if err != nil {
				return err
			}

			if err := os.WriteFile(entityDest, data, 0600); err != nil {
				return err
			}
		case libsmbclient.SmbcDir:
			err := downloadRecursive(ctx, client, entityURL, entityDest)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported type %q for entry %s", dirent.Type, dirent.Name)
		}
	}
	return nil
}

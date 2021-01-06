package ad

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/ad/registry"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/smbsafe"
)

// TODO: errors should logs in server (probably a grpc middleware)

// ObjectClass is the type of object in the directory. It can be a computer or a user
type ObjectClass string

const (
	// UserObject is a user representation in AD
	UserObject ObjectClass = "user"
	// ComputerObject is a computer representation in AD
	ComputerObject = "computer"
)

type gpo struct {
	name string
	url  string
	mu   *sync.RWMutex

	// This property is used to instrument the tests for concurrent download and parsing of GPOs
	// Cf internal_test::TestFetchOneGPOWhileParsingItConcurrently()
	testConcurrent bool
}

// AD structure to manage call concurrency
type AD struct {
	hostname string
	url      string

	gpoCacheDir  string
	krb5CacheDir string
	sssCCName    string

	gpos map[string]*gpo
	sync.RWMutex

	withoutKerberos bool
	gpoListCmd      []string
}

type options struct {
	runDir          string
	cacheDir        string
	sssCacheDir     string
	withoutKerberos bool
	gpoListCmd      []string
}

type option func(*options) error

type combinedOutputter interface {
	CombinedOutput() ([]byte, error)
}

// New returns an AD object to manage concurrency, with a local kr5 ticket from machine keytab
func New(ctx context.Context, url, domain string, opts ...option) (ad *AD, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf(i18n.G("couldn't create Active Directory object: %v"), err)
		}
	}()

	// defaults
	args := options{
		runDir:      "/run/adsys",
		cacheDir:    "/var/cache/adsys",
		sssCacheDir: "/var/lib/sss/db",
		gpoListCmd:  []string{"/usr/libexec/adsys-gpolist"},
	}
	// applied options
	for _, o := range opts {
		if err := o(&args); err != nil {
			return nil, err
		}
	}

	krb5CacheDir := filepath.Join(args.runDir, "krb5cc")
	if err := os.MkdirAll(krb5CacheDir, 0700); err != nil {
		return nil, err
	}
	gpoCacheDir := filepath.Join(args.cacheDir, "gpo_cache")
	if err := os.MkdirAll(gpoCacheDir, 0700); err != nil {
		return nil, err
	}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	// local machine sssd krb5 cache
	sssCCName := filepath.Join(args.sssCacheDir, "ccache_"+strings.ToUpper(domain))

	return &AD{
		hostname:     hostname,
		url:          url,
		gpoCacheDir:  gpoCacheDir,
		krb5CacheDir: krb5CacheDir,
		sssCCName:    sssCCName,
		gpos:         make(map[string]*gpo),
		gpoListCmd:   args.gpoListCmd,
	}, nil
}

// GetPolicies returns all policy entries, stacked in order of priority.GetPolicies
// It lists them, check state in global local cache and then redownload if any new version is available.
// It users the given krb5 ticket reference to authenticate to AD.
// userKrb5CCName has no impact for computer object and is ignored. If empty, we will expect to find one cached
// ticket <krb5CCDir>/<objectName>.
func (ad *AD) GetPolicies(ctx context.Context, objectName string, objectClass ObjectClass, userKrb5CCName string) (entries []entry.Entry, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf(i18n.G("error while getting policies for %q: %v"), objectName, err)
		}
	}()

	// Strip domain suffix if any
	if i := strings.LastIndex(objectName, "@"); i > 0 {
		objectName = objectName[:i]
	}

	log.Debugf(ctx, "GetPolicies for %q, type %q", objectName, objectClass)

	krb5CCPath := filepath.Join(ad.krb5CacheDir, objectName)
	if objectClass == ComputerObject && objectName != ad.hostname {
		return nil, fmt.Errorf(i18n.G("requested a type computer of %q which isn't current host %q"), objectName, ad.hostname)
	}
	// Create a ccache symlink on first fetch for futur calls (on refresh for instance)
	if userKrb5CCName != "" || objectClass == ComputerObject {
		src := userKrb5CCName
		// there is no env var for machine: get sss ccache
		if objectClass == ComputerObject {
			src = ad.sssCCName
		}
		if err := ad.ensureKrb5CCName(src, krb5CCPath); err != nil {
			return nil, err
		}
	}

	// Get the list of GPO for object
	// ./list --objectclass=user  ldap://adc01.warthogs.biz bob
	// TODO: Embed adsys-gpolist in binary
	args := append([]string{}, ad.gpoListCmd...) // Copy gpoListCmd to prevent data race
	cmdArgs := append(args, "--objectclass", string(objectClass), ad.url, objectName)
	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("KRB5CCNAME=%s", krb5CCPath))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	smbsafe.WaitExec()
	err = cmd.Run()
	smbsafe.DoneExec()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve the list of GPO: %v\n%s", err, stderr.String())
	}

	gpos := make(map[string]string)
	var orderedGPOs []gpo
	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		t := scanner.Text()
		res := strings.SplitN(t, "\t", 2)
		gpoName, gpoURL := res[0], res[1]
		log.Debugf(ctx, "GPO %q for %q available at %q", gpoName, objectName, gpoURL)
		gpos[gpoName] = gpoURL
		orderedGPOs = append(orderedGPOs, gpo{name: gpoName, url: gpoURL})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if err = ad.fetch(ctx, krb5CCPath, gpos); err != nil {
		return nil, err
	}

	// Parse policies
	entries, err = ad.parseGPOs(ctx, orderedGPOs, objectClass)
	if err != nil {
		return nil, err
	}

	return entries, nil
}

// ensureKrb5CCName manages user ccname symlinks.
// It handles concurrent calls, and only recreate the symlink if we want to point to
// a new destination.
func (ad *AD) ensureKrb5CCName(srcKrb5CCName, dstKrb5CCName string) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf(i18n.G("failed to create symlink for caching: %v"), err)
		}
	}()

	ad.Lock()
	defer ad.Unlock()

	srcKrb5CCName, err = filepath.Abs(srcKrb5CCName)
	if err != nil {
		return fmt.Errorf(i18n.G("can't get absolute path of ccname to symlink to: %v"), err)
	}

	src, err := os.Readlink(dstKrb5CCName)
	if err == nil {
		// All set, don’t recreate the symlink.
		if src == srcKrb5CCName {
			return nil
		}
		// Delete the symlink to create a new one.
		if err := os.Remove(dstKrb5CCName); err != nil {
			return fmt.Errorf(i18n.G("failed to remove existing symlink: %v"), err)
		}
	}

	if err := os.Symlink(srcKrb5CCName, dstKrb5CCName); err != nil {
		return err
	}
	return nil
}

func (ad *AD) parseGPOs(ctx context.Context, gpos []gpo, objectClass ObjectClass) ([]entry.Entry, error) {
	entries := make(map[string]entry.Entry)
	var keys []string
	for _, g := range gpos {
		name, url := g.name, g.url
		if err := func() error {
			ad.RLock()
			ad.gpos[name].mu.RLock()
			defer ad.gpos[name].mu.RUnlock()
			_ = ad.gpos[name].testConcurrent
			ad.RUnlock()

			class := "User"
			if objectClass == ComputerObject {
				class = "Machine"
			}
			f, err := os.Open(filepath.Join(ad.gpoCacheDir, filepath.Base(url), class, "Registry.pol"))
			if err != nil && os.IsExist(err) {
				return err
			} else if err != nil && os.IsNotExist(err) {
				log.Infof(ctx, "Policy %s doesn't have any policy for class %q %s", name, objectClass, err)
				return nil
			}
			defer f.Close()

			// Decode and apply policies in gpo order. First win
			policies, err := registry.DecodePolicy(f)
			if err != nil {
				return err
			}
			for _, pol := range policies {
				if _, ok := entries[pol.Key]; ok {
					continue
				}
				entries[pol.Key] = pol
				keys = append(keys, pol.Key)
			}

			return nil
		}(); err != nil {
			return nil, err
		}
	}

	var r []entry.Entry
	sort.Strings(keys)
	for _, k := range keys {
		r = append(r, entries[k])
	}

	return r, nil
}

package ad

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/ad/registry"
	"github.com/ubuntu/adsys/internal/policies/policy"
)

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
}

// AD structure to manage call concurrency
type AD struct {
	hostname string
	url      string

	gpoCacheDir  string
	krb5CacheDir string

	gpos map[string]gpo
	sync.Mutex

	withoutKerberos bool
	gpoListCmd      *exec.Cmd

	// This property is used to instrument the tests for concurrent download and parsing of GPOs
	// Cf internal_test::TestFetchOneGPOWhileParsingItConccurently()
	testConcurrentGPO bool
}

type options struct {
	runDir          string
	cacheDir        string
	withoutKerberos bool
	kinitCmd        combinedOutputter
	gpoListCmd      *exec.Cmd
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
		runDir:   "/run/adsys",
		cacheDir: "/var/cache/adsys",
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

	// Create local machine ticket
	// kinit 'machine$@domain' -k -c <DESTINATION DIRECTORY>
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	n := fmt.Sprintf("%s$@%s", hostname, domain)
	// we need previous options to be initialized as parameter for this command
	var kinitCmd combinedOutputter = exec.CommandContext(ctx, "kinit", n, "-k", "-c", filepath.Join(krb5CacheDir, hostname))
	if args.kinitCmd != nil {
		kinitCmd = args.kinitCmd
	}

	output, err := kinitCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to execute create machine ticket:\n%s\n%v", output, err)
	}

	return &AD{
		hostname:     hostname,
		url:          url,
		gpoCacheDir:  gpoCacheDir,
		krb5CacheDir: krb5CacheDir,
		gpos:         make(map[string]gpo),
		gpoListCmd:   args.gpoListCmd,
	}, nil
}

// GetPolicies returns all policy entries, stacked in order of priority.GetPolicies
// It lists them, check state in global local cache and then redownload if any new version is available.
// It users the given krb5 ticket reference to authenticate to AD.
// userKrb5CCName has no impact for computer object and is ignored. If empty, we will expect to find one cached
// ticket <krb5CCDir>/<objectName>.
func (ad *AD) GetPolicies(ctx context.Context, objectName string, objectClass ObjectClass, userKrb5CCName string) (entries map[string]policy.Entry, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf(i18n.G("error while getting policies for %q: %v"), objectName, err)
		}
	}()

	log.Debugf(ctx, "GetPolicies for %q, type %q", objectName, objectClass)

	krb5CCPath := filepath.Join(ad.krb5CacheDir, objectName)
	if objectClass == ComputerObject && objectName != ad.hostname {
		return nil, fmt.Errorf(i18n.G("requested a type computer of %q which isn't current host %q"), objectName, ad.hostname)
	}
	// Create a symlink for futur calls (on refresh for instance)
	if objectClass == UserObject && userKrb5CCName != "" {
		if err := os.Symlink(userKrb5CCName, krb5CCPath); err != nil {
			return nil, fmt.Errorf(i18n.G("failed to create symlink for caching: %v"), err)
		}
	}

	// Get the list of GPO for object
	// ./list --objectclass=user  ldap://adc01.warthogs.biz bob
	// TODO: Embed adsys-gpolist in binary
	cmd := exec.CommandContext(ctx, "/usr/libexec/adsys-gpolist", "--objectclass", string(objectClass), ad.url, objectName)
	cmd.Env = append(os.Environ(), fmt.Sprintf("KRB5CCNAME=%s", krb5CCPath))
	if ad.gpoListCmd != nil {
		cmd = ad.gpoListCmd
		cmd.Env = append(cmd.Env, fmt.Sprintf("KRB5CCNAME=%s", krb5CCPath))
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to retrieve the list of GPO: %v\n%s", err, stderr.String())
	}

	gpos := make(map[string]string)
	var gpoNames []string

	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		t := scanner.Text()
		res := strings.SplitN(t, "\t", 2)
		gpoName, gpoURL := res[0], res[1]
		log.Debugf(ctx, "GPO %q for %q available at %q", gpoName, objectName, gpoURL)
		gpos[gpoName] = gpoURL
		gpoNames = append(gpoNames, gpoName)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if err = ad.fetch(ctx, krb5CCPath, gpos); err != nil {
		return nil, err
	}

	// Parse policies
	entries, err = ad.parseGPOs(ctx, gpoNames, objectClass)
	if err != nil {
		return nil, err
	}

	return entries, nil
}

func (ad *AD) parseGPOs(ctx context.Context, gpos []string, objectClass ObjectClass) (entries map[string]policy.Entry, err error) {
	entries = make(map[string]policy.Entry)
	for _, n := range gpos {
		if err := func() error {
			ad.gpos[n].mu.RLock()
			defer ad.gpos[n].mu.RUnlock()
			_ = ad.testConcurrentGPO

			class := "User"
			if objectClass == ComputerObject {
				class = "Machine"
			}
			f, err := os.Open(filepath.Join(ad.gpoCacheDir, n, class, "Registry.pol"))
			if err != nil && os.IsExist(err) {
				return err
			} else if err != nil && os.IsNotExist(err) {
				log.Infof(ctx, "Policy %s doesn't have any policy for class %s", n, err)
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
			}

			return nil
		}(); err != nil {
			return nil, err
		}
	}
	return entries, nil
}

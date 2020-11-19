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
	url string

	gpoCacheDir  string
	krb5CacheDir string

	gpos map[string]gpo
	sync.Mutex
}

type options struct {
	runDir string
}

type option func(*options) error

func withRunDir(runDir string) func(o *options) error {
	return func(o *options) error {
		o.runDir = runDir
		return nil
	}
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
		runDir: "/run/adsys",
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
	gpoCacheDir := filepath.Join(args.runDir, "gpo_cache")
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

	output, err := exec.CommandContext(ctx, "kinit", n, "-k", "-c", filepath.Join(krb5CacheDir, hostname)).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to execute create machine ticket: %v\n%s", err, output)
	}

	return &AD{
		url:          url,
		gpoCacheDir:  gpoCacheDir,
		krb5CacheDir: krb5CacheDir,
		gpos:         make(map[string]gpo),
	}, nil
}

// GetPolicies returns all policy entries, stacked in order of priority.GetPolicies
// It lists them, check state in global local cache and then redownload if any new version is available.
// It users the given krb5 ticket reference to authenticate to AD.
// If krb5CCName is empty, we will expect to find one in krb5CCDir under objectName.
func (ad *AD) GetPolicies(ctx context.Context, objectName string, objectClass ObjectClass, krb5CCName string) (entries []policy.Entry, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf(i18n.G("error while getting policies for %q: %v"), objectName, err)
		}
	}()

	log.Debugf(ctx, "GetPolicies for %q", objectName)
	// Get the list of GPO for object
	// ./list --objectclass=user  ldap://adc01.warthogs.biz bob
	cmd := exec.CommandContext(ctx, "../list", "--objectclass", string(objectClass), ad.url, objectName)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to retrieve the list of GPO: %v\n%s", err, stderr.String())
	}

	gpos := make(map[string]string)
	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		t := scanner.Text()
		res := strings.SplitN(t, "\t", 2)
		gpoName, gpoURL := res[0], res[1]
		log.Debugf(ctx, "GPO %q for %q available at %q", gpoName, objectName, gpoURL)
		gpos[gpoName] = gpoURL
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if err = ad.fetch(ctx, krb5CCName, gpos); err != nil {
		return nil, err
	}

	return nil, nil
}

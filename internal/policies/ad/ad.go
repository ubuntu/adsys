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

	// embed gpolist python binary
	_ "embed"

	"github.com/ubuntu/adsys/internal/consts"
	"github.com/ubuntu/adsys/internal/decorate"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	adcommon "github.com/ubuntu/adsys/internal/policies/ad/common"
	"github.com/ubuntu/adsys/internal/policies/ad/registry"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/smbsafe"
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

	// This property is used to instrument the tests for concurrent download and parsing of GPOs
	// Cf internal_test::TestFetchOneGPOWhileParsingItConcurrently()
	testConcurrent bool
}

// AD structure to manage call concurrency
type AD struct {
	IsOffline bool

	hostname string
	url      string

	versionID        string
	gpoCacheDir      string
	gpoRulesCacheDir string
	krb5CacheDir     string
	sssCCName        string

	gpos map[string]*gpo
	sync.RWMutex

	withoutKerberos bool
	gpoListCmd      []string
}

type options struct {
	versionID       string
	runDir          string
	cacheDir        string
	sssCacheDir     string
	withoutKerberos bool
	gpoListCmd      []string
}

type Option func(*options) error

// WithCacheDir specifies a personalized daemon cache directory
func WithCacheDir(cacheDir string) func(o *options) error {
	return func(o *options) error {
		o.cacheDir = cacheDir
		return nil
	}
}

// WithRunDir specifies a personalized /run
func WithRunDir(runDir string) func(o *options) error {
	return func(o *options) error {
		o.runDir = runDir
		return nil
	}
}

// WithSSSCacheDir specifies which cache directory to use for SSS
func WithSSSCacheDir(cacheDir string) func(o *options) error {
	return func(o *options) error {
		o.sssCacheDir = cacheDir
		return nil
	}
}

//go:embed adsys-gpolist
var adsysGpoListCode string

// New returns an AD object to manage concurrency, with a local kr5 ticket from machine keytab
func New(ctx context.Context, url, domain string, opts ...Option) (ad *AD, err error) {
	defer decorate.OnError(&err, i18n.G("can't create Active Directory object"))

	versionID, err := adcommon.GetVersionID("/")
	if err != nil {
		return nil, err
	}

	// defaults
	args := options{
		runDir:      consts.DefaultRunDir,
		cacheDir:    consts.DefaultCacheDir,
		sssCacheDir: consts.DefaultSSSCacheDir,
		gpoListCmd:  []string{"python3", "-c", adsysGpoListCode},
		versionID:   versionID,
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
	gpoRulesCacheDir := filepath.Join(args.cacheDir, entry.GPORulesCacheBaseName)
	if err := os.MkdirAll(gpoRulesCacheDir, 0700); err != nil {
		return nil, err
	}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	// for misconfigured machines where /proc/sys/kernel/hostname returns the fqdn and not only the machine name, strip it
	hostname = strings.TrimSuffix(hostname, "."+domain)

	// local machine sssd krb5 cache
	sssCCName := filepath.Join(args.sssCacheDir, "ccache_"+strings.ToUpper(domain))

	return &AD{
		hostname:         hostname,
		url:              url,
		versionID:        args.versionID,
		gpoCacheDir:      gpoCacheDir,
		gpoRulesCacheDir: gpoRulesCacheDir,
		krb5CacheDir:     krb5CacheDir,
		sssCCName:        sssCCName,
		gpos:             make(map[string]*gpo),
		gpoListCmd:       args.gpoListCmd,
	}, nil
}

// GetPolicies returns all policy entries, stacked in order of priority.GetPolicies
// It lists them, check state in global local cache and then redownload if any new version is available.
// It users the given krb5 ticket reference to authenticate to AD.
// userKrb5CCName has no impact for computer object and is ignored. If empty, we will expect to find one cached
// ticket <krb5CCDir>/<objectName>.
func (ad *AD) GetPolicies(ctx context.Context, objectName string, objectClass ObjectClass, userKrb5CCName string) (r []entry.GPO, err error) {
	defer decorate.OnError(&err, i18n.G("can't get policies for %q"), objectName)

	log.Debugf(ctx, "GetPolicies for %q, type %q", objectName, objectClass)

	if objectClass == UserObject && !strings.Contains(objectName, "@") {
		return nil, fmt.Errorf(i18n.G("user name %q should be of the form %s@DOMAIN"), objectName, objectName)
	}

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
	userForGPOList := objectName
	if i := strings.LastIndex(userForGPOList, "@"); i > 0 {
		userForGPOList = userForGPOList[:i]
	}
	args := append([]string{}, ad.gpoListCmd...) // Copy gpoListCmd to prevent data race
	cmdArgs := append(args, "--objectclass", string(objectClass), ad.url, userForGPOList)
	// #nosec G204 - cmdArgs is under our control (python embedded script or mock for tests)
	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("KRB5CCNAME=%s", krb5CCPath))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	smbsafe.WaitExec()
	err = cmd.Run()
	smbsafe.DoneExec()
	if err != nil {
		if cmd.ProcessState.ExitCode() != 2 {
			return nil, fmt.Errorf(i18n.G("failed to retrieve the list of GPO: %v\n%s"), err, stderr.String())
		}

		// Exit status 2 is a network error (host of network unreadchable)
		// In this case we assume an offline connection and try to load the GPOs from cache
		// Otherwise we fail with an error.
		ad.Lock()
		ad.IsOffline = true
		ad.Unlock()
		if r, err = entry.NewGPOs(filepath.Join(ad.gpoRulesCacheDir, objectName)); err != nil {
			return nil, fmt.Errorf(i18n.G("machine is offline and GPO rules cache is unavailable: %v"), err)
		}

		log.Infof(ctx, "Can't reach AD: machine is offline and %q policies are applied using previous online update", objectName)
		return r, nil
	}

	ad.Lock()
	ad.IsOffline = false
	ad.Unlock()
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
	r, err = ad.parseGPOs(ctx, orderedGPOs, objectClass)
	if err != nil {
		return nil, err
	}

	return r, nil
}

// ListUsersFromCache return the list of active users on the system
func (ad *AD) ListUsersFromCache(ctx context.Context) (users []string, err error) {
	defer decorate.OnError(&err, i18n.G("can't list users from cache"))

	ad.Lock()
	defer ad.Unlock()

	files, err := os.ReadDir(ad.krb5CacheDir)
	if err != nil {
		return users, fmt.Errorf(i18n.G("failed to read cache directory: %v"), err)
	}

	for _, file := range files {
		if !strings.Contains(file.Name(), "@") {
			continue
		}
		users = append(users, file.Name())
	}
	return users, nil
}

// ensureKrb5CCName manages user ccname symlinks.
// It handles concurrent calls, and only recreate the symlink if we want to point to
// a new destination.
func (ad *AD) ensureKrb5CCName(srcKrb5CCName, dstKrb5CCName string) (err error) {
	defer decorate.OnError(&err, i18n.G("can't create symlink for caching"))

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

func (ad *AD) parseGPOs(ctx context.Context, gpos []gpo, objectClass ObjectClass) ([]entry.GPO, error) {
	var r []entry.GPO

	keyFilterPrefix := fmt.Sprintf("%s/%s/", adcommon.KeyPrefix, consts.DistroID)

	for _, g := range gpos {
		name, url := g.name, g.url
		gpoRules := entry.GPO{
			ID:    filepath.Base(url),
			Name:  name,
			Rules: make(map[string][]entry.Entry),
		}
		r = append(r, gpoRules)
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
				log.Debugf(ctx, "Policy %q doesn't have any policy for class %q %s", name, objectClass, err)
				return nil
			}
			defer decorate.LogFuncOnErrorContext(ctx, f.Close)

			// Decode and apply policies in gpo order. First win
			pols, err := registry.DecodePolicy(f)
			if err != nil {
				return fmt.Errorf(i18n.G("%s :%v"), f.Name(), err)
			}

			// filter keys to be overridden
			var currentKey string
			var overrideEnabled bool
			for _, pol := range pols {
				// Only consider supported policies for this distro
				if !strings.HasPrefix(pol.Key, keyFilterPrefix) {
					continue
				}
				pol.Key = strings.TrimPrefix(pol.Key, keyFilterPrefix)

				// Some keys can be overridden
				releaseID := filepath.Base(pol.Key)
				keyType := strings.Split(pol.Key, "/")[0]
				pol.Key = filepath.Dir(strings.TrimPrefix(pol.Key, keyType+"/"))

				if releaseID == "all" {
					currentKey = pol.Key
					overrideEnabled = false
					gpoRules.Rules[keyType] = append(gpoRules.Rules[keyType], pol)
					continue
				}

				// This is not an "all" key and the key name don’t match
				// This shouldn’t happen with our admx, but just to stay safe…
				if currentKey != pol.Key {
					continue
				}

				if strings.HasPrefix(releaseID, "Override"+ad.versionID) && pol.Value == "true" {
					overrideEnabled = true
					continue
				}
				// Check we have a matching override
				if !overrideEnabled || releaseID != ad.versionID {
					continue
				}

				// Matching enabled override
				// Replace value with the override content
				iLast := len(gpoRules.Rules[keyType]) - 1
				p := gpoRules.Rules[keyType][iLast]
				p.Value = pol.Value
				gpoRules.Rules[keyType][iLast] = p
			}
			return nil
		}(); err != nil {
			return nil, err
		}
	}

	return r, nil
}

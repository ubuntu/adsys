package ad

import (
	"bufio"
	"bytes"
	"context"
	// embed gpolist python binary.
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	adcommon "github.com/ubuntu/adsys/internal/ad/common"
	"github.com/ubuntu/adsys/internal/ad/registry"
	"github.com/ubuntu/adsys/internal/consts"
	"github.com/ubuntu/adsys/internal/decorate"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/smbsafe"
	"golang.org/x/sync/errgroup"
)

// ObjectClass is the type of object in the directory. It can be a computer or a user.
type ObjectClass string

const (
	// UserObject is a user representation in AD.
	UserObject ObjectClass = "user"
	// ComputerObject is a computer representation in AD.
	ComputerObject = "computer"
)

type gpo downloadable

type downloadable struct {
	name     string
	url      string
	mu       *sync.RWMutex
	isAssets bool

	// This property is used to instrument the tests for concurrent download and parsing of GPOs
	// Cf internal_test::TestFetchOneGPOWhileParsingItConcurrently()
	testConcurrent bool
}

// AD structure to manage call concurrency.
type AD struct {
	isOffline bool

	hostname            string
	url                 string
	defaultDomainSuffix string

	versionID        string
	sysvolCacheDir   string
	policiesCacheDir string
	krb5CacheDir     string
	sssCCName        string

	sssdDbus dbus.BusObject

	downloadables map[string]*downloadable
	sync.RWMutex
	fetchMu sync.Mutex

	withoutKerberos bool
	gpoListCmd      []string
}

type options struct {
	versionID           string
	runDir              string
	cacheDir            string
	sssCacheDir         string
	defaultDomainSuffix string
	withoutKerberos     bool
	gpoListCmd          []string
}

// Option reprents an optional function to change AD behavior.
type Option func(*options) error

// WithCacheDir specifies a personalized daemon cache directory.
func WithCacheDir(cacheDir string) Option {
	return func(o *options) error {
		o.cacheDir = cacheDir
		return nil
	}
}

// WithRunDir specifies a personalized /run.
func WithRunDir(runDir string) Option {
	return func(o *options) error {
		o.runDir = runDir
		return nil
	}
}

// WithSSSCacheDir specifies which cache directory to use for SSS.
func WithSSSCacheDir(cacheDir string) Option {
	return func(o *options) error {
		o.sssCacheDir = cacheDir
		return nil
	}
}

// WithDefaultDomainSuffix specifies a default domain suffix we provide.
func WithDefaultDomainSuffix(defaultDomainSuffix string) Option {
	return func(o *options) error {
		o.defaultDomainSuffix = defaultDomainSuffix
		return nil
	}
}

// AdsysGpoListCode is the embedded script which request
// Samba to get our GPO list for the given object.
//go:embed adsys-gpolist
var AdsysGpoListCode string

// New returns an AD object to manage concurrency, with a local kr5 ticket from machine keytab.
func New(ctx context.Context, url, domain string, bus *dbus.Conn, opts ...Option) (ad *AD, err error) {
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
		gpoListCmd:  []string{"python3", "-c", AdsysGpoListCode},
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
	sysvolCacheDir := filepath.Join(args.cacheDir, "sysvol")
	// Create Policies subdirectory under sysvol
	if err := os.MkdirAll(filepath.Join(sysvolCacheDir, "Policies"), 0700); err != nil {
		return nil, err
	}
	policiesCacheDir := filepath.Join(args.cacheDir, policies.PoliciesCacheBaseName)
	if err := os.MkdirAll(policiesCacheDir, 0700); err != nil {
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

	sssdDbus := bus.Object(consts.SSSDDbusRegisteredName,
		dbus.ObjectPath(filepath.Join(consts.SSSDDbusBaseObjectPath, strings.ReplaceAll(domain, ".", "_2e"))))

	if url != "" && !strings.HasPrefix(url, "ldap://") {
		url = fmt.Sprintf("ldap://%s", url)
	}

	return &AD{
		hostname:            hostname,
		url:                 url,
		defaultDomainSuffix: args.defaultDomainSuffix,
		versionID:           args.versionID,
		sysvolCacheDir:      sysvolCacheDir,
		policiesCacheDir:    policiesCacheDir,
		krb5CacheDir:        krb5CacheDir,
		sssCCName:           sssCCName,
		sssdDbus:            sssdDbus,
		downloadables:       make(map[string]*downloadable),
		gpoListCmd:          args.gpoListCmd,
	}, nil
}

// GetPolicies returns all policy entries, stacked in order of priority.GetPolicies
// It lists them, check state in global local cache and then redownload if any new version is available.
// It uses the given krb5 ticket reference to authenticate to AD.
// userKrb5CCName has no impact for computer object and is ignored. If empty, we will expect to find one cached
// ticket <krb5CCDir>/<objectName>.
// The GPOs are returned from the highest priority in the hierarchy, with enforcement in reverse order
// to the lowest priority.
func (ad *AD) GetPolicies(ctx context.Context, objectName string, objectClass ObjectClass, userKrb5CCName string) (pols policies.Policies, err error) {
	defer decorate.OnError(&err, i18n.G("can't get policies for %q"), objectName)

	log.Debugf(ctx, "GetPolicies for %q, type %q", objectName, objectClass)

	if objectClass == UserObject && !strings.Contains(objectName, "@") {
		return pols, fmt.Errorf(i18n.G("user name %q should be of the form %s@DOMAIN"), objectName, objectName)
	}

	krb5CCPath := filepath.Join(ad.krb5CacheDir, objectName)
	if objectClass == ComputerObject && objectName != ad.hostname {
		return pols, fmt.Errorf(i18n.G("requested a type computer of %q which isn't current host %q"), objectName, ad.hostname)
	}
	// Create a ccache symlink on first fetch for futur calls (on refresh for instance)
	if userKrb5CCName != "" || objectClass == ComputerObject {
		src := userKrb5CCName
		// there is no env var for machine: get sss ccache
		if objectClass == ComputerObject {
			src = ad.sssCCName
		}
		if err := ad.ensureKrb5CCName(src, krb5CCPath); err != nil {
			return pols, err
		}
	}

	var online bool
	if err := ad.sssdDbus.Call(consts.SSSDDbusInterface+".IsOnline", 0).Store(&online); err != nil {
		return pols, fmt.Errorf(i18n.G("failed to retrieve offline state from SSSD: %v"), err)
	}
	ad.Lock()
	ad.isOffline = !online
	ad.Unlock()

	// If sssd returns that we are offline, returns the cache list of GPOs if present
	if !online {
		var cachedPolicies policies.Policies
		if cachedPolicies, err = policies.NewFromCache(ctx, filepath.Join(ad.policiesCacheDir, objectName)); err != nil {
			return cachedPolicies, fmt.Errorf(i18n.G("machine is offline and policies cache is unavailable: %v"), err)
		}

		log.Infof(ctx, "Can't reach AD: machine is offline and %q policies are applied using previous online update", objectName)
		return cachedPolicies, nil
	}

	// We need an AD LDAP url to connect to
	adServerURL, _ := ad.GetStatus()
	if adServerURL == "" {
		log.Debug(ctx, "Triggering autodiscovery of AD server triggered because sssd.conf or manual url not provided")
		// Try to update from SSSD the current active AD server
		msg := i18n.G("error while trying to look up AD server address on SSSD")
		err := ad.sssdDbus.Call(consts.SSSDDbusInterface+".ActiveServer", 0, "AD").Store(&adServerURL)
		if err != nil {
			return pols, fmt.Errorf(i18n.G("%s: %v"), msg, err)
		}
		if adServerURL == "" {
			return pols, fmt.Errorf(i18n.G("%s: no active server found"), msg)
		}
		if !strings.HasPrefix(adServerURL, "ldap://") {
			adServerURL = fmt.Sprintf("ldap://%s", adServerURL)
		}
		ad.Lock()
		ad.url = adServerURL
		ad.Unlock()
	}

	// Otherwise, try fetching the GPO list from LDAP
	args := append([]string{}, ad.gpoListCmd...) // Copy gpoListCmd to prevent data race
	scriptArgs := []string{"--objectclass", string(objectClass), adServerURL, objectName}
	cmdArgs := append(args, scriptArgs...)
	cmdCtx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	log.Debugf(ctx, "Getting gpo list with arguments: %q", strings.Join(scriptArgs, " "))
	// #nosec G204 - cmdArgs is under our control (python embedded script or mock for tests)
	cmd := exec.CommandContext(cmdCtx, cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("KRB5CCNAME=%s", krb5CCPath))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	smbsafe.WaitExec()
	err = cmd.Run()
	smbsafe.DoneExec()
	if err != nil {
		return pols, fmt.Errorf(i18n.G("failed to retrieve the list of GPO (exited with %d): %v\n%s"), cmd.ProcessState.ExitCode(), err, stderr.String())
	}

	downloadables := make(map[string]string)
	var orderedGPOs []gpo
	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		t := scanner.Text()
		res := strings.SplitN(t, "\t", 2)
		gpoName, gpoURL := res[0], res[1]
		log.Debugf(ctx, "GPO %q for %q available at %q", gpoName, objectName, gpoURL)
		downloadables[gpoName] = gpoURL
		orderedGPOs = append(orderedGPOs, gpo{name: gpoName, url: gpoURL})

		if _, ok := downloadables["assets"]; ok {
			continue
		}
		u, err := url.Parse(gpoURL)
		if err != nil {
			return pols, err
		}
		// Assets are in <root>/DistroID, while GPOs are in <root>/Policies/<gpoName>
		u.Path = filepath.Join(filepath.Dir(filepath.Dir(u.Path)), consts.DistroID)
		downloadables["assets"] = u.String()
	}
	if err := scanner.Err(); err != nil {
		return pols, err
	}

	ad.Lock()
	defer ad.Unlock()
	assetsWereRefresh, err := ad.fetch(ctx, krb5CCPath, downloadables)
	if err != nil {
		return pols, err
	}

	var errg errgroup.Group
	// Parse policies
	var gposRules []policies.GPO
	errg.Go(func() (err error) {
		gposRules, err = ad.parseGPOs(ctx, orderedGPOs, objectClass)
		return err
	})

	// Compress assets
	var assetsDbPath string
	assetsSrc := filepath.Join(ad.sysvolCacheDir, "assets")
	errg.Go(func() (err error) {
		// Only compress assets if we have fetched them, otherwise attach optionally
		// existing db.
		if !assetsWereRefresh {
			db := filepath.Join(assetsSrc + ".db")
			if _, err := os.Stat(db); errors.Is(err, os.ErrNotExist) {
				return nil
			} else if err != nil {
				return err
			}
			assetsDbPath = db
			return nil
		}
		// check assetsSrc exists
		_, err = os.Stat(assetsSrc)
		if errors.Is(err, fs.ErrNotExist) {
			if err := os.Remove(filepath.Join(assetsSrc + ".db")); err != nil {
				return err
			}
			return nil
		} else if err != nil {
			return err
		}

		// Cache it as a single zip file
		if err := policies.CompressAssets(ctx, assetsSrc); err != nil {
			return err
		}

		assetsDbPath = filepath.Join(assetsSrc + ".db")

		return nil
	})

	if err := errg.Wait(); err != nil {
		return pols, fmt.Errorf("one or more error while parsing downloaded elements: %w", err)
	}

	return policies.New(ctx, gposRules, assetsDbPath)
}

// ListActiveUsers return the list of active users on the system.
func (ad *AD) ListActiveUsers(ctx context.Context) (users []string, err error) {
	defer decorate.OnError(&err, i18n.G("can't list users from cache"))

	log.Debug(ctx, "ListActiveUsers")

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

func (ad *AD) parseGPOs(ctx context.Context, gpos []gpo, objectClass ObjectClass) (r []policies.GPO, err error) {
	keyFilterPrefix := fmt.Sprintf("%s/%s/", adcommon.KeyPrefix, consts.DistroID)

	for _, g := range gpos {
		name, url := g.name, g.url
		gpoWithRules := policies.GPO{
			ID:    filepath.Base(url),
			Name:  name,
			Rules: make(map[string][]entry.Entry),
		}
		r = append(r, gpoWithRules)
		if err := func() error {
			ad.downloadables[name].mu.RLock()
			defer ad.downloadables[name].mu.RUnlock()
			_ = ad.downloadables[name].testConcurrent

			log.Debugf(ctx, "Parsing GPO %q", name)

			class := "User"
			if objectClass == ComputerObject {
				class = "Machine"
			}
			f, err := os.Open(filepath.Join(ad.sysvolCacheDir, "Policies", filepath.Base(url), class, "Registry.pol"))
			if errors.Is(err, fs.ErrExist) {
				return err
			} else if errors.Is(err, fs.ErrNotExist) {
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
					gpoWithRules.Rules[keyType] = append(gpoWithRules.Rules[keyType], pol)
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
				iLast := len(gpoWithRules.Rules[keyType]) - 1
				p := gpoWithRules.Rules[keyType][iLast]
				p.Value = pol.Value
				gpoWithRules.Rules[keyType][iLast] = p
			}
			return nil
		}(); err != nil {
			return r, err
		}
	}

	return r, nil
}

// GetStatus returns dynamic part of our AD instance like offline state and active server for AD ldap.
func (ad *AD) GetStatus() (adServerURL string, isOffline bool) {
	ad.RLock()
	defer ad.RUnlock()
	return ad.url, ad.isOffline
}

// NormalizeTargetName transform user or domain\user as user@domain.
// If no domain is provided, we rely on having a default domain policy.
func (ad *AD) NormalizeTargetName(ctx context.Context, target string, objectClass ObjectClass) (string, error) {
	log.Debugf(ctx, "NormalizeTargetName for %q, type %q", target, objectClass)

	if objectClass == ComputerObject {
		return target, nil
	}
	// If we don’t know if this is a computer, try to ensure first this is not our hostname
	// (or consider this without explicitly being specified)
	if objectClass == "" && target == ad.hostname {
		return target, nil
	}

	// Otherwise, consider it as a user and try to transform it
	if strings.Contains(target, "@") {
		return target, nil
	}

	var domainSuffix, baseUser string
	switch c := strings.Split(target, `\`); len(c) {
	case 2:
		domainSuffix, baseUser = c[0], c[1]
	case 1:
		baseUser = c[0]
	default:
		return "", fmt.Errorf(i18n.G(`only one \ is permitted in domain\username. Got: %s`), target)
	}
	if domainSuffix == "" && ad.defaultDomainSuffix == "" {
		return "", fmt.Errorf(i18n.G(`no domain provided for user %q and no default domain in sssd.conf`), target)
	}
	if domainSuffix == "" {
		domainSuffix = ad.defaultDomainSuffix
	}

	target = fmt.Sprintf("%s@%s", baseUser, domainSuffix)
	log.Debugf(ctx, "Target name normalized to %q", target)
	return target, nil
}

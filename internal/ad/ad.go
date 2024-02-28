// Package ad is responsible for the Active Directory connection to parse what to apply to each user/machine,
// get the URL and permissions on what to fetch, downloads GPOs policy files and assets.
//
// It has a cache policy to avoid unnecessary downloads.
package ad

import (
	"bufio"
	"bytes"
	"context"
	_ "embed" // embed gpolist python binary.
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

	"github.com/leonelquinteros/gotext"
	"github.com/ubuntu/adsys/internal/ad/backends"
	adcommon "github.com/ubuntu/adsys/internal/ad/common"
	"github.com/ubuntu/adsys/internal/ad/registry"
	"github.com/ubuntu/adsys/internal/consts"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/policies"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/smbsafe"
	"github.com/ubuntu/decorate"
	"golang.org/x/sync/errgroup"
)

// ObjectClass is the type of object in the directory. It can be a computer or a user.
type ObjectClass string

const (
	// UserObject is a user representation in AD.
	UserObject ObjectClass = "user"
	// ComputerObject is a computer representation in AD.
	ComputerObject ObjectClass = "computer"

	// certAutoEnrollKey is the GPO entry that configures certificate autoenrollment.
	certAutoEnrollKey string = "Software/Policies/Microsoft/Cryptography/AutoEnrollment/AEPolicy"

	// policyServerPrefix is the GPO prefix containing keys that configure
	// policy servers for certificate enrollment.
	policyServersPrefix string = "Software/Policies/Microsoft/Cryptography/PolicyServers/"
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
	hostname      string
	configBackend backends.Backend

	versionID        string
	sysvolCacheDir   string
	policiesCacheDir string
	krb5CacheDir     string

	downloadables map[string]*downloadable
	sync.RWMutex
	fetchMu sync.Mutex

	withoutKerberos bool
	gpoListCmd      []string
	gpoListTimeout  time.Duration
}

type options struct {
	versionID string
	runDir    string
	cacheDir  string

	withoutKerberos bool
	gpoListCmd      []string
	gpoListTimeout  time.Duration
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

// WithGpoListTimeout specifies a custom timeout for the adsys-gpolist command.
func WithGpoListTimeout(timeout time.Duration) Option {
	return func(o *options) error {
		o.gpoListTimeout = timeout
		return nil
	}
}

// AdsysGpoListCode is the embedded script which request
// Samba to get our GPO list for the given object.
//
//go:embed adsys-gpolist
var AdsysGpoListCode string

// New returns an AD object to manage concurrency, with a local kr5 ticket from machine keytab.
func New(ctx context.Context, configBackend backends.Backend, hostname string, opts ...Option) (ad *AD, err error) {
	defer decorate.OnError(&err, gotext.Get("can't create Active Directory object"))

	versionID, err := adcommon.GetVersionID("/")
	if err != nil {
		return nil, err
	}

	// defaults
	args := options{
		runDir:         consts.DefaultRunDir,
		cacheDir:       consts.DefaultCacheDir,
		gpoListCmd:     []string{"python3", "-c", AdsysGpoListCode},
		versionID:      versionID,
		gpoListTimeout: 30 * time.Second, // this is used in tests and set to consts.DefaultGpoListTimeout in production
	}
	// applied options
	for _, o := range opts {
		if err := o(&args); err != nil {
			return nil, err
		}
	}

	krb5CacheDir := filepath.Join(args.runDir, "krb5cc")
	if err := os.MkdirAll(filepath.Join(krb5CacheDir, "tracking"), 0700); err != nil {
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

	domain := configBackend.Domain()
	serverFQDN, err := configBackend.ServerFQDN(ctx)
	if err != nil && !errors.Is(err, backends.ErrNoActiveServer) {
		return nil, errors.New(gotext.Get("can't get current Server FQDN: %v", err))
	}
	log.Debugf(ctx, "Backend is SSSD. AD domain: %q, server from configuration: %q", domain, serverFQDN)

	return &AD{
		hostname:         hostname,
		configBackend:    configBackend,
		versionID:        args.versionID,
		sysvolCacheDir:   sysvolCacheDir,
		policiesCacheDir: policiesCacheDir,
		krb5CacheDir:     krb5CacheDir,

		downloadables:  make(map[string]*downloadable),
		gpoListCmd:     args.gpoListCmd,
		gpoListTimeout: args.gpoListTimeout,
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
	defer decorate.OnError(&err, gotext.Get("can't get policies for %q", objectName))

	log.Debugf(ctx, "GetPolicies for %q, type %q", objectName, objectClass)

	if objectClass == UserObject && !strings.Contains(objectName, "@") {
		return pols, errors.New(gotext.Get("user name %q should be of the form %s@DOMAIN", objectName, objectName))
	}

	if objectClass == ComputerObject && objectName != ad.hostname {
		return pols, errors.New(gotext.Get("requested a type computer of %q which isn't current host %q", objectName, ad.hostname))
	}

	krb5CCPath := filepath.Join(ad.krb5CacheDir, objectName)
	krb5CCSymlink := filepath.Join(ad.krb5CacheDir, "tracking", objectName)
	// Create a ccache symlink on first fetch for future calls (on refresh for instance)
	if userKrb5CCName != "" || objectClass == ComputerObject {
		src := userKrb5CCName
		// there is no env var for machine: get sss ccache
		if objectClass == ComputerObject {
			src, err = ad.configBackend.HostKrb5CCName()
			if err != nil {
				return pols, err
			}
		}

		// Create a symlink to the ccache file
		if err := ad.ensureKrb5CCSymlink(src, krb5CCSymlink); err != nil {
			return pols, err
		}
	}

	// Ensure we have an up-to-date copy of the ccache file
	if err := ad.ensureKrb5CCCopy(krb5CCSymlink, krb5CCPath); err != nil {
		return pols, err
	}

	var online bool
	if online, err = ad.configBackend.IsOnline(); err != nil {
		return pols, err
	}

	// If sssd returns that we are offline, returns the cache list of GPOs if present
	if !online {
		var cachedPolicies policies.Policies
		if cachedPolicies, err = policies.NewFromCache(ctx, filepath.Join(ad.policiesCacheDir, objectName)); err != nil {
			return cachedPolicies, errors.New(gotext.Get("machine is offline and policies cache is unavailable: %v", err))
		}

		log.Infof(ctx, "Can't reach AD: machine is offline and %q policies are applied using previous online update", objectName)
		return cachedPolicies, nil
	}

	// We need an AD DC to connect to
	adServerFQDN, err := ad.configBackend.ServerFQDN(ctx)
	if err != nil {
		return policies.Policies{}, errors.New(gotext.Get("can't get current Server FQDN: %v", err))
	}

	// Otherwise, try fetching the GPO list from LDAP
	args := append([]string{}, ad.gpoListCmd...) // Copy gpoListCmd to prevent data race
	scriptArgs := []string{"--objectclass", string(objectClass), adServerFQDN, objectName}
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
		return pols, errors.New(gotext.Get("failed to retrieve the list of GPO (exited with %d): %v\n%s", cmd.ProcessState.ExitCode(), err, stderr.String()))
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

// ListUsers returns the list of users on the system based on their cached policy information.
// If active is true, the list of users is retrieved from the cached Kerberos ticket information.
func (ad *AD) ListUsers(ctx context.Context, active bool) (users []string, err error) {
	defer decorate.OnError(&err, gotext.Get("can't list users from cache"))

	log.Debug(ctx, "ListUsers")

	ad.Lock()
	defer ad.Unlock()

	cacheDir := ad.policiesCacheDir
	if active {
		cacheDir = filepath.Join(ad.krb5CacheDir, "tracking")
	}

	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return users, errors.New(gotext.Get("failed to read cache directory: %v", err))
	}

	for _, entry := range entries {
		if !strings.Contains(entry.Name(), "@") {
			continue
		}

		// Silently skip over dangling symlinks
		if active {
			if _, err := os.Stat(filepath.Join(cacheDir, entry.Name())); err != nil && errors.Is(err, fs.ErrNotExist) {
				continue
			}
		}
		users = append(users, entry.Name())
	}
	return users, nil
}

// ensureKrb5CCSymlink manages user ccname ticket symlinks.
// It handles concurrent calls, and works by creating a symlink to the
// actual ticket for tracking purposes.
// It only recreates the symlink if we want to point to a new destination.
func (ad *AD) ensureKrb5CCSymlink(srcKrb5CCName, dstKrb5CCName string) error {
	ad.Lock()
	defer ad.Unlock()

	srcKrb5CCName, err := filepath.Abs(srcKrb5CCName)
	if err != nil {
		return errors.New(gotext.Get("can't get absolute path of ccname to symlink to: %v", err))
	}

	src, err := os.Readlink(dstKrb5CCName)
	if err == nil {
		// All set, don’t recreate the symlink.
		if src == srcKrb5CCName {
			return nil
		}
		// Delete the symlink to create a new one.
		if err := os.Remove(dstKrb5CCName); err != nil {
			return errors.New(gotext.Get("failed to remove existing symlink: %v", err))
		}
	}

	if err := os.MkdirAll(filepath.Dir(dstKrb5CCName), 0700); err != nil {
		return errors.New(gotext.Get("failed to create parent directory for symlink: %v", err))
	}

	if err := os.Symlink(srcKrb5CCName, dstKrb5CCName); err != nil {
		return err
	}
	return nil
}

// ensureKrb5CCCopy checks if the cached krb5cc ticket is up to date and updates
// it if not.
// The file ownership is changed to the calling user (root) in order to satisfy
// the Heimdal implementation of Kerberos.
// To track modifications to the krb5cc file we look at the mtime of the
// original ticket and keep it up to date with
// the copy.
func (ad *AD) ensureKrb5CCCopy(krb5CCSymlink, krb5CCCopyName string) error {
	ad.Lock()
	defer ad.Unlock()

	krb5CCSrc, err := os.Readlink(krb5CCSymlink)
	if err != nil {
		return errors.New(gotext.Get("failed to read krb5cc symlink: %v", err))
	}

	if copyStat, err := os.Lstat(krb5CCCopyName); err == nil && copyStat.Mode()&os.ModeSymlink == 0 {
		// We already have a copy of the ticket, let's check if we need to update it
		srcStat, err := os.Stat(krb5CCSrc)
		if err != nil {
			return errors.New(gotext.Get("failed to stat source ticket: %v", err))
		}

		// The source ticket is not newer than the destination one, no need to update
		if !srcStat.ModTime().After(copyStat.ModTime()) {
			return nil
		}
	}

	// The ticket is either not present or outdated, let's update it
	// Copy the ticket
	if err := safeCopyFile(krb5CCSrc, krb5CCCopyName, 0600); err != nil {
		return err
	}

	return nil
}

// safeCopyFile copies a file from src to dst, using the specified mode.
// It first writes to a temporary file in the same directory as dst, then
// renames it to dst, ensuring the write is atomic.
func safeCopyFile(src, dst string, mode os.FileMode) error {
	content, err := os.ReadFile(src)
	if err != nil {
		return errors.New(gotext.Get("failed to read source file: %v", err))
	}
	if err := os.WriteFile(dst+".new", content, mode); err != nil {
		return err
	}

	return os.Rename(dst+".new", dst)
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

			// We need to consider the uppercase version of the name as well,
			// which could occur in some of the default GPOs such as Default
			// Domain Policy.
			classes := []string{"User", "USER"}
			if objectClass == ComputerObject {
				classes = []string{"Machine", "MACHINE"}
			}

			var err error
			var f *os.File
			for _, class := range classes {
				var e error
				f, e = os.Open(filepath.Join(ad.sysvolCacheDir, "Policies", filepath.Base(url), class, "Registry.pol"))

				// We only care about the first error which is caused by opening
				// the capitalized version of the class, instead of the
				// uppercase version which is less common and more of an edge case.
				if e != nil && err == nil {
					err = e
				} else if e == nil {
					err = nil
					break
				}
			}

			if errors.Is(err, fs.ErrNotExist) {
				log.Debugf(ctx, "Policy %q doesn't have any policy for class %q %s", name, objectClass, err)
				return nil
			} else if err != nil {
				return err
			}
			defer decorate.LogFuncOnErrorContext(ctx, f.Close)

			// Decode and apply policies in gpo order. First win
			pols, err := registry.DecodePolicy(f)
			if err != nil {
				return errors.New(gotext.Get("%s: %v", f.Name(), err))
			}

			// filter keys to be overridden
			var currentKey string
			var overrideEnabled bool
			for _, pol := range pols {
				// Rewrite the certificate autoenrollment key so we can easily
				// use it in the policy manager
				if pol.Key == certAutoEnrollKey {
					pol.Key = fmt.Sprintf("%scertificate/autoenroll/all", keyFilterPrefix)
				}

				if strings.HasPrefix(pol.Key, policyServersPrefix) {
					pol.Key = fmt.Sprintf("%scertificate/%s/all", keyFilterPrefix, pol.Key)
				}

				// Only consider supported policies for this distro
				if !strings.HasPrefix(pol.Key, keyFilterPrefix) {
					continue
				}
				if pol.Err != nil {
					return errors.New(gotext.Get("%s: %v", f.Name(), pol.Err))
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

// GetInfo returns all information from the selected backend: static and dynamic part.
func (ad *AD) GetInfo(ctx context.Context) (msg string) {
	// static part
	config := ad.configBackend.Config()

	// dynamic info
	var online string
	if isOnline, err := ad.configBackend.IsOnline(); err != nil {
		log.Warning(ctx, err)
		online = fmt.Sprint(gotext.Get("**Can't check if we have an active connection**\n"))
	} else if !isOnline {
		online = fmt.Sprint(gotext.Get("**Offline mode** using cached policies\n"))
	}
	domain := ad.configBackend.Domain()
	server, err := ad.configBackend.ServerFQDN(ctx)
	if err != nil {
		server = "Unknown"
	}

	return gotext.Get("%s\n%sDomain: %s\nServer FQDN: %s", config, online, domain, server)
}

// NormalizeTargetName transforms the specified target to values adsys knows.
// User: transforms and lowercases User or DOMAIN\User to user@domain.
// Computer: strips the FQDN part, if it exists, and lowercases it.
// If no domain is provided, we rely on having a default domain policy.
func (ad *AD) NormalizeTargetName(ctx context.Context, target string, objectClass ObjectClass) (string, error) {
	log.Debugf(ctx, "NormalizeTargetName for %q, type %q", target, objectClass)

	// Lowercase the target name to ensure we don't pollute the Linux
	// case-sensitive filesystem with multiple files based on the case of the
	// target.
	target = strings.ToLower(target)

	if objectClass == ComputerObject {
		// For misconfigured machines where /proc/sys/kernel/hostname returns the fqdn and not only the machine name, strip it
		target, _, _ = strings.Cut(target, ".")
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
		return "", errors.New(gotext.Get(`only one \ is permitted in domain\username. Got: %s`, target))
	}
	if domainSuffix == "" && ad.configBackend.DefaultDomainSuffix() == "" {
		return "", errors.New(gotext.Get(`no domain provided for user %q and no default domain in sssd.conf`, target))
	}
	if domainSuffix == "" {
		domainSuffix = ad.configBackend.DefaultDomainSuffix()
	}

	target = fmt.Sprintf("%s@%s", baseUser, domainSuffix)
	log.Debugf(ctx, "Target name normalized to %q", target)
	return target, nil
}

// Hostname returns the normalized hostname of the current client.
func (ad *AD) Hostname() string {
	return ad.hostname
}

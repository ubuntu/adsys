// Package apparmor provides a manager to apply apparmor policies.
package apparmor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ubuntu/adsys/internal/consts"
	"github.com/ubuntu/adsys/internal/decorate"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"golang.org/x/exp/slices"
)

// WithApparmorParserCmd overrides the default apparmor_parser command.
func WithApparmorParserCmd(cmd []string) Option {
	return func(o *options) {
		o.apparmorParserCmd = cmd
	}
}

// WithApparmorFsDir specifies a personalized directory for the apparmor
// security filesystem.
func WithApparmorFsDir(path string) Option {
	return func(o *options) {
		o.apparmorFsDir = path
	}
}

// Manager prevents running multiple apparmor update processes in parallel while parsing policy in ApplyPolicy.
type Manager struct {
	apparmorDir        string
	apparmorCacheDir   string
	apparmorParserCmd  []string
	loadedPoliciesFile string

	muMu    sync.Mutex             // protect pathsMu
	pathsMu map[string]*sync.Mutex // mutex is per destination path (e.g. machine, users/user1, users/user2)
}

type options struct {
	apparmorParserCmd []string
	apparmorFsDir     string
}

// Option reprents an optional function to change the apparmor manager.
type Option func(*options)

// New creates a manager with a specific apparmor directory.
func New(apparmorDir string, opts ...Option) *Manager {
	// defaults
	args := options{
		apparmorParserCmd: []string{"apparmor_parser"},
		apparmorFsDir:     "/sys/kernel/security/apparmor",
	}
	// applied options
	for _, o := range opts {
		o(&args)
	}

	return &Manager{
		pathsMu:            make(map[string]*sync.Mutex),
		apparmorDir:        apparmorDir,
		apparmorCacheDir:   filepath.Join(consts.DefaultCacheDir, "apparmor"),
		apparmorParserCmd:  args.apparmorParserCmd,
		loadedPoliciesFile: filepath.Join(args.apparmorFsDir, "profiles"),
	}
}

// AssetsDumper is a function which uncompress policies assets to a directory.
type AssetsDumper func(ctx context.Context, relSrc, dest string, uid int, gid int) (err error)

// ApplyPolicy generates an apparmor policy based on a list of entries.
// Common scenario steps:
// 1.  Get the list of loaded apparmor policies
// 2.  Create /etc/apparmor.d/adsys/<object>.new with new policy
// 3a. Move /etc/apparmor.d/adsys/<object> to /etc/apparmor.d/adsys/<object>.old
// 3b. Move /etc/apparmor.d/adsys/<object>.new to /etc/apparmor.d/adsys/<object>
// 4.  Get the new list of apparmor policies
// 5.  Compute difference between old and new list of policies, unloading the removed ones if needed
// 6.  Run apparmor_parser -r -W -L /var/cache/adsys/apparmor on all files in /etc/apparmor.d/adsys/<object>
// 7a. If apparmor_parser fails, move /etc/apparmor.d/adsys/<object>.old to /etc/apparmor.d/adsys/<object>
// 7b. If apparmor_parser succeeds, remove /etc/apparmor.d/adsys/<object>.old.
func (m *Manager) ApplyPolicy(ctx context.Context, objectName string, isComputer bool, entries []entry.Entry, assetsDumper AssetsDumper) (err error) {
	defer decorate.OnError(&err, i18n.G("can't apply apparmor policy to %s"), objectName)

	objectDir := "machine"
	// TODO: add user support
	if !isComputer {
		// objectDir = "users"
		log.Warningf(ctx, i18n.G("Apparmor policies are currently only supported for computers"))
		return nil
	}
	apparmorPath := filepath.Join(m.apparmorDir, objectDir)

	// Mutex is per destination path (e.g. machine, users/user1, users/user2)
	m.muMu.Lock()
	// if mutex does not exist for this destination, creates it
	if _, exists := m.pathsMu[apparmorPath]; !exists {
		m.pathsMu[apparmorPath] = &sync.Mutex{}
	}
	m.muMu.Unlock()
	m.pathsMu[apparmorPath].Lock()
	defer m.pathsMu[apparmorPath].Unlock()

	// No point in continuing if apparmor isn't available
	absPath, err := exec.LookPath(m.apparmorParserCmd[0])
	if err != nil {
		// If we do have entries to apply we should explicitly fail
		if len(entries) > 0 {
			return err
		}
		// Otherwise, just let the user know
		log.Warningf(ctx, i18n.G("Apparmor is not available on this system: %v"), err)
		return nil
	}
	m.apparmorParserCmd[0] = absPath

	// If we have no entries, attempt to unload them and remove the apparmor directory
	if len(entries) == 0 {
		return m.unloadAllRules(ctx, apparmorPath)
	}

	log.Debugf(ctx, i18n.G("Applying apparmor policy to %s"), objectName)

	// Return early if we cannot find a valid policy entry
	idx := slices.IndexFunc(entries, func(e entry.Entry) bool { return e.Key == "apparmor-machine" })
	if idx == -1 {
		log.Warning(ctx, i18n.G("No valid entry found for the apparmor machine policy"))
		return nil
	}

	if err := os.MkdirAll(apparmorPath, 0750); err != nil {
		return fmt.Errorf(i18n.G("can't create apparmor directory %q: %v"), apparmorPath, err)
	}

	existingProfiles, err := filesInDir(apparmorPath)
	if err != nil {
		return err
	}

	// Get the currently loaded list of policies
	prevLoadedPolicies, err := m.loadedPolicies()
	if err != nil {
		return err
	}
	// Get the list of policies on the filesystem
	prevPolicies, err := m.policiesFromFiles(ctx, existingProfiles)
	if err != nil {
		return err
	}
	// Compute the intersection to determine which policies are actively loaded
	prevPolicies = intersection(prevPolicies, prevLoadedPolicies)

	// Remove any existing stale directories
	oldApparmorPath := apparmorPath + ".old"
	if err := os.RemoveAll(oldApparmorPath); err != nil {
		return fmt.Errorf(i18n.G("can't remove old apparmor directory %q: %v"), oldApparmorPath, err)
	}
	newApparmorPath := apparmorPath + ".new"
	if err := os.RemoveAll(newApparmorPath); err != nil {
		return fmt.Errorf(i18n.G("can't remove new apparmor directory %q: %v"), newApparmorPath, err)
	}

	// Dump assets to the adsys/machine.new/ subdirectory with correct
	// ownership. If no assets is present while entries != nil, we want to
	// return an error.
	if err := assetsDumper(ctx, "apparmor/", newApparmorPath, -1, -1); err != nil {
		return err
	}

	// Rename existing apparmor policy to .old
	if err := os.Rename(apparmorPath, oldApparmorPath); err != nil {
		return fmt.Errorf(i18n.G("can't rename apparmor directory %q to %q: %v"), apparmorPath, oldApparmorPath, err)
	}
	defer cleanupOldApparmorDir(ctx, oldApparmorPath, apparmorPath)

	// Rename new apparmor policy to current
	if err := os.Rename(newApparmorPath, apparmorPath); err != nil {
		return fmt.Errorf(i18n.G("can't rename apparmor directory %q to %q: %v"), newApparmorPath, apparmorPath, err)
	}

	e := entries[idx]
	// Get the list of files to run apparmor_parser on
	filesToLoad, err := filesFromEntry(e, apparmorPath)
	if err != nil {
		return err
	}

	// Clean up dumped asset files that are not in the policy entry
	if err := removeUnusedAssets(apparmorPath, filesToLoad); err != nil {
		return err
	}

	// Get the new list of policies
	newPolicies, err := m.policiesFromFiles(ctx, filesToLoad)
	if err != nil {
		return err
	}

	// Compute difference between the prevPolicies and newPolicies slices,
	// removing policies that are no longer needed
	policiesToUnload := difference(prevPolicies, newPolicies)
	if err := m.unloadPolicies(ctx, policiesToUnload); err != nil {
		return err
	}

	if len(filesToLoad) > 0 {
		// Run apparmor_parser on the files to load, relying on apparmor's caching mechanism
		apparmorParserCmd := append(m.apparmorParserCmd, []string{"-r", "-W", "-L", m.apparmorCacheDir}...)
		apparmorParserCmd = append(apparmorParserCmd, filesToLoad...)

		// #nosec G204 - We are in control of the arguments
		cmd := exec.CommandContext(ctx, apparmorParserCmd[0], apparmorParserCmd[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf(i18n.G("failed to load apparmor rules: %w\n%s"), err, string(out))
		}
	}

	// Loading rules succeeded, remove old apparmor policy dir
	if err := os.RemoveAll(oldApparmorPath); err != nil {
		return fmt.Errorf(i18n.G("can't remove old apparmor directory %q: %v"), oldApparmorPath, err)
	}

	return nil
}

// unloadAllRules unloads all apparmor rules in the given directory that are
// currently loaded in the system (present in the apparmorfs profiles file) and
// removes the directory.
// No action is taken if the directory doesn't exist.
func (m *Manager) unloadAllRules(ctx context.Context, apparmorPath string) (err error) {
	defer decorate.OnError(&err, i18n.G("can't unload apparmor rules"))

	// Nothing to do if the directory doesn't exist
	if _, err := os.Stat(apparmorPath); err != nil && os.IsNotExist(err) {
		return nil
	}

	// Walk the directory and get all the files to unload
	filesToUnload, err := filesInDir(apparmorPath)
	if err != nil {
		return err
	}
	// Get the currently loaded list of policies
	prevLoadedPolicies, err := m.loadedPolicies()
	if err != nil {
		return err
	}
	policies, err := m.policiesFromFiles(ctx, filesToUnload)
	if err != nil {
		return err
	}
	policies = intersection(policies, prevLoadedPolicies)

	if err := m.unloadPolicies(ctx, policies); err != nil {
		return err
	}

	// Unloading succeeded, remove apparmor policy dir
	if err := os.RemoveAll(apparmorPath); err != nil {
		return err
	}
	return nil
}

// policiesFromFiles produces a list of policies from a given set of apparmor profiles.
// A profile can have multiple policies.
func (m *Manager) policiesFromFiles(ctx context.Context, profiles []string) (policies []string, err error) {
	if len(profiles) == 0 {
		return nil, nil
	}

	apparmorParserCmd := append(m.apparmorParserCmd, "-N")
	apparmorParserCmd = append(apparmorParserCmd, profiles...)
	// #nosec G204 - We are in control of the arguments
	cmd := exec.CommandContext(ctx, apparmorParserCmd[0], apparmorParserCmd[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf(i18n.G("failed to get apparmor policies: %w\n%s"), err, string(out))
	}

	for _, line := range strings.Split(string(out), "\n") {
		policy := strings.TrimSpace(line)
		// If onlyLoaded is true, only policies currently loaded in the system are returned.
		if policy == "" {
			continue
		}
		policies = append(policies, policy)
	}
	return policies, nil
}

// unloadPolicies unloads the given apparmor policies.
// It returns an error if any of the policies can't be unloaded.
// No action is taken if the list of policies is empty.
func (m *Manager) unloadPolicies(ctx context.Context, policies []string) error {
	if len(policies) == 0 {
		return nil
	}

	log.Debugf(ctx, i18n.G("Unloading %d apparmor policies: %v"), len(policies), policies)
	apparmorParserCmd := append(m.apparmorParserCmd, "-R")
	// #nosec G204 - We are in control of the arguments
	cmd := exec.CommandContext(ctx, apparmorParserCmd[0], apparmorParserCmd[1:]...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	go func() {
		defer stdin.Close()
		for _, policy := range policies {
			// For each policy, declare an empty block to remove it.
			if _, err := io.WriteString(stdin, fmt.Sprintf("%s {}\n", policy)); err != nil {
				log.Warningf(ctx, i18n.G("Couldn't write to apparmor parser stdin: %v"), err)
			}
		}
	}()

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf(i18n.G("failed to unload apparmor policies: %w\n%s"), err, string(out))
	}
	return nil
}

// loadedPolicies parses the given system policies file and returns the list of
// loaded apparmor policies.
func (m *Manager) loadedPolicies() (policies []string, err error) {
	defer decorate.OnError(&err, i18n.G("can't parse loaded apparmor policies"))

	file, err := os.Open(m.loadedPoliciesFile)
	if err != nil {
		return nil, fmt.Errorf(i18n.G("failed to open %q: %w"), m.loadedPoliciesFile, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// The format of the file is:
	// policy_name (mode)
	//
	// Where mode is one of: enforce, complain
	// We only care about the policy name
	for scanner.Scan() {
		policy := strings.TrimSpace(strings.Split(scanner.Text(), " ")[0])
		policies = append(policies, policy)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return policies, nil
}

// cleanupOldApparmorDir handles putting the old apparmor policy files back if the
// new ones failed to apply.
func cleanupOldApparmorDir(ctx context.Context, oldApparmorPath, apparmorPath string) {
	// If the old apparmor directory is not present, it means we succeeded in
	// applying the new policy
	if _, err := os.Stat(oldApparmorPath); err != nil && os.IsNotExist(err) {
		return
	}

	// Otherwise, we need to restore the old apparmor directory
	if err := os.RemoveAll(apparmorPath); err != nil {
		log.Warningf(ctx, i18n.G("Couldn't remove new apparmor directory: %v"), err)
	}

	if err := os.Rename(oldApparmorPath, apparmorPath); err != nil {
		log.Warningf(ctx, i18n.G("Couldn't restore previous apparmor directory: %v"), err)
	}
}

// filesFromEntry returns the list of files configured in the given policy entry.
// It returns an error if the file does not exist or is a directory.
func filesFromEntry(e entry.Entry, apparmorPath string) ([]string, error) {
	var filesToLoad []string
	for _, profile := range strings.Split(e.Value, "\n") {
		profile = strings.TrimSpace(profile)
		if profile == "" {
			continue
		}

		profileFilePath := filepath.Join(apparmorPath, profile)
		info, err := os.Stat(profileFilePath)
		if err != nil {
			return nil, fmt.Errorf(i18n.G("apparmor profile %q is not accessible: %w"), err)
		}
		if info.IsDir() {
			return nil, fmt.Errorf(i18n.G("apparmor profile %q is a directory and not a file"), profile)
		}

		// Clean and deduplicate the profile file paths
		cleanProfilePath := filepath.Clean(profileFilePath)
		if slices.Contains(filesToLoad, cleanProfilePath) {
			continue
		}
		filesToLoad = append(filesToLoad, cleanProfilePath)
	}
	return filesToLoad, nil
}

// removeUnusedAssets removes all files/directories in the given directory that
// are not in the given list of files.
func removeUnusedAssets(apparmorPath string, filesToKeep []string) (e error) {
	defer decorate.OnError(&e, i18n.G("can't remove unused apparmor assets"))

	return filepath.WalkDir(apparmorPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.Type().IsRegular() || slices.Contains(filesToKeep, filepath.Clean(path)) {
			return nil
		}

		// Remove files that are not in the policy entry
		if err := os.Remove(path); err != nil {
			return err
		}

		// Remove parent directories if they're empty
		parentDir := filepath.Dir(path)
		parentEntries, err := os.ReadDir(parentDir)
		if err != nil {
			return err
		}
		if len(parentEntries) != 0 {
			return nil
		}

		return os.Remove(parentDir)
	})
}

// filesInDir returns the list of files in the given directory.
func filesInDir(path string) ([]string, error) {
	var files []string
	if err := filepath.WalkDir(path, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		files = append(files, path)
		return nil
	}); err != nil {
		return nil, err
	}
	return files, nil
}

// difference returns the elements in `a` that aren't in `b` with the caveat
// that the slices mustn't contain duplicate elements.
func difference(a, b []string) []string {
	mb := make(map[string]struct{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}
	}
	var diff []string
	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}

// intersection returns the elements that are common to both slices.
func intersection(a, b []string) []string {
	set := make([]string, 0)
	hash := make(map[string]struct{})

	for _, v := range a {
		hash[v] = struct{}{}
	}

	for _, v := range b {
		if _, found := hash[v]; found {
			set = append(set, v)
		}
	}

	return set
}

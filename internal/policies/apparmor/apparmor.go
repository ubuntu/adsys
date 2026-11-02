// Package apparmor provides a manager to apply apparmor policies.
//
// The policy manager first checks if apparmor_parser is available
// (file exists and is executable) and proceeds differently if these
// requirements are not met, depending on whether there are configured entries in
// the GPO:
// - no entries: a warning is logged and the manager returns without error
// - entries: the manager returns an error if apparmor_parser is not found
//
// Next, if we found no entries to apply (either to them not existing or being
// disabled), we attempt to unload all rules managed by ADSys.
//
// If there are entries to apply, based on the object type (machine or user), we
// attempt to apply them. This process is more clearly outlined in the
// ApplyPolicy function documentation.
//
// If any errors occur during the policy apply process, the manager will attempt
// to restore the initial state of the system before returning an error.
package apparmor

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/leonelquinteros/gotext"
	"github.com/ubuntu/adsys/internal/consts"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/smbsafe"
	"github.com/ubuntu/decorate"
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

	mu sync.Mutex // Prevents multiple instances of apparmor from running concurrenctly
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
		mu:                 sync.Mutex{},
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
	defer decorate.OnError(&err, gotext.Get("can't apply apparmor policy to %s", objectName))

	objectDir := "machine"
	if !isComputer {
		objectDir = "users"
	}
	apparmorPath := filepath.Join(m.apparmorDir, objectDir)

	// Apparmor can't be executed concurrently, so we need a lock to prevent it.
	m.mu.Lock()
	defer m.mu.Unlock()

	// No point in continuing if apparmor isn't available
	absPath, err := exec.LookPath(m.apparmorParserCmd[0])
	if err != nil {
		// If we do have entries to apply we should explicitly fail
		if len(entries) > 0 {
			return err
		}
		// Otherwise, just let the user know
		log.Warning(ctx, gotext.Get("Apparmor is not available on this system: %v", err))
		return nil
	}
	m.apparmorParserCmd[0] = absPath

	// If we have no entries, attempt to unload them and remove the apparmor directory
	idx := slices.IndexFunc(entries, func(e entry.Entry) bool { return e.Key == fmt.Sprintf("apparmor-%s", objectDir) })
	if idx == -1 || entries[idx].Disabled {
		log.Debug(ctx, gotext.Get("No entries found for the apparmor %s policy", objectDir))
		return m.unloadAllRules(ctx, objectName, isComputer)
	}

	log.Debug(ctx, gotext.Get("Applying apparmor %s policy to %s", objectDir, objectName))
	if err := os.MkdirAll(apparmorPath, 0750); err != nil {
		return errors.New(gotext.Get("can't create apparmor directory %q: %v", apparmorPath, err))
	}

	switch objectDir {
	case "machine":
		err = m.applyMachinePolicy(ctx, entries[idx], apparmorPath, assetsDumper)
	case "users":
		err = m.applyUserPolicy(ctx, entries[idx], apparmorPath, objectName, assetsDumper)
	}

	return err
}

// applyUserPolicy applies apparmor policies for the machine object.
func (m *Manager) applyMachinePolicy(ctx context.Context, e entry.Entry, apparmorPath string, assetsDumper AssetsDumper) (err error) {
	defer decorate.OnError(&err, gotext.Get("can't apply machine policy"))

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
		return errors.New(gotext.Get("can't remove old apparmor directory %q: %v", oldApparmorPath, err))
	}
	newApparmorPath := apparmorPath + ".new"
	if err := os.RemoveAll(newApparmorPath); err != nil {
		return errors.New(gotext.Get("can't remove new apparmor directory %q: %v", newApparmorPath, err))
	}

	// Dump assets to the adsys/machine.new/ subdirectory with correct
	// ownership. If no assets is present while entries != nil, we want to
	// return an error.
	if err := assetsDumper(ctx, "apparmor/", newApparmorPath, -1, -1); err != nil {
		return err
	}

	// Rename existing apparmor policy to .old
	if err := os.Rename(apparmorPath, oldApparmorPath); err != nil {
		return errors.New(gotext.Get("can't rename apparmor directory %q to %q: %v", apparmorPath, oldApparmorPath, err))
	}
	defer cleanupOldApparmorDir(ctx, oldApparmorPath, apparmorPath)

	// Rename new apparmor policy to current
	if err := os.Rename(newApparmorPath, apparmorPath); err != nil {
		return errors.New(gotext.Get("can't rename apparmor directory %q to %q: %v", newApparmorPath, apparmorPath, err))
	}

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

	if len(filesToLoad) > 0 && os.Getenv("ADSYS_SKIP_ROOT_CALLS") == "" {
		// Run apparmor_parser on the files to load, relying on apparmor's caching mechanism
		apparmorParserCmd := append(m.apparmorParserCmd, []string{"-r", "-W", "-L", m.apparmorCacheDir}...)
		apparmorParserCmd = append(apparmorParserCmd, filesToLoad...)

		// #nosec G204 - We are in control of the arguments
		cmd := exec.CommandContext(ctx, apparmorParserCmd[0], apparmorParserCmd[1:]...)
		cmd.Dir = m.apparmorDir
		smbsafe.WaitExec()
		out, err := cmd.CombinedOutput()
		smbsafe.DoneExec()
		if err != nil {
			return errors.New(gotext.Get("failed to load apparmor rules: %v\n%s", err, string(out)))
		}
	}

	// Loading rules succeeded, remove old apparmor policy dir
	if err := os.RemoveAll(oldApparmorPath); err != nil {
		return errors.New(gotext.Get("can't remove old apparmor directory %q: %v", oldApparmorPath, err))
	}
	return nil
}

// applyUserPolicy applies apparmor policies for the user object.
func (m *Manager) applyUserPolicy(ctx context.Context, e entry.Entry, apparmorPath string, username string, assetsDumper AssetsDumper) (err error) {
	defer decorate.OnError(&err, gotext.Get("can't apply user policy"))

	// Create a temporary filepath to be used by the assets dumper and dump all
	// assets in order to get our user policy
	tmpdir := filepath.Join(os.TempDir(), fmt.Sprintf("adsys_apparmor_user_%s_%d", username, time.Now().UnixNano()))
	if err := assetsDumper(ctx, "apparmor/", tmpdir, -1, -1); err != nil {
		return err
	}
	defer os.RemoveAll(tmpdir)
	profilePaths, err := filesFromEntry(e, tmpdir)
	if err != nil {
		return err
	}

	// The user policy is always a single file
	if len(profilePaths) != 1 {
		return errors.New(gotext.Get("expected exactly one profile, got %d", len(profilePaths)))
	}
	profilePath := profilePaths[0]
	profileContents, err := os.ReadFile(profilePath)
	if err != nil {
		return err
	}

	// Wrap the contents in a profile declaration with the username as the profile name
	parsedProfile := fmt.Sprintf("^%s {\n%s\n}\n", username, strings.TrimSpace(string(profileContents)))

	// Write the profile to the user's apparmor directory, getting the previous
	// contents if available
	oldContent, changed, err := writeIfChanged(filepath.Join(apparmorPath, username), parsedProfile)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}

	if os.Getenv("ADSYS_SKIP_ROOT_CALLS") != "" {
		return nil
	}

	// Reload apparmor machine profiles to ensure that updates to the user policy are applied
	existingProfiles, err := filesInDir(filepath.Join(m.apparmorDir, "machine"))
	if errors.Is(err, os.ErrNotExist) {
		log.Warning(ctx, gotext.Get("No apparmor machine profiles configured for this machine, skipping reload"))
		return nil
	}
	if err != nil {
		return err
	}
	apparmorParserCmd := append(m.apparmorParserCmd, []string{"-r", "-W", "-L", m.apparmorCacheDir}...)
	apparmorParserCmd = append(apparmorParserCmd, existingProfiles...)

	// #nosec G204 - We are in control of the arguments
	cmd := exec.CommandContext(ctx, apparmorParserCmd[0], apparmorParserCmd[1:]...)
	cmd.Dir = m.apparmorDir
	smbsafe.WaitExec()
	out, err := cmd.CombinedOutput()
	smbsafe.DoneExec()
	if err != nil {
		// Restore the old content
		var restoreErr error
		if len(oldContent) == 0 {
			restoreErr = os.Remove(filepath.Join(apparmorPath, username))
		} else {
			restoreErr = os.WriteFile(filepath.Join(apparmorPath, username), oldContent, 0600)
		}
		if restoreErr != nil {
			log.Warning(ctx, gotext.Get("Failed to restore old apparmor user profile: %v", restoreErr))
		}

		// Return the execution error
		return errors.New(gotext.Get("failed to load apparmor rules: %v\n%s", err, string(out)))
	}
	return nil
}

// unloadAllRules unloads all apparmor rules in the given directory that are
// currently loaded in the system (present in the apparmorfs profiles file) and
// removes the directory.
// If isComputer is true, only rules pertaining to the given user are unloaded.
// No action is taken if the directory doesn't exist.
func (m *Manager) unloadAllRules(ctx context.Context, objectName string, isComputer bool) (err error) {
	defer decorate.OnError(&err, gotext.Get("can't unload apparmor rules"))

	machinePoliciesPath := filepath.Join(m.apparmorDir, "machine")
	pathToRemove := machinePoliciesPath
	if !isComputer {
		pathToRemove = filepath.Join(m.apparmorDir, "users", objectName)
	}
	// If there are no machine policies there is nothing to unload
	if _, err := os.Stat(machinePoliciesPath); err != nil && os.IsNotExist(err) {
		if err := os.Remove(pathToRemove); !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}

	// Walk the directory and get all the files to unload
	filesToUnload, err := filesInDir(machinePoliciesPath)
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

	// Only remove user-specific policies if we're unloading the user part
	// These look like the following:
	// /usr/bin/su//administrator@warthogs.biz (enforce)
	// /usr/bin/su//anotheruser@warthogs.biz (enforce)
	if !isComputer {
		pathToRemove = filepath.Join(m.apparmorDir, "users", objectName)
		i := 0
		for _, policy := range policies {
			if strings.HasSuffix(policy, fmt.Sprintf("//%s", objectName)) {
				policies[i] = policy
				i++
			}
		}
		policies = policies[:i]
	}

	if err := m.unloadPolicies(ctx, policies); err != nil {
		return err
	}

	// Unloading succeeded, remove apparmor policy dir
	if err := os.RemoveAll(pathToRemove); err != nil {
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
	var outb, errb bytes.Buffer
	// #nosec G204 - We are in control of the arguments
	cmd := exec.CommandContext(ctx, apparmorParserCmd[0], apparmorParserCmd[1:]...)
	cmd.Dir = m.apparmorDir
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	smbsafe.WaitExec()
	err = cmd.Run()
	smbsafe.DoneExec()
	if err != nil {
		return nil, errors.New(gotext.Get("failed to get apparmor policies: %v\n%s", err, errb.String()))
	}
	// Execution succeeded but we still got something on stderr, let the user know
	if errb.Len() > 0 {
		log.Warning(ctx, gotext.Get(`Got stderr output from apparmor_parser:
%s`, errb.String()))
	}

	for _, line := range strings.Split(outb.String(), "\n") {
		policy := strings.TrimSpace(line)
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

	log.Debug(ctx, gotext.Get("Unloading %d apparmor policies: %v", len(policies), policies))
	apparmorParserCmd := append(m.apparmorParserCmd, "-R")
	// #nosec G204 - We are in control of the arguments
	cmd := exec.CommandContext(ctx, apparmorParserCmd[0], apparmorParserCmd[1:]...)
	cmd.Dir = m.apparmorDir
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	go func() {
		defer stdin.Close()
		for index, policy := range policies {
			// Handle cases where /usr/bin/foo and /usr/bin/foo//USER are both set to be unloaded.
			// Because unloading the former will also unload the latter we need to skip profiles for
			// which we've already removed the parent profile.
			parentPolicy, _, found := strings.Cut(policy, "//")
			if found && slices.IndexFunc(policies[:index], func(p string) bool { return p == parentPolicy }) != -1 {
				continue
			}
			// For each policy, declare an empty block to remove it.
			if _, err := io.WriteString(stdin, fmt.Sprintf("profile %s {}\n", policy)); err != nil {
				log.Warning(ctx, gotext.Get("Couldn't write to apparmor parser stdin: %v", err))
			}
		}
	}()

	smbsafe.WaitExec()
	defer smbsafe.DoneExec()
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.New(gotext.Get("failed to unload apparmor policies: %v\n%s", err, string(out)))
	}
	return nil
}

// loadedPolicies parses the given system policies file and returns the list of
// loaded apparmor policies.
func (m *Manager) loadedPolicies() (policies []string, err error) {
	defer decorate.OnError(&err, gotext.Get("can't parse loaded apparmor policies"))

	file, err := os.Open(m.loadedPoliciesFile)
	if err != nil {
		return nil, errors.New(gotext.Get("failed to open %q: %v", m.loadedPoliciesFile, err))
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
		log.Warning(ctx, gotext.Get("Couldn't remove new apparmor directory: %v", err))
	}

	if err := os.Rename(oldApparmorPath, apparmorPath); err != nil {
		log.Warning(ctx, gotext.Get("Couldn't restore previous apparmor directory: %v", err))
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
			return nil, errors.New(gotext.Get("apparmor profile %q is not accessible: %v", profile, err))
		}
		if info.IsDir() {
			return nil, errors.New(gotext.Get("apparmor profile %q is a directory and not a file", profile))
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
	defer decorate.OnError(&e, gotext.Get("can't remove unused apparmor assets"))

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

// writeIfChanged will only write to path if content is different from current content.
func writeIfChanged(path string, content string) (oldContent []byte, changed bool, err error) {
	defer decorate.OnError(&err, gotext.Get("can't save %s", path))

	oldContent, err = os.ReadFile(path)
	if err == nil && string(oldContent) == content {
		return oldContent, false, nil
	}

	if err := os.WriteFile(path+".new", []byte(content), 0600); err != nil {
		return nil, true, err
	}
	if err := os.Rename(path+".new", path); err != nil {
		return nil, true, err
	}

	return oldContent, true, nil
}

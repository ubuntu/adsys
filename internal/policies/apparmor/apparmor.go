// Package apparmor provides a manager to apply apparmor policies.
package apparmor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ubuntu/adsys/internal/decorate"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"golang.org/x/exp/slices"
)

// Manager prevents running multiple apparmor update processes in parallel while parsing policy in ApplyPolicy.
type Manager struct {
	apparmorDir       string
	apparmorParserCmd []string

	muMu    sync.Mutex             // protect pathsMu
	pathsMu map[string]*sync.Mutex // mutex is per destination path (e.g. machine, users/user1, users/user2)
}

type options struct {
	apparmorParserCmd []string
}

// Option reprents an optional function to change the apparmor manager.
type Option func(*options)

// New creates a manager with a specific apparmor directory.
func New(apparmorDir string, opts ...Option) *Manager {
	// defaults
	args := options{
		apparmorParserCmd: []string{"apparmor_parser"},
	}
	// applied options
	for _, o := range opts {
		o(&args)
	}

	return &Manager{
		pathsMu:           make(map[string]*sync.Mutex),
		apparmorDir:       apparmorDir,
		apparmorParserCmd: args.apparmorParserCmd,
	}
}

// AssetsDumper is a function which uncompress policies assets to a directory.
type AssetsDumper func(ctx context.Context, relSrc, dest string, uid int, gid int) (err error)

// ApplyPolicy generates an apparmor policy based on a list of entries.
// Steps:
// 1. Create /etc/apparmor.d/adsys/<object>.new with new policy
// 2a. Move /etc/apparmor.d/adsys/<object> to /etc/apparmor.d/adsys/<object>.old
// 2b. Move /etc/apparmor.d/adsys/<object>.new to /etc/apparmor.d/adsys/<object>
// 3. Run apparmor_parser -r on all files in /etc/apparmor.d/adsys/<object>
// 4a. If apparmor_parser fails, move /etc/apparmor.d/adsys/<object>.old to /etc/apparmor.d/adsys/<object>
// 4b. If apparmor_parser succeeds, remove /etc/apparmor.d/adsys/<object>.old.
func (m *Manager) ApplyPolicy(ctx context.Context, objectName string, isComputer bool, entries []entry.Entry, assetsDumper AssetsDumper) (err error) {
	defer decorate.OnError(&err, i18n.G("can't apply apparmor policy to %s"), objectName)

	objectDir := "machine"
	// TODO: add user support
	if !isComputer {
		// objectDir = "users"
		log.Warningf(ctx, i18n.G("apparmor policies are currently only supported for computers"))
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
		log.Warningf(ctx, "Apparmor is not available on this system: %v", err)
		return nil
	}
	m.apparmorParserCmd[0] = absPath

	// If we have no entries, attempt to unload them and remove the apparmor directory
	if len(entries) == 0 {
		return unloadRules(ctx, m.apparmorParserCmd, apparmorPath)
	}

	log.Debugf(ctx, "Applying apparmor policy to %s", objectName)

	// Return early if we cannot find a valid policy entry
	idx := slices.IndexFunc(entries, func(e entry.Entry) bool { return e.Key == "apparmor-machine" })
	if idx == -1 {
		log.Warning(ctx, i18n.G("No valid entry found for the apparmor machine policy"))
		return nil
	}

	if err := os.MkdirAll(apparmorPath, 0750); err != nil {
		return fmt.Errorf(i18n.G("can't create apparmor directory %q: %v"), apparmorPath, err)
	}

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

	if len(filesToLoad) > 0 {
		// Run apparmor_parser on all profiles
		apparmorParserCmd := append(m.apparmorParserCmd, "-r")
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
		log.Warningf(ctx, "can't remove new apparmor directory: %v", err)
	}

	if err := os.Rename(oldApparmorPath, apparmorPath); err != nil {
		log.Warningf(ctx, "can't restore previous apparmor directory: %v", err)
	}
}

// unloadRules unloads the apparmor rules in the given directory and removes the directory.
// No action is taken if the directory doesn't exist.
func unloadRules(ctx context.Context, apparmorParserCmd []string, apparmorPath string) (err error) {
	defer decorate.OnError(&err, i18n.G("can't unload apparmor rules"))

	// Nothing to do if the directory doesn't exist
	if _, err := os.Stat(apparmorPath); err != nil && os.IsNotExist(err) {
		return nil
	}

	// Walk the directory and get all the files to unload
	var filesToUnload []string
	if err := filepath.WalkDir(apparmorPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		filesToUnload = append(filesToUnload, path)
		return nil
	}); err != nil {
		return err
	}

	apparmorParserCmd = append(apparmorParserCmd, "-R")
	apparmorParserCmd = append(apparmorParserCmd, filesToUnload...)

	// #nosec G204 - We are in control of the arguments
	cmd := exec.CommandContext(ctx, apparmorParserCmd[0], apparmorParserCmd[1:]...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf(i18n.G("failed to unload apparmor rules: %w\n%s"), err, string(out))
	}

	// Unloading succeeded, remove apparmor policy dir
	if err := os.RemoveAll(apparmorPath); err != nil {
		log.Warningf(ctx, "can't remove apparmor directory: %v", err)
	}
	return nil
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

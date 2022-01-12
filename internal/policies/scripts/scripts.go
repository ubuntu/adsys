package scripts

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/termie/go-shutil"
	"github.com/ubuntu/adsys/internal/consts"
	"github.com/ubuntu/adsys/internal/decorate"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/entry"
	"github.com/ubuntu/adsys/internal/smbsafe"
)

/*
	Notes:

	scripts are executed to control machine startup and shutdown, and user login/logout.
	We rely on systemd units to manage them and only control the execution of the machine startup one.
*/

const readyFlag = ".ready"

// Manager prevents running multiple scripts update process in parallel while parsing policy in ApplyPolicy.
type Manager struct {
	scriptsMu map[string]*sync.Mutex // mutex is per destination directory (user1/user2/computer)
	muMu      sync.Mutex             // protect scriptsMu

	runDir       string
	gpoScriptDir string

	systemctlCmd []string
	userLookup   func(string) (*user.User, error)
}

type options struct {
	cacheDir     string
	runDir       string
	userLookup   func(string) (*user.User, error)
	systemctlCmd []string
}

// Option reprents an optional function to change scripts manager.
type Option func(*options)

// New creates a manager with a specific scripts directory.
func New(cacheDir, runDir string, opts ...Option) *Manager {
	// defaults
	args := options{
		userLookup:   user.Lookup,
		systemctlCmd: []string{"systemctl"},
	}
	// applied options
	for _, o := range opts {
		o(&args)
	}

	return &Manager{
		scriptsMu:    make(map[string]*sync.Mutex),
		gpoScriptDir: filepath.Join(cacheDir, "gpo_cache", "scripts"),
		runDir:       runDir,
		userLookup:   args.userLookup,
		systemctlCmd: args.systemctlCmd,
	}
}

// ApplyPolicy generates a privilege policy based on a list of entries.
func (m *Manager) ApplyPolicy(ctx context.Context, objectName string, isComputer bool, entries []entry.Entry) (err error) {
	defer decorate.OnError(&err, i18n.G("can't apply scripts policy to %s"), objectName)

	log.Debugf(ctx, "Applying scripts policy to %s", objectName)

	objectDir := "machine"
	var uid, gid int
	if !isComputer {
		user, err := m.userLookup(objectName)
		if err != nil {
			return fmt.Errorf(i18n.G("couldn't retrieve user for %q: %v"), objectName, err)
		}
		if uid, err = strconv.Atoi(user.Uid); err != nil {
			return fmt.Errorf(i18n.G("couldn't convert %q to a valid uid for %q"), user.Uid, objectName)
		}
		if gid, err = strconv.Atoi(user.Gid); err != nil {
			return fmt.Errorf(i18n.G("couldn't convert %q to a valid gid for %q"), user.Gid, objectName)
		}

		objectDir = filepath.Join("users", user.Uid)
	}

	scriptsDir := filepath.Join(m.runDir, objectDir, "scripts")

	// Mutex is per user1, user2, computer
	m.muMu.Lock()
	// if mutex does not exist for this destination, creates it
	if _, exists := m.scriptsMu[scriptsDir]; !exists {
		m.scriptsMu[scriptsDir] = &sync.Mutex{}
	}
	m.muMu.Unlock()
	m.scriptsMu[scriptsDir].Lock()
	defer m.scriptsMu[scriptsDir].Unlock()

	// If exists: there is a "session" in progress:*
	// - machine already booted and startup scripts executed
	// - user session in progress and login scripts executed
	// Do nothing, we have potential next versions in cache, we will use them on next apply at session start if all sessions are closed.
	if _, err := os.Stat(filepath.Join(scriptsDir, readyFlag)); err == nil {
		log.Infof(ctx, "%q already exists, a session is already running, ignoring.", scriptsDir)
		return nil
	}

	if err := os.RemoveAll(scriptsDir); err != nil {
		return err
	}

	if len(entries) == 0 {
		return nil
	}

	// create scriptsDir directory and chown it to uid:gid of the user
	if err := os.MkdirAll(scriptsDir, 0700); err != nil {
		return fmt.Errorf(i18n.G("can't create scripts directory %q: %v"), scriptsDir, err)
	}
	if !isComputer {
		if err := os.Chown(scriptsDir, uid, gid); err != nil {
			return fmt.Errorf(i18n.G("can't change owner of script directory %q to user %s: %v"), scriptsDir, objectName, err)
		}
	}

	// create scripts files, index them in each destDir directory
	i := make(map[string]int)
	for _, e := range entries {
		destDir := filepath.Join(scriptsDir, filepath.Base(e.Key))
		if err := createDirectoryWithUIDGid(destDir, uid, gid); err != nil {
			return err
		}

		for _, script := range strings.Split(e.Value, "\n") {
			script = strings.TrimSpace(script)
			if script == "" {
				continue
			}

			dest := filepath.Join(destDir, fmt.Sprintf("%02d_%s", i[destDir], filepath.Base(script)))
			if err := shutil.CopyFile(filepath.Join(m.gpoScriptDir, script), dest, true); err != nil {
				return fmt.Errorf(i18n.G("can't copy script %q to %q: %v"), script, dest, err)
			}
			if !isComputer {
				if err := os.Chown(dest, uid, gid); err != nil {
					return fmt.Errorf(i18n.G("can't change owner of script %q to user %d: %v"), script, uid, err)
				}
			}
			if os.Chmod(dest, 0550) != nil {
				return fmt.Errorf(i18n.G("can't change mode of script %q to %o: %v"), dest, 0550, err)
			}

			i[destDir]++
		}
	}

	f, err := os.Create(filepath.Join(scriptsDir, readyFlag))
	if err != nil {
		return fmt.Errorf(i18n.G("can't create ready file for scripts: %v"), err)
	}
	if err := f.Close(); err != nil {
		return err
	}

	if !isComputer {
		return nil
	}

	log.Info(ctx, "Running machine startup scripts")
	cmdArgs := m.systemctlCmd
	cmdArgs = append(cmdArgs, "start", consts.AdysMachineScriptsServiceName)
	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	smbsafe.WaitExec()
	defer smbsafe.DoneExec()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to run machine scripts: %v\n%s", err, string(out))
	}

	return nil
}

// createDirectoryWithUIDGid creates a directory with the given uid and gid if not 0.
func createDirectoryWithUIDGid(p string, uid, gid int) error {
	if err := os.MkdirAll(p, 0700); err != nil {
		return fmt.Errorf(i18n.G("can't create scripts directory %q: %v"), p, err)
	}
	if uid != 0 {
		if err := os.Chown(p, uid, gid); err != nil {
			return fmt.Errorf(i18n.G("can't change owner of script directory %q to user %d: %v"), p, uid, err)
		}
	}
	return nil
}

// RunScripts executes all scripts in directory if ready and not already executed.
func RunScripts(ctx context.Context, path string) (err error) {
	defer decorate.OnError(&err, i18n.G("can't run scripts in %s"), path)

	log.Infof(ctx, "Calling RunScripts on %q", path)

	// Check that we are in a directory
	fileInfo, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !fileInfo.IsDir() {
		return fmt.Errorf(i18n.G("%q is not a directory"), path)
	}

	// Ensure we are ready to execute
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), readyFlag)); err != nil {
		return fmt.Errorf(i18n.G("%q is not ready to execute scripts"), path)
	}

	// List in version order all the executables in the directory and execute them
	scripts, err := os.ReadDir(path)
	if err != nil {
		return err
	}

	// Sort scripts in numeric order
	sort.Slice(scripts, func(i, j int) bool {
		a, err := strconv.Atoi(strings.Split(scripts[i].Name(), "_")[0])
		if err != nil {
			log.Warningf(ctx, "%q doesn’t have the required DD_name format: %v\n", filepath.Join(path, scripts[i].Name()), err)
			return false
		}
		b, err := strconv.Atoi(strings.Split(scripts[j].Name(), "_")[0])
		if err != nil {
			log.Warningf(ctx, "%q doesn’t have the required DD_name format: %v\n", filepath.Join(path, scripts[j].Name()), err)
			return true
		}

		return a < b
	})

	// No need for smbsafe here: this process will never execute smb.
	for _, script := range scripts {
		if out, err := exec.CommandContext(ctx, filepath.Join(path, script.Name())).CombinedOutput(); err != nil {
			log.Warningf(ctx, "%q failed to run: %v\n%v", script.Name(), err, string(out))
		}
	}

	// Delete users script directory once all logoff scripts are executed
	if !strings.Contains(path, "/users/") || !strings.HasSuffix(path, "/logoff") {
		return nil
	}
	return os.RemoveAll(filepath.Dir(path))
}

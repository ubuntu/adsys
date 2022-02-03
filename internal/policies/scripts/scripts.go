package scripts

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

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

const (
	readyFlag     = ".ready"
	executableDir = "scripts"
)

// Manager prevents running multiple scripts update process in parallel while parsing policy in ApplyPolicy.
type Manager struct {
	scriptsMu map[string]*sync.Mutex // mutex is per destination directory (user1/user2/computer)
	muMu      sync.Mutex             // protect scriptsMu

	runDir string

	systemctlCmd []string
	userLookup   func(string) (*user.User, error)
}

type options struct {
	userLookup   func(string) (*user.User, error)
	systemctlCmd []string
}

// Option reprents an optional function to change scripts manager.
type Option func(*options)

// New creates a manager with a specific scripts directory.
func New(runDir string, opts ...Option) *Manager {
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
		runDir:       runDir,
		userLookup:   args.userLookup,
		systemctlCmd: args.systemctlCmd,
	}
}

// AssetsDumper is a function which uncompress policies assets to a directory.
type AssetsDumper func(ctx context.Context, relSrc, dest string) (err error)

// ApplyPolicy generates a privilege policy based on a list of entries.
func (m *Manager) ApplyPolicy(ctx context.Context, objectName string, isComputer bool, entries []entry.Entry, assetsDumper AssetsDumper) (err error) {
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

	scriptsPath := filepath.Join(m.runDir, objectDir, executableDir)

	// Mutex is per user1, user2, computer
	m.muMu.Lock()
	// if mutex does not exist for this destination, creates it
	if _, exists := m.scriptsMu[scriptsPath]; !exists {
		m.scriptsMu[scriptsPath] = &sync.Mutex{}
	}
	m.muMu.Unlock()
	m.scriptsMu[scriptsPath].Lock()
	defer m.scriptsMu[scriptsPath].Unlock()

	// If exists: there is a "session" in progress:*
	// - machine already booted and startup scripts executed
	// - user session in progress and login scripts executed
	// Do nothing, we have potential next versions in cache, we will use them on next apply at session start if all sessions are closed.
	if _, err := os.Stat(filepath.Join(scriptsPath, readyFlag)); err == nil {
		log.Infof(ctx, "%q already exists, a session is already running, ignoring.", scriptsPath)
		return nil
	}

	if err := os.RemoveAll(scriptsPath); err != nil {
		return err
	}

	if len(entries) == 0 {
		return nil
	}

	// create scriptsDir directory and chown it to uid:gid of the user
	if err := os.MkdirAll(scriptsPath, 0700); err != nil {
		return fmt.Errorf(i18n.G("can't create scripts directory %q: %v"), scriptsPath, err)
	}
	if !isComputer {
		if err := chown(ctx, scriptsPath, uid, gid); err != nil {
			return fmt.Errorf(i18n.G("can't change owner of script directory %q to user %s: %v"), scriptsPath, objectName, err)
		}
	}

	// Dump assets to scripts/ subdirectory. If no assets is present while entries != nil, we want to return an error.
	dest := filepath.Join(scriptsPath, executableDir)
	if err := assetsDumper(ctx, "scripts/", dest); err != nil {
		return err
	}
	// Fix ownership of scripts/ subdirectory and its contents
	if !isComputer {
		log.Debugf(ctx, "Fixing ownership of scripts/ subdirectory for user %q", objectName)
		if err := filepath.WalkDir(dest, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			return chown(ctx, path, uid, gid)
		}); err != nil {
			return err
		}
	}

	// create order files, check that the scripts existings in the destination
	log.Debugf(ctx, "Creating script order file for user %q", objectName)
	orderFilesContent := make(map[string][]string)
	for _, e := range entries {
		lifecycle := filepath.Base(e.Key)
		for _, script := range strings.Split(e.Value, "\n") {
			script = strings.TrimSpace(script)
			if script == "" {
				continue
			}

			// check that the script exists and make it executable
			scriptFilePath := filepath.Join(scriptsPath, executableDir, script)
			log.Debugf(ctx, "%q: found %q. Marking as executable %q", e.Key, script, scriptFilePath)
			info, err := os.Stat(scriptFilePath)
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf(i18n.G("script %q doesn't exist in SYSVOL scripts/ subdirectory"), script)
			}
			if info.IsDir() {
				return fmt.Errorf(i18n.G("script %q is a directory and not a file to execute"), script)
			}
			if err := os.Chmod(scriptFilePath, 0550); err != nil {
				return fmt.Errorf(i18n.G("can't change mode of script %qto %o: %v"), scriptFilePath, 0550, err)
			}

			// append it to the list of our scripts
			orderFilesContent[lifecycle] = append(orderFilesContent[lifecycle], filepath.Join(executableDir, script))
		}
	}

	for lifecycle, scripts := range orderFilesContent {
		orderFilePath := filepath.Join(scriptsPath, lifecycle)

		log.Debugf(ctx, "Creating order file %q", orderFilePath)
		f, err := os.Create(orderFilePath)
		if err != nil {
			return err
		}
		defer f.Close()

		for _, script := range scripts {
			if _, err := f.WriteString(script + "\n"); err != nil {
				return err
			}
		}
		// Commit file on disk before preparing the ready flag
		if err := f.Close(); err != nil {
			return err
		}
		if !isComputer {
			if err := chown(ctx, orderFilePath, uid, gid); err != nil {
				return fmt.Errorf(i18n.G("can't change owner of order file %q to user %s: %v"), orderFilePath, objectName, err)
			}
		}
	}

	// Create ready flag
	log.Debugf(ctx, "Create script ready flag for user %q", objectName)
	f, err := os.Create(filepath.Join(scriptsPath, readyFlag))
	if err != nil {
		return fmt.Errorf(i18n.G("can't create ready file for scripts: %v"), err)
	}
	if err := f.Close(); err != nil {
		return err
	}

	if !isComputer {
		return nil
	}

	// Check that there are a startup directory and only execute if there is one.
	if _, err = os.Stat(filepath.Join(scriptsPath, "startup")); errors.Is(err, os.ErrNotExist) {
		return nil
	}

	log.Info(ctx, "Running machine startup scripts")
	cmdArgs := m.systemctlCmd
	cmdArgs = append(cmdArgs, "start", consts.AdysMachineScriptsServiceName)
	// #nosec G204 - We are in control of the arguments
	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	smbsafe.WaitExec()
	defer smbsafe.DoneExec()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to run machine scripts: %w\n%s", err, string(out))
	}

	return nil
}

// RunScripts executes all scripts in directory if ready and not already executed.
// allowOrderMissing will not require order to exists if we are ready to execute.
func RunScripts(ctx context.Context, order string, allowOrderMissing bool) (err error) {
	defer decorate.OnError(&err, i18n.G("can't run scripts listed in %s"), order)

	log.Infof(ctx, "Calling RunScripts on %q", order)

	baseDir := filepath.Dir(order)

	// Ensure we are ready to execute
	if _, err := os.Stat(filepath.Join(baseDir, readyFlag)); err != nil {
		return fmt.Errorf(i18n.G("%q is not ready to execute scripts"), order)
	}

	// Read from the order file the order of scripts to run
	f, err := os.Open(order)
	if allowOrderMissing && errors.Is(err, os.ErrNotExist) {
		log.Infof(ctx, "%q doesn't exist, but allowed to be missing, skipping", order)
		return nil
	} else if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf(i18n.G("%q is a directory and not a file"), order)
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		scriptPath := strings.TrimSpace(scanner.Text())
		if scriptPath == "" {
			continue
		}
		script := filepath.Join(baseDir, scriptPath)
		// #nosec G204 - this variable is coming from concatenation of an order file.
		// Permissions are restricted to the owner of the order file, which is the one executing
		// this script.
		if out, err := exec.CommandContext(ctx, script).CombinedOutput(); err != nil {
			log.Warningf(ctx, "%q failed to run: %v\n%v", script, err, string(out))
		}
	}

	// Delete users script directory once all logoff scripts are executed
	if !strings.Contains(order, "/users/") || !strings.HasSuffix(order, "/logoff") {
		return nil
	}
	return os.RemoveAll(baseDir)
}

// chown allow to skip the Chown syscall for automated or manual testing when running as non root.
func chown(ctx context.Context, name string, uid, gid int) error {
	if os.Getenv("ADSYS_SKIP_ROOT_CALLS") != "" {
		log.Infof(ctx, "Skipping chown on %q as requested by ADSYS_SKIP_ROOT_CALLS", name)
		return nil
	}

	return os.Chown(name, uid, gid)
}

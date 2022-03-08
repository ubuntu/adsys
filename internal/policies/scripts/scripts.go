package scripts

import (
	"bufio"
	"context"
	"errors"
	"fmt"
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
	inSessionFlag = ".running"
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
func New(runDir string, opts ...Option) (m *Manager, err error) {
	defer decorate.OnError(&err, i18n.G("can't create scripts manager"))

	// defaults
	args := options{
		userLookup:   user.Lookup,
		systemctlCmd: []string{"systemctl"},
	}
	// applied options
	for _, o := range opts {
		o(&args)
	}

	// Multiple users will be in users/ subdirectory. Create the main one.
	// #nosec G301 - multiple users will be in users/ subdirectory, we want all of them
	// to be able to access its own subdirectory.
	if err := os.MkdirAll(filepath.Join(runDir, "users"), 0755); err != nil {
		return nil, err
	}

	return &Manager{
		scriptsMu:    make(map[string]*sync.Mutex),
		runDir:       runDir,
		userLookup:   args.userLookup,
		systemctlCmd: args.systemctlCmd,
	}, nil
}

// AssetsDumper is a function which uncompress policies assets to a directory.
type AssetsDumper func(ctx context.Context, relSrc, dest string, uid int, gid int) (err error)

// ApplyPolicy generates a privilege policy based on a list of entries.
func (m *Manager) ApplyPolicy(ctx context.Context, objectName string, isComputer bool, entries []entry.Entry, assetsDumper AssetsDumper) (err error) {
	defer decorate.OnError(&err, i18n.G("can't apply scripts policy to %s"), objectName)

	log.Debugf(ctx, "Applying scripts policy to %s", objectName)

	objectDir := "machine"
	uid, gid := -1, -1
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

	objectPath := filepath.Join(m.runDir, objectDir)
	scriptsPath := filepath.Join(objectPath, executableDir)

	// Mutex is per user1, user2, computer
	m.muMu.Lock()
	// if mutex does not exist for this destination, creates it
	if _, exists := m.scriptsMu[scriptsPath]; !exists {
		m.scriptsMu[scriptsPath] = &sync.Mutex{}
	}
	m.muMu.Unlock()
	m.scriptsMu[scriptsPath].Lock()
	defer m.scriptsMu[scriptsPath].Unlock()

	// If exists: there is a "session" in progress:
	// - machine already booted and startup scripts executed
	// - user session in progress and login scripts executed
	// Do nothing, we have potential next versions in cache, we will use them on next apply at session start if all sessions are closed.
	if _, err := os.Stat(filepath.Join(scriptsPath, inSessionFlag)); err == nil {
		log.Infof(ctx, "%q already exists, a session is already running, ignoring.", filepath.Join(scriptsPath, inSessionFlag))
		return nil
	}

	if err := os.RemoveAll(scriptsPath); err != nil {
		return err
	}

	if len(entries) == 0 {
		return nil
	}

	// This creates objectDirPath and scriptsDir directory.
	// We chown objectDirPath and scripts (user specific) to uid:gid of the user. Nothing is done for the machine
	if err := mkdirAllWithUIDGid(objectPath, uid, gid); err != nil {
		return fmt.Errorf(i18n.G("can't create object directory %q: %v"), objectPath, err)
	}
	if err := mkdirAllWithUIDGid(scriptsPath, uid, gid); err != nil {
		return fmt.Errorf(i18n.G("can't create scripts directory %q: %v"), scriptsPath, err)
	}

	// Dump assets to scripts/scripts/ subdirectory with correct ownership. If no assets is present while entries != nil, we want to return an error.
	dest := filepath.Join(scriptsPath, "scripts")
	if err := assetsDumper(ctx, "scripts/", dest, uid, gid); err != nil {
		return err
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
		if err := chown(orderFilePath, f, uid, gid); err != nil {
			return err
		}
		// Commit file on disk before preparing the ready flag
		if err := f.Close(); err != nil {
			return err
		}
	}

	// Create ready flag
	if err := createFlagFile(ctx, filepath.Join(scriptsPath, readyFlag), uid, gid); err != nil {
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

	// create running flag for the user or machine
	if err := createFlagFile(ctx, filepath.Join(baseDir, inSessionFlag), -1, -1); err != nil {
		return err
	}

	// Delete users or machine script directory once all user logoff or machine shutdown scripts are executed
	defer func() {
		if !((strings.Contains(order, "/users/") && strings.HasSuffix(order, "/logoff")) ||
			(strings.Contains(order, "/machine/") && strings.HasSuffix(order, "/shutdown"))) {
			return
		}
		log.Debug(ctx, "Logoff or shutdown called, deleting in session flag")
		errRemove := os.Remove(filepath.Join(baseDir, inSessionFlag))
		// Keep primary error as first
		if err != nil {
			return
		}
		// Ignore unexisting running session flag
		if errors.Is(errRemove, os.ErrNotExist) {
			return
		}
	}()

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
		log.Debugf(ctx, "Running script %q", script)
		// #nosec G204 - this variable is coming from concatenation of an order file.
		// Permissions are restricted to the owner of the order file, which is the one executing
		// this script.
		cmd := exec.CommandContext(ctx, script)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Warningf(ctx, "%q failed to run\n%v", script, err)
		}
	}

	return nil
}

func mkdirAllWithUIDGid(p string, uid, gid int) error {
	if err := os.MkdirAll(p, 0750); err != nil {
		return fmt.Errorf(i18n.G("can't create scripts directory %q: %v"), p, err)
	}

	return chown(p, nil, uid, gid)
}

func createFlagFile(ctx context.Context, path string, uid, gid int) (err error) {
	defer decorate.OnError(&err, i18n.G("can't create flag file %q"), path)

	log.Debugf(ctx, "Create script flag %q", path)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := chown(path, f, uid, gid); err != nil {
		return err
	}
	return nil
}

// chown either chown the file descriptor attached, or the path if this one is null to uid and gid.
// It will know if we should skip chown for tests.
func chown(p string, f *os.File, uid, gid int) (err error) {
	defer decorate.OnError(&err, i18n.G("can't chown %q"), p)

	if os.Getenv("ADSYS_SKIP_ROOT_CALLS") != "" {
		uid = -1
		gid = -1
	}

	if f == nil {
		// Ensure that if p is a symlink, we only change the symlink itself, not what was pointed by it.
		return os.Lchown(p, uid, gid)
	}

	return f.Chown(uid, gid)
}

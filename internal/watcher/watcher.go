package watcher

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/kardianos/service"
	"github.com/ubuntu/adsys/internal/decorate"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"gopkg.in/ini.v1"
)

const (
	gptFileName = "gpt.ini"
)

// Watcher provides options necessary to watch a directory and its children.
type Watcher struct {
	dirs      []string
	parentCtx context.Context
	cancel    context.CancelFunc
	watching  chan struct{}

	refreshDuration time.Duration
}

// options are the configurable functional options for the watcher.
type options struct {
	refreshDuration time.Duration
}
type option func(*options) error

// New returns a new Watcher instance.
func New(ctx context.Context, dirs []string, opts ...option) (*Watcher, error) {
	if len(dirs) == 0 {
		return nil, errors.New(i18n.G("no directories to watch"))
	}

	// Set default options
	args := options{
		refreshDuration: 10 * time.Second,
	}
	// Override default options with user-provided ones
	for _, o := range opts {
		if err := o(&args); err != nil {
			return nil, err
		}
	}

	return &Watcher{
		dirs: dirs,

		parentCtx:       ctx,
		refreshDuration: args.refreshDuration,
	}, nil
}

// Dirs returns the directories currently being watched.
func (w *Watcher) Dirs() []string {
	return w.dirs
}

// Start is called by the service manager to start the watcher service.
// Documentation states that the function should not block but run
// asynchronously. When our function exits, the service manager registers a
// signal handler that calls Stop when a signal is received.
func (w *Watcher) Start(s service.Service) (err error) {
	decorate.OnError(&err, i18n.G("can't start service"))

	return w.startWatch(w.parentCtx, w.dirs)
}

// Stop is called by the service manager to stop the watcher service.
// Documentation states that the function should not take more than a few
// seconds to execute.
func (w *Watcher) Stop(s service.Service) (err error) {
	decorate.OnError(&err, i18n.G("can't stop service"))

	return w.stopWatch(w.parentCtx)
}

// startWatch starts the actual watch loop in a goroutine.
func (w *Watcher) startWatch(ctx context.Context, dirs []string) error {
	ctx, cancel := context.WithCancel(w.parentCtx)
	w.cancel = cancel

	w.watching = make(chan struct{})
	initError := make(chan error)
	go func() {
		if errWatching := w.watch(ctx, w.dirs, initError); errWatching != nil {
			log.Warningf(ctx, i18n.G("Watch failed: %v"), errWatching)
		}
	}()
	return <-initError
}

// stopWatch stops the watch loop.
func (w *Watcher) stopWatch(ctx context.Context) error {
	if w.cancel == nil {
		return errors.New(i18n.G("the service is already stopping or not running"))
	}

	w.cancel()
	w.cancel = nil

	// wait for watching to be closed
	for {
		_, ok := <-w.watching
		if ok {
			continue
		}
		break
	}

	return nil
}

// UpdateDirs restarts watch loop with new directories. No action is taken if
// one or more directories do not exist.
func (w *Watcher) UpdateDirs(dirs []string) (err error) {
	decorate.OnError(&err, i18n.G("can't update directories to watch"))
	for _, dir := range dirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return fmt.Errorf(i18n.G("directory %q does not exist"), dir)
		}
	}

	log.Debugf(w.parentCtx, i18n.G("Updating directories to %v"), dirs)

	if err := w.stopWatch(w.parentCtx); err != nil {
		return err
	}

	w.dirs = dirs
	return w.startWatch(w.parentCtx, dirs)
}

// watch is the main watch loop.
func (w *Watcher) watch(ctx context.Context, dirs []string, initError chan<- error) (err error) {
	decorate.OnError(&err, i18n.G("can't watch over %v"), dirs)
	defer close(w.watching)

	fsWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		initError <- fmt.Errorf(i18n.G("could not initialize fsnotify watcher: %v"), err)
	}
	defer fsWatcher.Close()

	// Collect directories to watch.
	for _, dir := range dirs {
		if err := watchSubDirs(ctx, fsWatcher, dir); err != nil {
			initError <- fmt.Errorf(i18n.G("failed to watch directory %q: %v"), dir, err)
		}
	}

	// We configure a timer for a grace period without changes before committing any changes.
	refreshTimer := time.NewTimer(w.refreshDuration)
	defer refreshTimer.Stop()
	refreshTimer.Stop()

	// Collect directories to watch.
	var modifiedRootDirs []string
	initError <- nil
	for {
		select {
		case event, ok := <-fsWatcher.Events:
			if !ok {
				continue
			}
			log.Debugf(ctx, i18n.G("Got event: %v"), event)

			// If the modified file is our own change, ignore it.
			if strings.ToLower(filepath.Base(event.Name)) == gptFileName {
				continue
			}

			if event.Op&fsnotify.Create == fsnotify.Create {
				fileInfo, err := os.Stat(event.Name)
				if err != nil {
					log.Warningf(ctx, i18n.G("Failed to stat: %s"), err)
					continue
				}

				// Add new detected files and directories to the watch list.
				if fileInfo.IsDir() {
					if err := watchSubDirs(ctx, fsWatcher, event.Name); err != nil {
						log.Warningf(ctx, i18n.G("Failed to watch: %s"), err)
					}
				} else if fileInfo.Mode().IsRegular() {
					fsWatcher.Add(event.Name)
				}
			}

			// Remove deleted or renamed files/directories from the watch list.
			if event.Op&fsnotify.Remove == fsnotify.Remove || event.Op&fsnotify.Rename == fsnotify.Rename {
				fsWatcher.Remove(event.Name)
			}

			// Check there is something to update
			if !(event.Op&fsnotify.Write == fsnotify.Write ||
				event.Op&fsnotify.Create == fsnotify.Create || // Rename is always followed by a Create.
				event.Op&fsnotify.Remove == fsnotify.Remove) {
				continue
			}

			// Find and add matching root directory if not already present in the list to refresh.
			rootDir, err := getRootDir(event.Name, dirs)
			if err != nil {
				log.Warning(ctx, err)
				continue
			}
			var alreadyAdded bool
			for _, modifiedRootDir := range modifiedRootDirs {
				if rootDir != modifiedRootDir {
					continue
				}
				alreadyAdded = true
				break
			}
			if !alreadyAdded {
				modifiedRootDirs = append(modifiedRootDirs, rootDir)
			}

			// Stop means that the timer expired, not that it was stopped, so
			// drain the channel only if there is something to drain.
			if !refreshTimer.Stop() {
				select {
				case <-refreshTimer.C:
				default:
				}
			}

			// We got a change, so reset the timer to the grace period.
			refreshTimer.Reset(w.refreshDuration)

		case err, ok := <-fsWatcher.Errors:
			if ok {
				log.Warningf(ctx, i18n.G("Got event error: %v"), err)
			}
			continue

		case <-refreshTimer.C:
			// Update relevant GPT.ini files.
			updateVersions(ctx, modifiedRootDirs)

		case <-ctx.Done():
			log.Infof(ctx, i18n.G("Watcher stopped"))
			// Check if there was a timer in progress to not miss an update before exiting.
			if refreshTimer.Stop() {
				updateVersions(ctx, modifiedRootDirs)
			}
			return nil
		}
	}
}

// watchSubDirs walks a given directory and adds all subdirectories to the watch list.
func watchSubDirs(ctx context.Context, fsWatcher *fsnotify.Watcher, path string) (err error) {
	decorate.OnError(&err, i18n.G("can't watch directory and children of %s"), path)
	log.Debugf(ctx, i18n.G("Watching %s and children"), path)

	err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		log.Debugf(ctx, i18n.G("Watching: %v"), p)
		return fsWatcher.Add(p)
	})
	return err
}

// getRootDir returns the configured directory of the given file path. It
// handles nested directories by returning the most nested one. It ensures paths
// are compatible by normalizing them first (e.g. removing trailing slashes,
// replacing backslashes with slashes).
func getRootDir(path string, rootDirs []string) (string, error) {
	path = filepath.ToSlash(filepath.Clean(path))
	var rootDir string
	var currentRootDirLength int
	for _, root := range rootDirs {
		root = filepath.ToSlash(filepath.Clean(root))
		if strings.HasPrefix(path, root) {
			// Make sure we take into account the possibility of nested
			// configured directories.
			if len(root) <= currentRootDirLength {
				continue
			}
			rootDir = root
			currentRootDirLength = len(root)
		}
	}
	if rootDir == "" {
		return "", fmt.Errorf(i18n.G("no root directory matching %s found"), path)
	}

	return rootDir, nil
}

// updateVersions updates the GPT.ini files of the given directories.
func updateVersions(ctx context.Context, modifiedRootDirs []string) {
	for _, dir := range modifiedRootDirs {
		gptIniPath := filepath.Join(dir, gptFileName)
		if err := bumpVersion(ctx, gptIniPath); err != nil {
			log.Warningf(ctx, i18n.G("Failed to bump %s version: %s"), gptIniPath, err)
		}
	}
}

// bumpVersion does the actual bumping of the version in the given GPT.ini file.
func bumpVersion(ctx context.Context, path string) (err error) {
	decorate.OnError(&err, i18n.G("can't bump version for %s"), path)
	log.Infof(ctx, i18n.G("Bumping version for %s"), path)

	cfg, err := ini.Load(path)

	// If the file doesn't exist, create it and initialize the key to be updated.
	if err != nil {
		log.Warningf(ctx, i18n.G("error loading ini contents: %v, creating a new file"), err)
		cfg = ini.Empty()
		cfg.Section("General").NewKey("Version", "0")
	}

	v, err := cfg.Section("General").Key("Version").Int()

	// Error out if the key is absent or malformed.
	if err != nil {
		return err
	}

	// Increment the version and write it back to the file.
	v++
	cfg.Section("General").Key("Version").SetValue(strconv.Itoa(v))

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = cfg.WriteTo(f)

	return err
}

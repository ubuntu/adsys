package watchdservice

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kardianos/service"
	"github.com/ubuntu/adsys/internal/decorate"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/loghooks"
	"github.com/ubuntu/adsys/internal/watchdhelpers"
	"github.com/ubuntu/adsys/internal/watcher"
)

// WatchdService contains the service and watcher.
type WatchdService struct {
	service service.Service
	watcher *watcher.Watcher

	options options
}

// options are the configurable functional options for the service.
type options struct {
	dirs        []string
	extraArgs   []string
	name        string
	userService bool
	interactive bool
}
type option func(*options) error

// WithDirs allows overriding default directories to watch.
func WithDirs(dirs []string) func(o *options) error {
	return func(o *options) error {
		o.dirs = dirs
		return nil
	}
}

// WithArgs allows adding additional arguments to the service.
func WithArgs(args []string) func(o *options) error {
	return func(o *options) error {
		o.extraArgs = args
		return nil
	}
}

// WithName allows setting a custom name to the service.
func WithName(name string) func(o *options) error {
	return func(o *options) error {
		o.name = name
		return nil
	}
}

// Name returns the name of the service.
func (s *WatchdService) Name() string {
	return s.options.name
}

// New returns a new WatchdService instance.
func New(ctx context.Context, opts ...option) (*WatchdService, error) {
	// Set default options.
	args := options{
		name: "adwatchd",
	}

	// Apply given options.
	for _, o := range opts {
		if err := o(&args); err != nil {
			return nil, err
		}
	}

	var w *watcher.Watcher
	var err error
	if len(args.dirs) > 0 {
		if w, err = watcher.New(ctx, args.dirs); err != nil {
			return nil, err
		}
	}

	// Create service options.
	svcOptions := make(service.KeyValue)
	svcOptions["UserService"] = args.userService
	svcArguments := append([]string{"run"}, args.extraArgs...)

	config := service.Config{
		Name:        args.name,
		DisplayName: "Active Directory Watch Daemon",
		Description: "Monitors configured directories for changes and increases the associated GPT.ini version.",
		Arguments:   svcArguments,
		Option:      svcOptions,
	}
	s, err := service.New(w, &config)
	if err != nil {
		return nil, err
	}

	// If we're not running in interactive mode (CLI), add a hook to the logger
	// so that the service can log to the Windows Event Log.
	if !service.Interactive() {
		logger, err := s.Logger(nil)
		if err != nil {
			return nil, err
		}
		log.AddHook(ctx, &loghooks.EventLog{Logger: logger})
	}

	return &WatchdService{
		service: s,
		watcher: w,
		options: args,
	}, nil
}

// UpdateDirs updates the watcher with the new directories.
func (s *WatchdService) UpdateDirs(ctx context.Context, dirs []string) (err error) {
	decorate.OnError(&err, i18n.G("failed to change directories to watch"))
	log.Info(ctx, i18n.G("Updating directories to watch"))

	if err := s.watcher.UpdateDirs(dirs); err != nil {
		return err
	}

	// Make sure we update the options struct as well.
	s.options.dirs = dirs
	return nil
}

// Start starts the watcher service.
func (s *WatchdService) Start(ctx context.Context) (err error) {
	decorate.OnError(&err, i18n.G("failed to start service"))
	log.Info(ctx, i18n.G("Starting service"))

	stat, err := s.service.Status()
	if err != nil {
		return err
	}

	// Only start if the service is not running.
	if stat == service.StatusRunning {
		return nil
	}

	if err := s.service.Start(); err != nil {
		return err
	}

	return s.waitForStatus(ctx, service.StatusRunning)
}

// Stop stops the watcher service.
func (s *WatchdService) Stop(ctx context.Context) (err error) {
	decorate.OnError(&err, i18n.G("failed to stop service"))
	log.Info(ctx, i18n.G("Stopping service"))

	stat, err := s.service.Status()
	if err != nil {
		return err
	}

	// Only stop if the service is not stopped.
	if stat == service.StatusStopped {
		return nil
	}

	if err := s.service.Stop(); err != nil {
		return err
	}

	return s.waitForStatus(ctx, service.StatusStopped)
}

func (s *WatchdService) waitForStatus(ctx context.Context, status service.Status) error {
	// Check that the service updated correctly.
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var gotStatus bool
	for !gotStatus {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			newStatus, _ := s.service.Status()
			if newStatus != status {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			gotStatus = true
			break
		}
	}
	return nil
}

// Restart restarts the watcher service.
func (s *WatchdService) Restart(ctx context.Context) (err error) {
	decorate.OnError(&err, i18n.G("failed to restart service"))
	log.Info(ctx, i18n.G("Restarting service"))

	stat, err := s.service.Status()
	if err != nil {
		return err
	}

	// Only stop if the service is running.
	if stat == service.StatusRunning {
		if err := s.service.Stop(); err != nil {
			return err
		}
	}

	if err := s.service.Start(); err != nil {
		return err
	}

	return nil
}

// Status provides a status of the watcher service in a pretty format.
func (s *WatchdService) Status(ctx context.Context) (status string, err error) {
	decorate.OnError(&err, i18n.G("failed to retrieve status for service"))
	log.Debug(ctx, i18n.G("Getting status from service"))

	uninstalledState := service.Status(42)
	stat, err := s.service.Status()
	if errors.Is(err, service.ErrNotInstalled) {
		stat = uninstalledState
	} else if err != nil {
		return "", err
	}

	var serviceStatus string
	switch stat {
	case service.StatusRunning:
		serviceStatus = i18n.G("running")
	case service.StatusStopped:
		serviceStatus = i18n.G("stopped")
	case service.StatusUnknown:
		serviceStatus = i18n.G("unknown")
	case uninstalledState:
		serviceStatus = i18n.G("not installed")
	default:
		serviceStatus = i18n.G("undefined")
	}

	// If the service is installed, attempt to figure out the configured
	// directories.
	var dirs []string
	configFile := i18n.G("no config file")
	if stat != uninstalledState {
		configFile, dirs, err = s.getConfigAndDirsFromArgs()
		if err != nil {
			log.Warningf(ctx, i18n.G("Failed to get directories from service arguments: %v"), err)
		}
	}

	var statStr strings.Builder
	statStr.WriteString(fmt.Sprintf(i18n.G("Service status: %s"), serviceStatus))
	statStr.WriteString("\n\n")
	statStr.WriteString(fmt.Sprintf(i18n.G("Config file: %s\n"), configFile))
	statStr.WriteString(i18n.G("Watched directories: "))

	if len(dirs) == 0 {
		statStr.WriteString(i18n.G("no configured directories"))
	}

	for _, dir := range dirs {
		statStr.WriteString(fmt.Sprintf("\n  - %s", dir))
	}
	status = statStr.String()

	return status, nil
}

// getDirsFromArgs returns the directories to watch from the service arguments.
func (s *WatchdService) getConfigAndDirsFromArgs() (string, []string, error) {
	args, err := s.getServiceArgs()
	if err != nil {
		return "", nil, fmt.Errorf(i18n.G("failed to get service args: %v"), err)
	}

	configFile, err := watchdhelpers.GetConfigFileFromArgs(args)
	if err != nil {
		return "", nil, fmt.Errorf(i18n.G("failed to get config file from args: %v"), err)
	}

	return configFile, watchdhelpers.GetDirsFromConfigFile(configFile), nil
}

// Install installs the watcher service and starts it if it doesn't
// automatically start in due time.
func (s *WatchdService) Install(ctx context.Context) (err error) {
	decorate.OnError(&err, i18n.G("failed to install service"))
	log.Info(ctx, i18n.G("Installing watcher service"))
	if err := s.service.Install(); err != nil {
		return err
	}

	if err := s.waitForStatus(ctx, service.StatusRunning); err != nil {
		// Try to start it (not all platforms try to start it after installing)
		return s.service.Start()
	}

	return nil
}

// Uninstall uninstalls the watcher service. If the service is not installed it
// logs a message and returns. If the service is running it attempts to stop it
// first.
func (s *WatchdService) Uninstall(ctx context.Context) (err error) {
	decorate.OnError(&err, i18n.G("failed to uninstall service"))
	log.Info(ctx, i18n.G("Uninstalling watcher service"))

	stat, err := s.service.Status()
	if errors.Is(err, service.ErrNotInstalled) {
		log.Info(ctx, i18n.G("Service is not installed"))
		return nil
	}

	// Stop the service first if running
	if stat == service.StatusRunning {
		if err := s.service.Stop(); err != nil {
			return err
		}
	}

	return s.service.Uninstall()
}

// Run runs the watcher service.
func (s *WatchdService) Run(ctx context.Context) (err error) {
	decorate.OnError(&err, i18n.G("failed to run service"))

	log.Info(ctx, i18n.G("Running watcher service"))
	return s.service.Run()
}

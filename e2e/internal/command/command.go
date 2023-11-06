// Package command provides a framework to create CLI commands.
package command

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/mitchellh/go-homedir"
	log "github.com/sirupsen/logrus"
	"github.com/ubuntu/adsys/e2e/internal/inventory"
)

const (
	// DefaultSSHKeyPath is the default path to the SSH private key.
	DefaultSSHKeyPath = "~/.ssh/adsys-e2e.pem"
)

type cmdFunc func(context.Context, *Command) error

type globalFlags struct {
	InventoryFile string
	Debug         bool
	Help          bool
}

// Command is a command that can be executed.
type Command struct {
	GlobalFlags globalFlags
	Inventory   inventory.Inventory
	Usage       string

	validate cmdFunc
	action   cmdFunc

	fSet *flag.FlagSet

	fromState inventory.State
	toState   inventory.State
}

// WithStateTransition sets the expected state transition for the command.
func WithStateTransition(from, to inventory.State) func(*options) {
	return func(a *options) {
		a.fromState = from
		a.toState = to
	}
}

// WithValidateFunc sets the validation function for the command.
func WithValidateFunc(validate cmdFunc) func(*options) {
	return func(a *options) {
		a.validate = validate
	}
}

type options struct {
	validate  cmdFunc
	fromState inventory.State
	toState   inventory.State
}

// Option is a function that configures the command.
type Option func(*options)

// New creates a new command.
func New(action cmdFunc, args ...Option) *Command {
	// Apply given options
	opts := options{
		fromState: inventory.Null,
		toState:   inventory.Null,
	}

	for _, f := range args {
		f(&opts)
	}

	return &Command{
		action:   action,
		validate: opts.validate,

		fSet:      flag.NewFlagSet("", flag.ContinueOnError),
		fromState: opts.fromState,
		toState:   opts.toState,
	}
}

// ValidateAndExpandPath expands the given path, checks if it exists and falls
// back to the given default if not.
func ValidateAndExpandPath(path, def string) (string, error) {
	if path == "" {
		path = def
	}
	expandedPath, err := homedir.Expand(path)
	if err != nil {
		return "", fmt.Errorf("failed to expand path: %w", err)
	}
	path = expandedPath
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("path %q does not exist: %w", path, err)
	}

	return path, nil
}

// AddStringFlag adds a string flag to the command.
func (c *Command) AddStringFlag(param *string, name, value, usage string) {
	c.fSet.StringVar(param, name, value, usage)
}

// AddBoolFlag adds a boolean flag to the command.
func (c *Command) AddBoolFlag(param *bool, name string, value bool, usage string) {
	c.fSet.BoolVar(param, name, value, usage)
}

func (c *Command) setGlobalFlags() {
	c.fSet.StringVar(&c.GlobalFlags.InventoryFile, "i", inventory.DefaultPath, "Use custom inventory file")
	c.fSet.StringVar(&c.GlobalFlags.InventoryFile, "inventory-file", inventory.DefaultPath, "Use custom inventory file")
	c.fSet.BoolVar(&c.GlobalFlags.Debug, "debug", false, "Enable debug logging")
	c.fSet.BoolVar(&c.GlobalFlags.Debug, "d", false, "Enable debug logging")
	c.fSet.BoolVar(&c.GlobalFlags.Help, "help", false, "Print this message")
	c.fSet.BoolVar(&c.GlobalFlags.Help, "h", false, "Print this message")
}

func (c *Command) parseFlags(args []string) (showedUsage bool, err error) {
	c.setGlobalFlags()
	c.fSet.Usage = func() {
		err = errors.New("usage error")
		showedUsage = true

		fmt.Fprintf(os.Stderr, `Usage:
%s

Global Flags:
 -i, --inventory-file    use custom inventory file (default: %s)
 -d, --debug             enable debug logging (default: false)
 -h, --help              print this message and exit
`, c.Usage, inventory.DefaultPath)
	}

	parseErr := c.fSet.Parse(args)
	if len(c.fSet.Args()) > 0 || parseErr != nil {
		return true, errors.New("usage error")
	}

	if c.GlobalFlags.Debug {
		log.SetLevel(log.DebugLevel)
	}

	if c.GlobalFlags.Help {
		c.fSet.Usage()
		return true, nil
	}

	return showedUsage, err
}

// Execute runs the command and returns the exit code.
func (c *Command) Execute(ctx context.Context) int {
	ctx, cancel := context.WithCancel(ctx)
	defer c.installSignalHandler(cancel)()

	showedUsage, err := c.parseFlags(os.Args[1:])
	if showedUsage {
		if err != nil {
			return 2
		}
		return 0
	}

	if err != nil {
		log.Error(err)
		return 1
	}

	if c.requireInventory() {
		c.Inventory, err = inventory.Read(c.GlobalFlags.InventoryFile)
		log.Debugf("Inventory: %+v", c.Inventory)
		if err != nil {
			log.Errorf("Failed to read inventory file required by the current script: %s. Please refer to the previous script in the series", err)
			return 1
		}

		if c.Inventory.State != c.fromState {
			log.Errorf("Inventory file is not in the expected state: %s", c.fromState)
			return 1
		}
	}

	if c.validate != nil {
		if err := c.validate(ctx, c); err != nil {
			log.Error(err)
			return 1
		}
	}

	if err := c.action(ctx, c); err != nil {
		log.Error(err)
		return 1
	}

	// Don't write the state if we're transitioning to Null
	c.Inventory.State = c.toState
	if c.Inventory.State != inventory.Null {
		log.Debugf("Writing inventory file: %+v", c.Inventory)
		if err := inventory.Write(c.GlobalFlags.InventoryFile, c.Inventory); err != nil {
			log.Error(err)
			return 1
		}
	}

	return 0
}

func (c *Command) requireInventory() bool {
	return c.fromState != inventory.Null
}

func (c *Command) installSignalHandler(cancel context.CancelFunc) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			switch v, ok := <-ch; v {
			case syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM:
				log.Infof("Received signal %s, exiting...", v)
				cancel()
				return
			default:
				// channel was closed: we exited
				if !ok {
					return
				}
			}
		}
	}()

	return func() {
		signal.Stop(ch)
		close(ch)
		wg.Wait()
	}
}

package watchd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ubuntu/adsys/internal/decorate"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"gopkg.in/yaml.v2"
)

// CmdName is the binary name for the daemon.
const CmdName = "adwatchd"

// AppConfig represents the configurable options of the application.
type AppConfig struct {
	Verbose int
	Force   bool `yaml:"-"` // This is a CLI-only option
	Dirs    []string
}

// DirsFromConfigFile unmarshals and returns the directories from the passed in
// config file.
func DirsFromConfigFile(ctx context.Context, configFile string) []string {
	var dirs []string
	config, err := os.ReadFile(configFile)
	if err != nil {
		log.Debugf(ctx, i18n.G("Could not read config file: %v"), err)
		return dirs
	}
	cfg := AppConfig{}
	if err := yaml.Unmarshal(config, &cfg); err != nil {
		log.Debugf(ctx, i18n.G("Could not unmarshal config YAML: %v"), err)
		return dirs
	}
	dirs = cfg.Dirs

	return dirs
}

// WriteConfig writes the config to the given file, checking whether the
// directories that are passed in actually exist. It receives a config file and
// a slice of absolute sorted paths.
func WriteConfig(confFile string, dirs []string) (err error) {
	defer decorate.OnError(&err, i18n.G("can't write config"))

	if len(dirs) == 0 {
		return fmt.Errorf(i18n.G("needs at least one directory to watch"))
	}

	// Make sure all directories exist
	for _, dir := range dirs {
		if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf(i18n.G("directory %q does not exist"), dir)
		}
	}

	// Make sure the directory structure exists for the config file
	if err := os.MkdirAll(filepath.Dir(confFile), 0750); err != nil {
		return fmt.Errorf(i18n.G("unable to create config directory: %v"), err)
	}

	cfg := AppConfig{Dirs: dirs, Verbose: 0}
	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return fmt.Errorf(i18n.G("unable to marshal: %v"), err)
	}

	if err := os.WriteFile(confFile, data, 0600); err != nil {
		return err
	}

	return nil
}

// ConfigFileFromArgs returns the path to the config file extracted from the
// command line arguments.
//
// This is not an exhaustive implementation of "parsing" the command line and
// only covers the cases used by the service installer, which should be good
// enough for us.
func ConfigFileFromArgs(args string) (string, error) {
	err := fmt.Errorf(i18n.G("missing config file in CLI arguments"))

	_, configFile, found := strings.Cut(args, "-c")
	if !found {
		return configFile, err
	}

	// Remove trailing quotes and spaces (quotes are added if the path to the
	// config file contains spaces)
	configFile = strings.Trim(configFile, `" `)
	if configFile == "" {
		return "", err
	}
	return configFile, nil
}

// DefaultConfigPath returns the default path to the config file inferred from
// the current executable directory.
func DefaultConfigPath() string {
	binPath, err := os.Executable()
	if err != nil {
		log.Warningf(context.Background(), i18n.G("failed to get executable path, using relative path for default config: %v"), err)
	}
	return filepath.Join(filepath.Dir(binPath), fmt.Sprintf("%s.yaml", CmdName))
}

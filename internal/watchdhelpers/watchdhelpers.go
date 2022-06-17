package watchdhelpers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"gopkg.in/yaml.v2"
)

// AppConfig represents the configurable options of the application.
type AppConfig struct {
	Verbose int
	Force   bool
	Dirs    []string
}

// GetDirsFromConfigFile unmarshals and returns the directories from the passed in
// config file.
func GetDirsFromConfigFile(configFile string) []string {
	var dirs []string
	config, err := os.ReadFile(configFile)
	if err != nil {
		return dirs
	}
	cfg := AppConfig{}
	if err := yaml.Unmarshal(config, &cfg); err == nil {
		dirs = cfg.Dirs
	}
	return dirs
}

// FilterAbsentDirs returns only the existing directories from the passed in
// slice.
func FilterAbsentDirs(dirs []string) []string {
	var filtered []string
	for _, dir := range dirs {
		if stat, err := os.Stat(dir); err == nil && stat.IsDir() {
			filtered = append(filtered, dir)
		}
	}
	return filtered
}

// WriteConfig writes the config to the given file, checking whether the
// directories that are passed in actually exist. It receives a config file and
// a slice of absolute sorted paths.
func WriteConfig(confFile string, dirs []string) error {
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
		return fmt.Errorf(i18n.G("unable to marshal config: %v"), err)
	}

	if err := os.WriteFile(confFile, data, 0600); err != nil {
		return fmt.Errorf(i18n.G("unable to write config file: %v"), err)
	}

	return nil
}

// GetConfigFileFromArgs returns the path to the config file extracted from the
// command line arguments.
//
// This is not an exhaustive implementation of "parsing" the command line and
// only covers the cases used by the service installer, which should be good
// enough for us.
func GetConfigFileFromArgs(args string) (string, error) {
	_, configFile, found := strings.Cut(args, "-c")
	if !found {
		return "", fmt.Errorf(i18n.G("missing config file in CLI arguments"))
	}

	// Remove trailing quotes and spaces (quotes are added if the path to the
	// config file contains spaces)
	configFile = strings.Trim(configFile, `" `)
	return configFile, nil
}

func DefaultConfigPath() string {
	binPath, err := os.Executable()
	if err != nil {
		log.Warningf(context.Background(), i18n.G("failed to get executable path, using relative path for default config: %v"), err)
	}
	return filepath.Join(filepath.Dir(binPath), "adwatchd.yml")
}

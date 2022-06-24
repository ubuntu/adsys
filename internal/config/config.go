package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/ubuntu/adsys/internal/consts"
	"github.com/ubuntu/adsys/internal/decorate"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
)

// SetVerboseMode change ErrorFormat and logs between very, middly and non verbose.
func SetVerboseMode(level int) {
	var reportCaller bool
	switch level {
	case 0:
		logrus.SetLevel(consts.DefaultLogLevel)
	case 1:
		logrus.SetLevel(logrus.InfoLevel)
	case 3:
		reportCaller = true
		fallthrough
	default:
		logrus.SetLevel(logrus.DebugLevel)
	}
	log.SetReportCaller(reportCaller)
}

// Init sets verbosity level and add config env variables and file support based on name prefix.
// It calls immediately the configChanged function with refreshed set to false (as this is the first call)
// to let you deserialize the initial configuration and returns any errors.
// Then, it automatically watches any configuration changes and will call configChanged with refresh set to true.
func Init(name string, cmd cobra.Command, vip *viper.Viper, configChanged func(refreshed bool) error) (err error) {
	defer decorate.OnError(&err, i18n.G("can't load configuration"))

	// Force a visit of the local flags so persistent flags for all parents are merged.
	cmd.LocalFlags()

	// Get cmdline flag for verbosity to configure logger until we have everything parsed.
	v, err := cmd.Flags().GetCount("verbose")
	if err != nil {
		return fmt.Errorf("internal error: no persistent verbose flag installed on cmd: %w", err)
	}

	SetVerboseMode(v)

	if v, err := cmd.Flags().GetString("config"); err == nil && v != "" {
		vip.SetConfigFile(v)
	} else {
		vip.SetConfigName(name)
		vip.AddConfigPath("./")
		vip.AddConfigPath("$HOME/")
		vip.AddConfigPath("/etc/")
		// Add the executable path to the config search path.
		if binPath, err := os.Executable(); err != nil {
			log.Warningf(context.Background(), i18n.G("Failed to get current executable path, not adding it as a config dir: %v"), err)
		} else {
			vip.AddConfigPath(filepath.Dir(binPath))
		}
	}

	if err := vip.ReadInConfig(); err != nil {
		var e viper.ConfigFileNotFoundError
		if errors.As(err, &e) {
			log.Infof(context.Background(), "No configuration file: %v.\nWe will only use the defaults, env variables or flags.", e)
		} else {
			return fmt.Errorf("invalid configuration file: %w", err)
		}
	} else {
		log.Infof(context.Background(), "Using configuration file: %v", vip.ConfigFileUsed())
		vip.WatchConfig()
		vip.OnConfigChange(func(e fsnotify.Event) {
			if e.Op != fsnotify.Write {
				return
			}
			log.Infof(context.Background(), "Config file %q changed. Reloading.", e.Name)
			if err := configChanged(true); err != nil {
				log.Warningf(context.Background(), "Error while refreshing configuration: %v", err)
			}
		})
	}

	vip.SetEnvPrefix(name)
	vip.AutomaticEnv()

	if err := configChanged(false); err != nil {
		return err
	}

	return nil
}

// LoadConfig takes c and unmarshall current configuration to it.
func LoadConfig(c interface{}, viper *viper.Viper) error {
	if err := viper.Unmarshal(&c); err != nil {
		return fmt.Errorf("unable to decode configuration into struct: %w", err)
	}
	return nil
}

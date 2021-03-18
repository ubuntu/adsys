package config

import (
	"errors"
	"fmt"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/ubuntu/adsys/internal/decorate"
	"github.com/ubuntu/adsys/internal/i18n"
)

// TEXTDOMAIN is the gettext domain for l10n
const TEXTDOMAIN = "adsys"

// SetVerboseMode change ErrorFormat and logs between very, middly and non verbose
func SetVerboseMode(level int) {
	switch level {
	case 0:
		log.SetLevel(defaultLevel)
	case 1:
		log.SetLevel(log.InfoLevel)
	case 3:
		log.SetReportCaller(true)
		fallthrough
	default:
		log.SetLevel(log.DebugLevel)
	}
}

// Configure sets verbosity level and add config env variables and file support based on name prefix.
// It call the refreshConfig function so that you can deserialized the configuration and returns any error.
// It automatically watches any configuration changes and will call refreshConfig with the config file that changed
// passed as an argument. No config path is the initial loading.
func Configure(name string, rootCmd cobra.Command, vip *viper.Viper, refreshConfig func(configPath string) error) (err error) {
	defer decorate.OnError(&err, i18n.G("can't load configuration"))

	// Get cmdline flag for verbosity to configure logger until we have everything parsed.
	v, err := rootCmd.PersistentFlags().GetCount("verbose")
	if err != nil {
		return fmt.Errorf("internal error: no persistent verbose flag installed on rootCmd: %v", err)
	}

	SetVerboseMode(v)

	if v, err := rootCmd.PersistentFlags().GetString("config"); err == nil && v != "" {
		vip.SetConfigFile(v)
	} else {
		vip.SetConfigName(name)
		vip.AddConfigPath("./")
		vip.AddConfigPath("$HOME/")
		vip.AddConfigPath("/etc/")
	}

	if err := vip.ReadInConfig(); err != nil {
		var e viper.ConfigFileNotFoundError
		if errors.As(err, &e) {
			log.Infof("No configuration file: %v.\nWe will use the defaults, env variables or flags.", e)
		} else {
			return fmt.Errorf("invalid configuration file: %v", err)
		}
	} else {
		log.Infof("Using configuration file: %v", vip.ConfigFileUsed())
		vip.WatchConfig()
		vip.OnConfigChange(func(e fsnotify.Event) {
			if e.Op != fsnotify.Write {
				return
			}
			if err := refreshConfig(e.Name); err != nil {
				log.Warningf("Error while refreshing configuration: %v", err)
			}
		})
	}

	vip.SetEnvPrefix(name)
	vip.AutomaticEnv()

	if err := refreshConfig(""); err != nil {
		return err
	}

	return nil
}

// DefaultLoadConfig takes c and unmarshall the config to it.
func DefaultLoadConfig(c interface{}, viper *viper.Viper) error {
	if err := viper.Unmarshal(&c); err != nil {
		return fmt.Errorf("unable to decode configuration into struct: %v", err)
	}
	return nil
}

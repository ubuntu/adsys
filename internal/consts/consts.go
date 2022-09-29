// Package consts defines the constants used by the project
package consts

import log "github.com/sirupsen/logrus"

var (
	// Version is the version of the executable.
	Version = "dev"
)

const (
	// TEXTDOMAIN is the gettext domain for l10n.
	TEXTDOMAIN = "adsys"

	// DefaultLogLevel is the default logging level selected without any option.
	DefaultLogLevel = log.WarnLevel

	// DefaultSocket is the default socket path.
	DefaultSocket = "/run/adsysd.sock"

	// DefaultCacheDir is the default path for adsys system cache directory.
	DefaultCacheDir = "/var/cache/adsys"

	// DefaultRunDir is the default path for adsys run directory.
	DefaultRunDir = "/run/adsys"

	// DefaultClientTimeout is the maximum default time in seconds between 2 server activities before the client returns and abort the request.
	DefaultClientTimeout = 30

	// DefaultServiceTimeout is the default time in seconds without any active request before the service exits.
	DefaultServiceTimeout = 120

	// DistroID is the distro ID which can be overridden at build time.
	DistroID = "Ubuntu"

	// StartupScriptsMachineBaseDir is the base directory for machine startup scripts.
	StartupScriptsMachineBaseDir = "startup"

	// AdysMachineScriptsServiceName is the machine script systemd service.
	AdysMachineScriptsServiceName = "adsys-machine-scripts.service"

	// SSSD related properties.

	// DefaultSSSCacheDir is the default sssd cache dir.
	DefaultSSSCacheDir = "/var/lib/sss/db"
	// DefaultSSSConf is the default sssd.conf location.
	DefaultSSSConf = "/etc/sssd/sssd.conf"
	// DefaultDconfDir is the default dconf directory.
	DefaultDconfDir = "/etc/dconf"
	// DefaultSudoersDir is the default directory for sudoers configuration.
	DefaultSudoersDir = "/etc/sudoers.d"
	// DefaultPolicyKitDir is the default directory for policykit configuration and rules.
	DefaultPolicyKitDir = "/etc/polkit-1"

	// SSSDDbusRegisteredName is the well-known name used on dbus.
	SSSDDbusRegisteredName = "org.freedesktop.sssd.infopipe"
	// SSSDDbusBaseObjectPath is the path under which all domains are registered.
	SSSDDbusBaseObjectPath = "/org/freedesktop/sssd/infopipe/Domains"
	// SSSDDbusInterface is the interface we are using for access dbus methods.
	SSSDDbusInterface = "org.freedesktop.sssd.infopipe.Domains.Domain"

	// SubscriptionDbusRegisteredName is the well-known name of UA on dbus.
	SubscriptionDbusRegisteredName = "com.canonical.UbuntuAdvantage"
	// SubscriptionDbusObjectPath  is the path under which our AD service is registered.
	SubscriptionDbusObjectPath = "/com/canonical/UbuntuAdvantage/Manager"
	// SubscriptionDbusInterface is the interface we are using for access dbus properties.
	SubscriptionDbusInterface = "com.canonical.UbuntuAdvantage.Manager"
)

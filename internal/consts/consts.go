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

	// DefaultStateDir is the default path for adsys system state directory.
	DefaultStateDir = "/var/lib/adsys"

	// DefaultRunDir is the default path for adsys run directory.
	DefaultRunDir = "/run/adsys"

	// DefaultShareDir is the default path for adsys share directory.
	DefaultShareDir = "/usr/share/adsys"

	// DefaultClientTimeout is the maximum default time in seconds between 2 server activities before the client returns and abort the request.
	DefaultClientTimeout = 30

	// DefaultServiceTimeout is the default time in seconds without any active request before the service exits.
	DefaultServiceTimeout = 120

	// DistroID is the distro ID which can be overridden at build time.
	DistroID = "Ubuntu"
)

// Manager related properties.
const (
	// StartupScriptsMachineBaseDir is the base directory for machine startup scripts.
	StartupScriptsMachineBaseDir = "startup"

	// AdysMachineScriptsServiceName is the machine script systemd service.
	AdysMachineScriptsServiceName = "adsys-machine-scripts.service"

	// DefaultDconfDir is the default dconf directory.
	DefaultDconfDir = "/etc/dconf"
	// DefaultSudoersDir is the default directory for sudoers configuration.
	DefaultSudoersDir = "/etc/sudoers.d"
	// DefaultPolicyKitDir is the default directory for policykit configuration and rules.
	DefaultPolicyKitDir = "/etc/polkit-1"
	// DefaultApparmorDir is the default directory for apparmor configuration.
	DefaultApparmorDir = "/etc/apparmor.d/adsys"
	// DefaultSystemUnitDir is the default directory for systemd unit files.
	DefaultSystemUnitDir = "/etc/systemd/system"
	// DefaultGlobalTrustDir is the default directory for the global trust store.
	DefaultGlobalTrustDir = "/usr/local/share/ca-certificates"
)

// SSSD related properties.
const (
	// DefaultSSSCacheDir is the default sssd cache dir.
	DefaultSSSCacheDir = "/var/lib/sss/db"
	// DefaultSSSConf is the default sssd.conf location.
	DefaultSSSConf = "/etc/sssd/sssd.conf"
	// SSSDDbusRegisteredName is the well-known name used on dbus.
	SSSDDbusRegisteredName = "org.freedesktop.sssd.infopipe"
	// SSSDDbusBaseObjectPath is the path under which all domains are registered.
	SSSDDbusBaseObjectPath = "/org/freedesktop/sssd/infopipe/Domains"
	// SSSDDbusInterface is the interface we are using for access dbus methods.
	SSSDDbusInterface = "org.freedesktop.sssd.infopipe.Domains.Domain"
)

// systemd related properties.
const (
	// SystemdDbusRegisteredName is the well-known name of systemd on dbus.
	SystemdDbusRegisteredName = "org.freedesktop.systemd1"
	// SystemdDbusObjectPath is the systemd path for dbus.
	SystemdDbusObjectPath = "/org/freedesktop/systemd1"
	// SystemdDbusManagerInterface is the interface we are using to access dbus methods.
	SystemdDbusManagerInterface = "org.freedesktop.systemd1.Manager"
	// SystemdDbusUnitInterface is the interface we are using to access units.
	SystemdDbusUnitInterface = "org.freedesktop.systemd1.Unit"
	// SystemdDbusTimerInterface is the interface we are using to access timer unit objects.
	SystemdDbusTimerInterface = "org.freedesktop.systemd1.Timer"
	// SystemdDbusServiceInterface is the interface we are using to access service unit objects.
	SystemdDbusServiceInterface = "org.freedesktop.systemd1.Service"
)

// Ubuntu Advantage related properties.
const (
	// SubscriptionDbusRegisteredName is the well-known name of UA on dbus.
	SubscriptionDbusRegisteredName = "com.canonical.UbuntuAdvantage"
	// SubscriptionDbusObjectPath  is the path under which our AD service is registered.
	SubscriptionDbusObjectPath = "/com/canonical/UbuntuAdvantage/Manager"
	// SubscriptionDbusInterface is the interface we are using for access dbus properties.
	SubscriptionDbusInterface = "com.canonical.UbuntuAdvantage.Manager"
)

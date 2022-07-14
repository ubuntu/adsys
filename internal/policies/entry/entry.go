package entry

// Entry represents a key/value based policy (dconf, apparmor, ...) entry.
type Entry struct {
	// Key is the relative path to setting. Ex: Software/Ubuntu/User/dconf/wallpaper/path outside of GPO, and then
	// wallpaper/path in "dconf" rule category.
	Key      string
	Value    string
	Disabled bool
	Meta     string `yaml:",omitempty"`
	// Strategy are overlay rules for the same keys between multiple GPOs.
	// Default (empty or unknown value) means "override".
	Strategy string `yaml:",omitempty"`
	// Err is set if there was an error parsing the entry. It is ignored if the
	// underlying key is not supported by adsys.
	Err error `yaml:"-"`
}

const (
	// StrategyOverride is the default strategy.
	StrategyOverride = "override"
	// StrategyAppend is the strategy to append a value to an existing one.
	// append means from a GPO standpoint that the further GPO value is listed before closest GPO
	// (and then, enforced GPO in reverse order).
	StrategyAppend = "append"
	// This can be extended to support prepend but it is implemented yet as there is no real world cases.
)

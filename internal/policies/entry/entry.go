package entry

// Entry represents a key/value based policy (dconf, apparmor, ...) entry
type Entry struct {
	Key      string // Absolute path to setting. Ex: Software/Ubuntu/User/dconf/wallpaper
	Value    string
	Disabled bool
	Meta     string
}

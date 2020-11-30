package policies

type Entry struct {
	Key      string // Absolute path to setting. Ex: Sofware/Ubuntu/User/dconf/wallpaper
	Value    string
	Disabled bool
}

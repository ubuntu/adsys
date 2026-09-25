package dconf

// NewWithDconfDirAndProfileDataDirs creates a manager with a specific dconf
// directory and profile data directories. A nil profileDataDirs uses
// XDG_DATA_DIRS or its default.
func NewWithDconfDirAndProfileDataDirs(dir string, profileDataDirs []string) *Manager {
	return newWithDconfDirAndProfileDataDirs(dir, profileDataDirs)
}

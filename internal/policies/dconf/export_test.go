package dconf

// NewWithDconfDirAndProfileDataDirs creates a manager with a specific dconf
// directory and profile data directories. A nil profileDataDirs falls back to
// the directories the manager would use in production.
func NewWithDconfDirAndProfileDataDirs(dir string, profileDataDirs []string) *Manager {
	return newWithDconfDirAndProfileDataDirs(dir, profileDataDirs)
}

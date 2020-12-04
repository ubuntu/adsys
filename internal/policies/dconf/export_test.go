package dconf

func NewWithDconfDir(dir string) *Manager {
	return &Manager{dconfDir: dir}
}

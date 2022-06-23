package watchdservice

// serviceArgs is a dummy function to satisfy compilation on Linux.
func (s *WatchdService) serviceArgs() (string, string, error) {
	return "", "", nil
}

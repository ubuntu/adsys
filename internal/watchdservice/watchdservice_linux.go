package watchdservice

// getServiceArgs is a dummy function to satisfy compilation on Linux.
func (s *WatchdService) getServiceArgs() (string, string, error) {
	return "", "", nil
}

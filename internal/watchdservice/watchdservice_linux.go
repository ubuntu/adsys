package watchdservice

// getServiceArgs is a dummy function to satisfy compilation on Linux.
func (s *WatchdService) getServiceArgs() (string, error) {
	return "", nil
}

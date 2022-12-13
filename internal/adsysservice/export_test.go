package adsysservice

import (
	"context"
	"strings"
)

// Option type exported for tests.
type Option = option

// SelectedBackend returns currently selected backend for tests.
// It's based on string comparison in the info message.
func (s *Service) SelectedBackend() string {
	info := s.adc.GetInfo(context.Background())

	backend := "unknown"
	if strings.Contains(info, "sssd") {
		backend = "sssd"
	} else if strings.Contains(info, "Winbind") {
		backend = "winbind"
	}

	return backend
}

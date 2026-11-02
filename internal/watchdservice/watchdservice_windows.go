package watchdservice

import (
	"fmt"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// serviceArgs returns the absolute binary path and the full command line
// arguments for the service.
func (s *WatchdService) serviceArgs() (string, string, error) {
	m, err := lowPrivMgr()
	if err != nil {
		return "", "", fmt.Errorf("failed to get low-privilege service manager: %v", err)
	}
	defer m.Disconnect()

	svc, err := lowPrivSvc(m, s.Name())
	if err != nil {
		return "", "", fmt.Errorf("failed to get low-privilege service: %v", err)
	}
	defer svc.Close()

	config, err := svc.Config()
	if err != nil {
		return "", "", fmt.Errorf("failed to get service config: %v", err)
	}

	idx := strings.Index(config.BinaryPathName, " run ")
	// Strip quotes and spaces from the binary path if they exist
	binPath := strings.Trim(config.BinaryPathName[:idx], `" `)
	args := strings.Trim(config.BinaryPathName[idx+1:], " ")

	return binPath, args, nil
}

// lowPrivMgr returns a low-privilege Windows Service Manager that can be used
// to get access to Windows services.
func lowPrivMgr() (*mgr.Mgr, error) {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, err
	}
	return &mgr.Mgr{Handle: h}, nil
}

// lowPrivSvc returns a low-privilege Windows Service instance that can only
// query its state and query parameters.
func lowPrivSvc(m *mgr.Mgr, name string) (*mgr.Service, error) {
	h, err := windows.OpenService(
		m.Handle, syscall.StringToUTF16Ptr(name),
		windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return nil, err
	}
	return &mgr.Service{Handle: h, Name: name}, nil
}

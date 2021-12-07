package adsysservice

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/adsysservice/actions"
	"github.com/ubuntu/adsys/internal/authorizer"
	"github.com/ubuntu/adsys/internal/consts"
	"github.com/ubuntu/adsys/internal/decorate"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/stdforward"
	"google.golang.org/grpc"
)

// Cat forwards any messages from all requests to the client.
// Anything logged by the server on stdout, stderr or via the standard logger.
// Only one call at a time can be performed here.
func (s *Service) Cat(r *adsys.Empty, stream adsys.Service_CatServer) (err error) {
	defer decorate.OnError(&err, i18n.G("error while trying to display daemon output"))

	if err := s.authorizer.IsAllowedFromContext(stream.Context(), actions.ActionServiceManage); err != nil {
		return err
	}

	// Redirect stdout and stderr
	f := streamWriter{stream}
	remove, err := stdforward.AddStdoutWriter(f)
	if err != nil {
		return err
	}
	defer remove()
	remove, err = stdforward.AddStderrWriter(f)
	if err != nil {
		return err
	}
	defer remove()

	// Redirect all logs
	defer log.AddStreamToForward(stream)()

	<-stream.Context().Done()
	return nil
}

type streamWriter struct {
	grpc.ServerStream
}

func (ss streamWriter) Write(b []byte) (n int, err error) {
	return len(b), ss.SendMsg(&adsys.StringResponse{Msg: string(b)})
}

// Status returns internal daemon status to the client.
func (s *Service) Status(r *adsys.Empty, stream adsys.Service_StatusServer) (err error) {
	defer decorate.OnError(&err, i18n.G("error while getting daemon status"))

	if err := s.authorizer.IsAllowedFromContext(stream.Context(), authorizer.ActionAlwaysAllowed); err != nil {
		return err
	}

	state := s.state

	// Empty values: takes defaults from conf to avoid exposing too much data
	if state.dconfDir == "" {
		state.dconfDir = consts.DefaultDconfDir
	}
	if state.sudoersDir == "" {
		state.sudoersDir = consts.DefaultSudoersDir
	}
	if state.policyKitDir == "" {
		state.policyKitDir = consts.DefaultPolicyKitDir
	}
	if state.sssCacheDir == "" {
		state.sssCacheDir = consts.DefaultSSSCacheDir
	}
	if state.sssConf == "" {
		state.sssConf = consts.DefaultSSSConf
	}

	timeout := i18n.G("unknown")
	socket := i18n.G("unknown")
	if s.daemon != nil {
		timeout = s.daemon.Timeout().String()
		sock := s.daemon.GetSocketAddr()
		if sock != "" {
			socket = sock
		}
	}

	var offline string
	adServerURL, isOffline := s.adc.GetStatus()
	if isOffline {
		offline = fmt.Sprint(i18n.G("**Offline mode** using cached policies\n\n"))
	}

	if adServerURL == "" {
		adServerURL = i18n.G("N/A")
	}

	timeLayout := "Mon Jan 2 15:04"

	nextRefresh := i18n.G("unknown")
	if next, err := s.nextRefreshTime(); err == nil {
		nextRefresh = next.Format(timeLayout)
	} else {
		log.Warning(stream.Context(), err)
	}

	updateFmt := i18n.G("%s, updated on %s")
	updateMachine := i18n.G("Machine, no gpo applied found")
	t, err := s.policyManager.LastUpdateFor(stream.Context(), "", true)
	if err == nil {
		updateMachine = fmt.Sprintf(updateFmt, i18n.G("Machine"), t.Format(timeLayout))
	}

	updateUsers := fmt.Sprint(i18n.G("Can't get connected users"))
	users, err := s.adc.ListActiveUsers(stream.Context())
	if err == nil {
		updateUsers = fmt.Sprint(i18n.G("Connected users:"))
		for _, u := range users {
			if t, err := s.policyManager.LastUpdateFor(stream.Context(), u, false); err == nil {
				updateUsers = updateUsers + "\n  " + fmt.Sprintf(updateFmt, u, t.Format(timeLayout))
			} else {
				updateUsers = updateUsers + "\n  " + fmt.Sprintf(i18n.G("%s, no gpo applied found"), u)
			}
		}
		if len(users) == 0 {
			updateUsers = updateUsers + "\n  " + i18n.G("None")
		}
	}

	status := fmt.Sprintf(i18n.G(`%s%s
%s
Next Refresh: %s

Active Directory:
  Server: %s
  Domain: %s

SSS:
  Configuration: %s
  Cache directory: %s

Daemon:
  Timeout after %s
  Listening on: %s
  Cache path: %s
  Run path: %s
  Dconf path: %s
  Sudoers path: %s
  PolicyKit path: %s`), offline, updateMachine, updateUsers, nextRefresh,
		adServerURL, state.adDomain,
		state.sssConf, state.sssCacheDir,
		timeout, socket, state.cacheDir, state.runDir, state.dconfDir,
		state.sudoersDir, state.policyKitDir)

	if err := stream.Send(&adsys.StringResponse{
		Msg: status,
	}); err != nil {
		log.Warningf(stream.Context(), "couldn't send status to client: %v", err)
	}

	return nil
}

// Stop requests to stop the service once all connections are done. Force will shut it down immediately and drop
// existing connections.
func (s *Service) Stop(r *adsys.StopRequest, stream adsys.Service_StopServer) (err error) {
	defer decorate.OnError(&err, i18n.G("error while trying to stop daemon"))

	if err := s.authorizer.IsAllowedFromContext(stream.Context(), actions.ActionServiceManage); err != nil {
		return err
	}

	go s.daemon.Quit(r.GetForce())
	return nil
}

// ListActiveUsers returns the list of currently active users.
func (s *Service) ListActiveUsers(r *adsys.Empty, stream adsys.Service_ListActiveUsersServer) (err error) {
	defer decorate.OnError(&err, i18n.G("error while trying to get the list of active users"))

	if err := s.authorizer.IsAllowedFromContext(stream.Context(), authorizer.ActionAlwaysAllowed); err != nil {
		return err
	}

	users, err := s.adc.ListActiveUsers(stream.Context())
	if err != nil {
		return err
	}

	if err := stream.Send(&adsys.StringResponse{
		Msg: strings.Join(users, " "),
	}); err != nil {
		log.Warningf(stream.Context(), "couldn't send service version to client: %v", err)
	}
	return nil
}

// nextRefreshTime returns next adsys schedule refresh call.
func (s Service) nextRefreshTime() (next *time.Time, err error) {
	defer decorate.OnError(&err, i18n.G("error while trying to determine next refresh time"))

	if s.initSystemTime == nil {
		return nil, errors.New(i18n.G("no boot system time found"))
	}

	const unit = "adsys-gpo-refresh.timer"

	timerUnit := s.bus.Object("org.freedesktop.systemd1",
		dbus.ObjectPath(fmt.Sprintf("/org/freedesktop/systemd1/unit/%s",
			strings.ReplaceAll(strings.ReplaceAll(unit, ".", "_2e"), "-", "_2d"))))
	val, err := timerUnit.GetProperty("org.freedesktop.systemd1.Timer.NextElapseUSecMonotonic")
	if err != nil {
		return nil, fmt.Errorf(i18n.G("could not find %s unit on systemd bus: no GPO refresh scheduled? %v"), unit, err)
	}
	nextRaw, ok := val.Value().(uint64)
	if !ok {
		return nil, fmt.Errorf(i18n.G("invalid next GPO refresh value: %v"), val.Value(), err)
	}

	nextRefresh := s.initSystemTime.Add(time.Duration(nextRaw) * time.Microsecond / time.Nanosecond)
	return &nextRefresh, nil
}

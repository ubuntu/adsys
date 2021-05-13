package adsysservice

import (
	"fmt"

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
	if s.adc.IsOffline {
		offline = fmt.Sprint(i18n.G("**Offline mode** using cached policies\n\n"))
	}

	timeLayout := "Mon Jan 2 15:04"
	updateFmt := i18n.G("%s, updated on %s")
	updateMachine := i18n.G("Machine, no gpo applied found")
	t, err := s.policyManager.LastUpdateFor(stream.Context(), "", true)
	if err == nil {
		updateMachine = fmt.Sprintf(updateFmt, i18n.G("Machine"), t.Format(timeLayout))
	}

	updateUsers := fmt.Sprint(i18n.G("Can't get connected users"))
	users, err := s.adc.ListUsersFromCache(stream.Context())
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
  Dconf path: %s`), offline, updateMachine, updateUsers,
		state.adServer, state.adDomain,
		state.sssConf, state.sssCacheDir,
		timeout, socket, state.cacheDir, state.runDir, state.dconfDir)

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

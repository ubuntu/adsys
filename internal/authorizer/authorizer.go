// Package authorizer deals client authorization based on a definite set of polkit actions.
// The client uid and pid are obtained via the unix socket (SO_PEERCRED) information,
// that are attached to the grpc request by the server.
package authorizer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/godbus/dbus/v5"
	"github.com/ubuntu/adsys/internal/decorate"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"google.golang.org/grpc/peer"
)

type caller interface {
	Call(method string, flags dbus.Flags, args ...interface{}) *dbus.Call
}

// Authorizer is an abstraction of polkit authorization.
type Authorizer struct {
	authority  caller
	userLookup func(string) (*user.User, error)

	root string
}

func withAuthority(c caller) func(*Authorizer) {
	return func(a *Authorizer) {
		a.authority = c
	}
}

func withUserLookup(userLookup func(string) (*user.User, error)) func(*Authorizer) {
	return func(a *Authorizer) {
		a.userLookup = userLookup
	}
}

func withRoot(root string) func(*Authorizer) {
	return func(a *Authorizer) {
		a.root = root
	}
}

// New returns a new authorizer.
func New(bus *dbus.Conn, options ...func(*Authorizer)) (auth *Authorizer, err error) {
	defer decorate.OnError(&err, i18n.G("can't create new authorizer"))

	authority := bus.Object("org.freedesktop.PolicyKit1",
		"/org/freedesktop/PolicyKit1/Authority")

	a := Authorizer{
		authority:  authority,
		root:       "/",
		userLookup: user.Lookup,
	}

	for _, option := range options {
		option(&a)
	}

	return &a, nil
}

// Action is an polkit action.
type Action struct {
	ID      string
	SelfID  string
	OtherID string
}

var (
	// ActionAlwaysAllowed is a no-op bypassing any user or dbus checks.
	ActionAlwaysAllowed = Action{ID: "always-allowed"}
)

type polkitCheckFlags uint32

const (
	checkAllowInteraction polkitCheckFlags = 0x01
)

type onUserKey string

// OnUserKey is the authorizer context key passing optional user name.
var OnUserKey onUserKey = "UserName"

type authSubject struct {
	Kind    string
	Details map[string]dbus.Variant
}

type authResult struct {
	IsAuthorized bool
	IsChallenge  bool
	Details      map[string]string
}

// IsAllowedFromContext returns nil if the user is allowed to perform an operation.
// The pid and uid are extracted from peerCredsInfo grpc context.
func (a Authorizer) IsAllowedFromContext(ctx context.Context, action Action) (err error) {
	log.Debug(ctx, i18n.G("Check if grpc request peer is authorized"))

	defer decorate.OnError(&err, i18n.G("permission denied"))

	p, ok := peer.FromContext(ctx)
	if !ok {
		return errors.New(i18n.G("context request doesn't have grpc peer creds informations."))
	}
	pci, ok := p.AuthInfo.(peerCredsInfo)
	if !ok {
		return errors.New(i18n.G("context request grpc peer creeds information is not a peerCredsInfo."))
	}

	// Is it an action needing user checking?
	var actionUID uint32
	if action.SelfID != "" {
		userName, ok := ctx.Value(OnUserKey).(string)
		if !ok {
			return errors.New(i18n.G("request to act on user action should have a user name attached"))
		}
		user, err := a.userLookup(userName)
		if err != nil {
			return fmt.Errorf(i18n.G("couldn't retrieve user for %q: %v"), userName, err)
		}
		uid, err := strconv.Atoi(user.Uid)
		if err != nil {
			return fmt.Errorf(i18n.G("couldn't convert %q to a valid uid for %q"), user.Uid, userName)
		}
		actionUID = uint32(uid)
	}

	return a.isAllowed(ctx, action, pci.pid, pci.uid, actionUID)
}

// isAllowed returns nil if the user is allowed to perform an operation.
// ActionUID is only used for ActionUserWrite which will be converted to corresponding polkit action
// (self or others).
func (a Authorizer) isAllowed(ctx context.Context, action Action, pid int32, uid uint32, actionUID uint32) error {
	if uid == 0 {
		log.Debug(ctx, i18n.G("Authorized as being administrator"))
		return nil
	} else if action == ActionAlwaysAllowed {
		log.Debug(ctx, i18n.G("Any user always authorized"))
		return nil
	} else if action.SelfID != "" {
		action.ID = action.OtherID
		if actionUID == uid {
			action.ID = action.SelfID
		}
	}

	f, err := os.Open(filepath.Join(a.root, fmt.Sprintf("proc/%d/stat", pid)))
	if err != nil {
		return fmt.Errorf(i18n.G("couldn't open stat file for process: %v"), err)
	}
	defer decorate.LogFuncOnErrorContext(ctx, f.Close)

	startTime, err := getStartTimeFromReader(f)
	if err != nil {
		return err
	}

	subject := authSubject{
		Kind: "unix-process",
		Details: map[string]dbus.Variant{
			"pid":        dbus.MakeVariant(uint32(pid)), // polkit requests an uint32 on dbus
			"start-time": dbus.MakeVariant(startTime),
			"uid":        dbus.MakeVariant(uid),
		},
	}

	var result authResult
	var details map[string]string
	err = a.authority.Call(
		"org.freedesktop.PolicyKit1.Authority.CheckAuthorization", dbus.FlagAllowInteractiveAuthorization,
		subject, action.ID, details, checkAllowInteraction, "").Store(&result)
	if err != nil {
		return fmt.Errorf(i18n.G("call to polkit failed: %v"), err)
	}

	log.Debugf(ctx, i18n.G("Polkit call result, authorized: %t"), result.IsAuthorized)

	if !result.IsAuthorized {
		return errors.New(i18n.G("polkit denied access"))
	}
	return nil
}

// getStartTimeFromReader determines the start time from a process stat file content
//
// The implementation is intended to be compatible with polkit:
//    https://cgit.freedesktop.org/polkit/tree/src/polkit/polkitunixprocess.c
func getStartTimeFromReader(r io.Reader) (t uint64, err error) {
	defer decorate.OnError(&err, i18n.G("can't determine start time of client process"))

	data, err := io.ReadAll(r)
	if err != nil {
		return 0, err
	}
	contents := string(data)

	// start time is the token at index 19 after the '(process
	// name)' entry - since only this field can contain the ')'
	// character, search backwards for this to avoid malicious
	// processes trying to fool us
	//
	// See proc(5) man page for a description of the
	// /proc/[pid]/stat file format and the meaning of the
	// starttime field.
	idx := strings.IndexByte(contents, ')')
	if idx < 0 {
		return 0, errors.New(i18n.G("parsing error: missing )"))
	}
	idx += 2 // skip ") "
	if idx > len(contents) {
		return 0, errors.New(i18n.G("parsing error: ) at the end"))
	}
	tokens := strings.Split(contents[idx:], " ")
	if len(tokens) < 20 {
		return 0, errors.New(i18n.G("parsing error: less fields than required"))
	}
	v, err := strconv.ParseUint(tokens[19], 10, 64)
	if err != nil {
		return 0, fmt.Errorf(i18n.G("parsing error: %v"), err)
	}
	return v, nil
}

package authorizer

import (
	"errors"

	"github.com/godbus/dbus/v5"
)

var (
	WithAuthority  = withAuthority
	WithRoot       = withRoot
	WithUserLookup = withUserLookup
)

type PeerCredsInfo = peerCredsInfo

//nolint:revive // Revive doesn’t understand we return an exported type aliases
func NewTestPeerCredsInfo(uid uint32, pid int32) PeerCredsInfo {
	return PeerCredsInfo{uid: uid, pid: pid}
}

type DbusMock struct {
	IsAuthorized    bool
	WantPolkitError bool

	actionRequested Action
}

func (d *DbusMock) Call(method string, flags dbus.Flags, args ...interface{}) *dbus.Call {
	var errPolkit error

	content, ok := args[1].(string)
	if !ok {
		panic("Expected string as second argument")
	}

	d.actionRequested = Action{ID: content}

	if d.WantPolkitError {
		errPolkit = errors.New("Polkit error")
	}

	return &dbus.Call{
		Err: errPolkit,
		Body: []interface{}{
			[]interface{}{
				d.IsAuthorized,
				true,
				map[string]string{
					"polkit.retains_authorization_after_challenge": "true",
					"polkit.dismissed": "true",
				},
			},
		},
	}
}

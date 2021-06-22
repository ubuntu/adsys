package authorizer_test

import (
	"context"
	"errors"
	"os/user"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ubuntu/adsys/internal/authorizer"
	"github.com/ubuntu/adsys/internal/testutils"
	"google.golang.org/grpc/peer"
)

func TestIsAllowedFromContext(t *testing.T) {
	t.Parallel()

	bus := testutils.NewDbusConn(t)

	var emptyAction authorizer.Action
	simpleAction := authorizer.Action{
		ID: "simpleAction",
	}
	myUserOtherAction := authorizer.Action{
		ID:      "UserOtherActionID",
		SelfID:  "Self",
		OtherID: "Other",
	}

	tests := map[string]struct {
		action authorizer.Action
		pid    int32
		uid    uint32

		userUIDReturn   string
		userLookupError bool

		wantAuthorized  bool
		wantPolkitError bool
	}{
		"Root is always authorized": {uid: 0, wantAuthorized: true},
		"Valid process and ACK":     {pid: 10000, uid: 1000, wantAuthorized: true},
		"Valid process and NACK":    {pid: 10000, uid: 1000, wantAuthorized: false},

		"Extract current user action from request": {action: myUserOtherAction, userUIDReturn: "1000", pid: 10000, uid: 1000, wantAuthorized: true},
		"Extract other user action from request":   {action: myUserOtherAction, userUIDReturn: "999", pid: 10000, uid: 1000, wantAuthorized: true},

		// Error cases
		"User lookup returns an error": {action: myUserOtherAction, userLookupError: true, pid: 10000, uid: 1000, wantAuthorized: false},
		"User has invalid uid":         {action: myUserOtherAction, userUIDReturn: "NaN", pid: 10000, uid: 1000, wantAuthorized: false},
	}
	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if tc.action == emptyAction {
				tc.action = simpleAction
			}
			p := peer.Peer{
				AuthInfo: authorizer.NewTestPeerCredsInfo(tc.uid, tc.pid),
			}
			ctx := peer.NewContext(context.Background(), &p)

			userLookup := user.Lookup
			if tc.action == myUserOtherAction {
				ctx = context.WithValue(ctx, authorizer.OnUserKey, "foo")
				if tc.userLookupError {
					userLookup = func(string) (*user.User, error) {
						return nil, errors.New("User error requested")
					}
				} else {
					userLookup = func(string) (*user.User, error) {
						return &user.User{Uid: tc.userUIDReturn}, nil
					}
				}
			}
			d := &authorizer.DbusMock{
				IsAuthorized:    tc.wantAuthorized,
				WantPolkitError: tc.wantPolkitError}
			a, err := authorizer.New(bus, authorizer.WithAuthority(d), authorizer.WithRoot("testdata"), authorizer.WithUserLookup(userLookup))
			if err != nil {
				t.Fatalf("Failed to create authorizer: %v", err)
			}

			errAllowed := a.IsAllowedFromContext(ctx, tc.action)

			assert.Equal(t, tc.wantAuthorized, errAllowed == nil, "IsAllowedFromContext returned state match expectations")
		})
	}
}

func TestIsAllowedFromContextWithoutPeer(t *testing.T) {
	t.Parallel()
	bus := testutils.NewDbusConn(t)

	a, err := authorizer.New(bus)
	if err != nil {
		t.Fatalf("Failed to create authorizer: %v", err)
	}

	errAllowed := a.IsAllowedFromContext(context.Background(), authorizer.ActionAlwaysAllowed)
	assert.Equal(t, false, errAllowed == nil, "IsAllowedFromContext must deny without peer creds info")
}

func TestIsAllowedFromContextWithInvalidPeerCreds(t *testing.T) {
	t.Parallel()
	bus := testutils.NewDbusConn(t)

	a, err := authorizer.New(bus)
	if err != nil {
		t.Fatalf("Failed to create authorizer: %v", err)
	}

	p := peer.Peer{
		AuthInfo: invalidPeerCredsInfo{},
	}
	ctx := peer.NewContext(context.Background(), &p)

	errAllowed := a.IsAllowedFromContext(ctx, authorizer.ActionAlwaysAllowed)
	assert.Equal(t, false, errAllowed == nil, "IsAllowedFromContext must deny with an unexpected peer creds info type")
}

func TestIsAllowedFromContextWithoutUserKey(t *testing.T) {
	t.Parallel()
	bus := testutils.NewDbusConn(t)

	myUserOtherAction := authorizer.Action{
		ID:      "UserOtherActionID",
		SelfID:  "Self",
		OtherID: "Other",
	}

	p := peer.Peer{
		AuthInfo: authorizer.NewTestPeerCredsInfo(1000, 10000),
	}
	ctx := peer.NewContext(context.Background(), &p)

	a, err := authorizer.New(bus, authorizer.WithRoot("testdata"))
	if err != nil {
		t.Fatalf("Failed to create authorizer: %v", err)
	}

	errAllowed := a.IsAllowedFromContext(ctx, myUserOtherAction)
	assert.Equal(t, false, errAllowed == nil, "IsAllowedFromContext must deny without peer creds info")
}

type invalidPeerCredsInfo struct{}

func (invalidPeerCredsInfo) AuthType() string { return "" }

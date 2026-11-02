/*Package actions contains all ADSys polkit actions we support
 */
package actions

import "github.com/ubuntu/adsys/internal/authorizer"

//go:generate go run ../../generators/copy.go com.ubuntu.adsys.policy usr/share/polkit-1/actions ../../../generated
var (
	// ActionServiceManage is the action to perform read operations.
	ActionServiceManage = authorizer.Action{ID: "com.ubuntu.adsys.service.manage"}

	// ActionPolicyUpdate is the action to perform any policy update. It will turn to a "self" or an "other" action.
	ActionPolicyUpdate = authorizer.Action{
		ID:      "policy-update",
		SelfID:  "com.ubuntu.adsys.policy.update-self",
		OtherID: "com.ubuntu.adsys.policy.update-others",
	}

	// ActionPolicyDump is the action to perform any policy inspection. It will turn to a "self" or an "other" action.
	ActionPolicyDump = authorizer.Action{
		ID:      "policy-dump",
		SelfID:  "com.ubuntu.adsys.policy.dump-self",
		OtherID: "com.ubuntu.adsys.policy.dump-others",
	}
)

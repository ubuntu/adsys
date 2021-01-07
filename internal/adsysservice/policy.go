package adsysservice

import (
	"context"
	"fmt"

	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/adsysservice/actions"
	"github.com/ubuntu/adsys/internal/authorizer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/ad"
)

// UpdatePolicy refreshes or creates a policy for current user or user given as argument.
func (s *Service) UpdatePolicy(r *adsys.UpdatePolicyRequest, stream adsys.Service_UpdatePolicyServer) (err error) {
	target, targetForAuthorizer := r.GetTarget(), r.GetTarget()
	// prevent case of username == machine name to allow updating machine
	if r.IsComputer {
		targetForAuthorizer = "root"
	}

	if err := s.authorizer.IsAllowedFromContext(context.WithValue(stream.Context(), authorizer.OnUserKey, targetForAuthorizer),
		actions.ActionPolicyUpdate); err != nil {
		return err
	}

	go func() {
		if err != nil {
			err = fmt.Errorf(i18n.G("error while updating policy: %v"), err)
		}
	}()

	objectClass := ad.UserObject
	if r.IsComputer {
		objectClass = ad.ComputerObject
	}

	entries, err := s.adc.GetPolicies(stream.Context(), target, objectClass, r.Krb5Cc)
	if err != nil {
		return err
	}

	return s.policyManager.ApplyPolicy(stream.Context(), target, r.GetIsComputer(), entries)
}

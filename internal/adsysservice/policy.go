package adsysservice

import (
	"context"
	"fmt"

	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/adsysservice/actions"
	"github.com/ubuntu/adsys/internal/authorizer"
	"github.com/ubuntu/adsys/internal/decorate"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/ad"
	"golang.org/x/sync/errgroup"
)

// UpdatePolicy refreshes or creates a policy for current user or user given as argument.
func (s *Service) UpdatePolicy(r *adsys.UpdatePolicyRequest, stream adsys.Service_UpdatePolicyServer) (err error) {
	defer decorate.OnError(&err, i18n.G("error while updating policy"))

	target, targetForAuthorizer := r.GetTarget(), r.GetTarget()
	// prevent case of username == machine name to allow updating machine or anyone abusing the API passing an user.
	if r.GetIsComputer() || r.GetAll() {
		targetForAuthorizer = "root"
	}

	if err := s.authorizer.IsAllowedFromContext(context.WithValue(stream.Context(), authorizer.OnUserKey, targetForAuthorizer),
		actions.ActionPolicyUpdate); err != nil {
		return err
	}

	objectClass := ad.UserObject
	if r.GetIsComputer() {
		objectClass = ad.ComputerObject
	}

	if r.GetIsComputer() || r.GetAll() {
		err = s.updatePolicyFor(stream.Context(), true, target, ad.ComputerObject, "")

		if r.GetAll() {
			users, err := s.adc.ListUsersFromCache(stream.Context())
			if err != nil {
				return err
			}
			errg := new(errgroup.Group)
			for _, user := range users {
				user := user
				errg.Go(func() (err error) {
					return s.updatePolicyFor(stream.Context(), false, user, ad.UserObject, "")
				})
			}
			if err := errg.Wait(); err != nil {
				return fmt.Errorf("one or more error for updating all users: %v", err)
			}
		}

		return err
	}
	// Update a single user
	return s.updatePolicyFor(stream.Context(), r.GetIsComputer(), target, objectClass, r.Krb5Cc)
}

// updatePolicyFor updates the policy for a given object
func (s *Service) updatePolicyFor(ctx context.Context, isComputer bool, target string, objectClass ad.ObjectClass, krb5cc string) error {
	gpos, err := s.adc.GetPolicies(ctx, target, objectClass, krb5cc)
	if err != nil {
		return err
	}

	return s.policyManager.ApplyPolicy(ctx, target, isComputer, gpos)

}

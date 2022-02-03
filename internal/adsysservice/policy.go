package adsysservice

import (
	"context"
	"fmt"
	"os"

	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/ad"
	"github.com/ubuntu/adsys/internal/adsysservice/actions"
	"github.com/ubuntu/adsys/internal/authorizer"
	"github.com/ubuntu/adsys/internal/decorate"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"golang.org/x/sync/errgroup"
)

// UpdatePolicy refreshes or creates a policy for current user or user given as argument.
func (s *Service) UpdatePolicy(r *adsys.UpdatePolicyRequest, stream adsys.Service_UpdatePolicyServer) (err error) {
	defer decorate.OnError(&err, i18n.G("error while updating policy"))

	objectClass := ad.UserObject
	if r.GetIsComputer() || r.GetAll() {
		objectClass = ad.ComputerObject
	}
	target, err := s.adc.NormalizeTargetName(stream.Context(), r.GetTarget(), objectClass)
	if err != nil {
		return err
	}

	targetForAuthorizer := target
	// prevent case of username == machine name to allow updating machine or anyone abusing the API passing an user.
	if r.GetIsComputer() || r.GetAll() {
		targetForAuthorizer = "root"
	}

	if err := s.authorizer.IsAllowedFromContext(context.WithValue(stream.Context(), authorizer.OnUserKey, targetForAuthorizer),
		actions.ActionPolicyUpdate); err != nil {
		return err
	}

	if r.GetIsComputer() || r.GetAll() {
		hostname, err := os.Hostname()
		if err != nil {
			return err
		}
		err = s.updatePolicyFor(stream.Context(), true, hostname, ad.ComputerObject, "")

		if r.GetAll() {
			users, err := s.adc.ListActiveUsers(stream.Context())
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
				return fmt.Errorf("one or more error for updating all users: %w", err)
			}
		}

		return err
	}
	// Update a single user
	return s.updatePolicyFor(stream.Context(), r.GetIsComputer(), target, objectClass, r.Krb5Cc)
}

// updatePolicyFor updates the policy for a given object.
func (s *Service) updatePolicyFor(ctx context.Context, isComputer bool, target string, objectClass ad.ObjectClass, krb5cc string) error {
	pols, err := s.adc.GetPolicies(ctx, target, objectClass, krb5cc)
	if err != nil {
		return err
	}

	return s.policyManager.ApplyPolicies(ctx, target, isComputer, &pols)
}

// DumpPolicies displays all applied policies for a given user.
func (s *Service) DumpPolicies(r *adsys.DumpPoliciesRequest, stream adsys.Service_DumpPoliciesServer) (err error) {
	defer decorate.OnError(&err, i18n.G("error while displaying applied policies"))

	target, err := s.adc.NormalizeTargetName(stream.Context(), r.GetTarget(), "")
	if err != nil {
		return err
	}

	// hostname policy display is allowed to all users
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	if target != hostname {
		if err := s.authorizer.IsAllowedFromContext(context.WithValue(stream.Context(), authorizer.OnUserKey, target),
			actions.ActionPolicyDump); err != nil {
			return err
		}
	}

	msg, err := s.policyManager.DumpPolicies(stream.Context(), target, r.GetDetails(), r.GetAll())
	if err != nil {
		return err
	}
	if err := stream.Send(&adsys.StringResponse{
		Msg: msg,
	}); err != nil {
		log.Warningf(stream.Context(), "couldn't send currently applied policies to client: %v", err)
	}

	return nil
}

// DumpPoliciesDefinitions dumps requested policy definitions stored in daemon at build time.
func (s *Service) DumpPoliciesDefinitions(r *adsys.DumpPolicyDefinitionsRequest, stream adsys.Service_DumpPoliciesDefinitionsServer) (err error) {
	defer decorate.OnError(&err, i18n.G("error while dumping policy definitions"))

	if err := s.authorizer.IsAllowedFromContext(stream.Context(), authorizer.ActionAlwaysAllowed); err != nil {
		return err
	}

	admx, adml, err := ad.GetPolicyDefinitions(stream.Context(), r.Format, r.GetDistroID())
	if err != nil {
		return err
	}

	if err := stream.Send(&adsys.DumpPolicyDefinitionsResponse{
		Admx: admx,
		Adml: adml,
	}); err != nil {
		log.Warningf(stream.Context(), "couldn't send policy definition to client: %v", err)
	}

	return nil
}

// GPOListScript returns the embedded GPO python list script.
func (s *Service) GPOListScript(r *adsys.Empty, stream adsys.Service_GPOListScriptServer) (err error) {
	defer decorate.OnError(&err, i18n.G("error while getting gpo list script"))

	if err := s.authorizer.IsAllowedFromContext(stream.Context(), authorizer.ActionAlwaysAllowed); err != nil {
		return err
	}

	if err := stream.Send(&adsys.StringResponse{
		Msg: ad.AdsysGpoListCode,
	}); err != nil {
		log.Warningf(stream.Context(), "couldn't send gpo list to client: %v", err)
	}

	return nil
}

// FIXME: check cache file permission

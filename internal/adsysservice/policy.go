package adsysservice

import (
	"fmt"

	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/policies/ad"
)

// UpdatePolicy refreshes or creates a policy for current user or user given as argument.
func (s *Service) UpdatePolicy(r *adsys.UpdatePolicyRequest, stream adsys.Service_UpdatePolicyServer) (err error) {
	go func() {
		if err != nil {
			err = fmt.Errorf(i18n.G("error while updating policy: %v"), err)
		}
	}()

	// TODO: Check that user name matches socket user or is admin

	objectClass := ad.UserObject
	if r.IsComputer {
		objectClass = ad.ComputerObject
	}

	entries, err := s.adc.GetPolicies(stream.Context(), r.User, objectClass, r.Krb5Cc)
	if err != nil {
		return err
	}

	return s.policyManager.ApplyPolicy(r.User, r.IsComputer, entries)
}

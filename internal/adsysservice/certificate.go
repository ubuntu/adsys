package adsysservice

import (
	"context"
	"errors"
	"time"

	"github.com/leonelquinteros/gotext"
	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/internal/adsysservice/actions"
	"github.com/ubuntu/adsys/internal/authorizer"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/policies/certificate"
	"github.com/ubuntu/decorate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// certTarget returns the certificate enrollment object name to operate on,
// defaulting to the machine hostname when the client does not specify one.
func (s *Service) certTarget(target string) string {
	if target == "" {
		return s.adc.Hostname()
	}
	return target
}

// mapCertError translates management sentinel errors into user-facing gRPC errors.
func mapCertError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, certificate.ErrNotLDAPMethod) {
		return status.Error(codes.FailedPrecondition,
			gotext.Get("certificate management is only available with the ldap enrollment method; use getcert for cepces-enrolled certificates"))
	}
	return err
}

// CertList streams the certificates enrolled by adsys for the machine.
func (s *Service) CertList(r *adsys.CertTargetRequest, stream adsys.Service_CertListServer) (err error) {
	defer decorate.OnError(&err, gotext.Get("error while listing certificates"))

	if err := s.authorizer.IsAllowedFromContext(stream.Context(), authorizer.ActionAlwaysAllowed); err != nil {
		return err
	}

	certs, err := s.policyManager.CertificatesList(stream.Context(), s.certTarget(r.GetTarget()))
	if err != nil {
		return mapCertError(err)
	}

	for _, c := range certs {
		if err := stream.Send(certInfoToProto(c)); err != nil {
			log.Warningf(stream.Context(), "couldn't send certificate info to client: %v", err)
		}
	}
	return nil
}

// CertStatus streams the health of a single enrolled certificate.
func (s *Service) CertStatus(r *adsys.CertItemRequest, stream adsys.Service_CertStatusServer) (err error) {
	defer decorate.OnError(&err, gotext.Get("error while getting certificate status"))

	if err := s.authorizer.IsAllowedFromContext(stream.Context(), authorizer.ActionAlwaysAllowed); err != nil {
		return err
	}

	info, err := s.policyManager.CertificateStatus(stream.Context(), s.certTarget(r.GetTarget()), r.GetNickname())
	if err != nil {
		return mapCertError(err)
	}

	if err := stream.Send(certInfoToProto(info)); err != nil {
		log.Warningf(stream.Context(), "couldn't send certificate status to client: %v", err)
	}
	return nil
}

// CertRenew forces re-enrollment of the targeted certificate(s), streaming progress.
func (s *Service) CertRenew(r *adsys.CertItemRequest, stream adsys.Service_CertRenewServer) (err error) {
	defer decorate.OnError(&err, gotext.Get("error while renewing certificate"))

	if err := s.authorizer.IsAllowedFromContext(
		context.WithValue(stream.Context(), authorizer.OnUserKey, "root"),
		actions.ActionPolicyUpdate); err != nil {
		return err
	}

	progress := certProgressSender(stream)
	if err := s.policyManager.RenewCertificates(stream.Context(), s.certTarget(r.GetTarget()), r.GetNickname(), r.GetAll(), progress); err != nil {
		return mapCertError(err)
	}
	return nil
}

// CertRemove removes the targeted certificate(s) and cleans up state, streaming progress.
func (s *Service) CertRemove(r *adsys.CertItemRequest, stream adsys.Service_CertRemoveServer) (err error) {
	defer decorate.OnError(&err, gotext.Get("error while removing certificate"))

	if err := s.authorizer.IsAllowedFromContext(
		context.WithValue(stream.Context(), authorizer.OnUserKey, "root"),
		actions.ActionPolicyUpdate); err != nil {
		return err
	}

	progress := certProgressSender(stream)
	if err := s.policyManager.RemoveCertificates(stream.Context(), s.certTarget(r.GetTarget()), r.GetNickname(), r.GetAll(), r.GetForce(), progress); err != nil {
		return mapCertError(err)
	}
	return nil
}

// CertVerify streams the verification results for the targeted certificate(s).
func (s *Service) CertVerify(r *adsys.CertItemRequest, stream adsys.Service_CertVerifyServer) (err error) {
	defer decorate.OnError(&err, gotext.Get("error while verifying certificate"))

	if err := s.authorizer.IsAllowedFromContext(stream.Context(), authorizer.ActionAlwaysAllowed); err != nil {
		return err
	}

	results, err := s.policyManager.VerifyCertificates(stream.Context(), s.certTarget(r.GetTarget()), r.GetNickname(), r.GetOnline())
	if err != nil {
		return mapCertError(err)
	}

	for _, res := range results {
		if err := stream.Send(verifyResultToProto(res)); err != nil {
			log.Warningf(stream.Context(), "couldn't send verification result to client: %v", err)
		}
	}
	return nil
}

// CertListCAs streams the certificate authorities discovered in AD.
func (s *Service) CertListCAs(r *adsys.CertTargetRequest, stream adsys.Service_CertListCAsServer) (err error) {
	defer decorate.OnError(&err, gotext.Get("error while listing certificate authorities"))

	if err := s.authorizer.IsAllowedFromContext(stream.Context(), authorizer.ActionAlwaysAllowed); err != nil {
		return err
	}

	cas, err := s.policyManager.DiscoverCAsInfo(stream.Context(), s.certTarget(r.GetTarget()))
	if err != nil {
		return mapCertError(err)
	}

	for _, ca := range cas {
		if err := stream.Send(caInfoToProto(ca)); err != nil {
			log.Warningf(stream.Context(), "couldn't send CA info to client: %v", err)
		}
	}
	return nil
}

// CertTemplates streams the certificate templates offered by a CA server.
func (s *Service) CertTemplates(r *adsys.CertTemplatesRequest, stream adsys.Service_CertTemplatesServer) (err error) {
	defer decorate.OnError(&err, gotext.Get("error while listing certificate templates"))

	if err := s.authorizer.IsAllowedFromContext(stream.Context(), authorizer.ActionAlwaysAllowed); err != nil {
		return err
	}

	templates, err := s.policyManager.SupportedCertTemplates(stream.Context(), r.GetServer())
	if err != nil {
		return mapCertError(err)
	}

	for _, t := range templates {
		if err := stream.Send(&adsys.StringResponse{Msg: t + "\n"}); err != nil {
			log.Warningf(stream.Context(), "couldn't send template to client: %v", err)
		}
	}
	return nil
}

// stringSender abstracts a stream that carries StringResponse progress messages.
type stringSender interface {
	Send(*adsys.StringResponse) error
	Context() context.Context
}

// certProgressSender returns a callback that streams progress lines to the client.
func certProgressSender(stream stringSender) func(string) {
	return func(line string) {
		if err := stream.Send(&adsys.StringResponse{Msg: line + "\n"}); err != nil {
			log.Warningf(stream.Context(), "couldn't send certificate progress to client: %v", err)
		}
	}
}

func certHealthToProto(h certificate.CertHealth) adsys.CertHealth {
	switch h {
	case certificate.CertHealthy:
		return adsys.CertHealth_CERT_HEALTH_HEALTHY
	case certificate.CertDueRenewal:
		return adsys.CertHealth_CERT_HEALTH_DUE_RENEWAL
	case certificate.CertExpired:
		return adsys.CertHealth_CERT_HEALTH_EXPIRED
	case certificate.CertMissing:
		return adsys.CertHealth_CERT_HEALTH_MISSING
	case certificate.CertKeyMismatch:
		return adsys.CertHealth_CERT_HEALTH_KEY_MISMATCH
	case certificate.CertUnparseable:
		return adsys.CertHealth_CERT_HEALTH_UNPARSEABLE
	default:
		return adsys.CertHealth_CERT_HEALTH_UNSPECIFIED
	}
}

func rfc3339OrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

func certInfoToProto(c certificate.CertInfo) *adsys.CertInfo {
	return &adsys.CertInfo{
		Nickname:        c.Nickname,
		Template:        c.Template,
		CaName:          c.CAName,
		CaHostname:      c.CAHostname,
		Subject:         c.Subject,
		Issuer:          c.Issuer,
		Serial:          c.Serial,
		NotBefore:       rfc3339OrEmpty(c.NotBefore),
		NotAfter:        rfc3339OrEmpty(c.NotAfter),
		DaysUntilExpiry: int64(c.DaysUntilExpiry),
		Sans:            c.SANs,
		Eku:             c.EKU,
		KeyAlgo:         c.KeyAlgo,
		KeySize:         int64(c.KeySize),
		KeyFile:         c.KeyFile,
		CertFile:        c.CertFile,
		RootCertFiles:   c.RootCertFiles,
		TrustSymlinks:   c.TrustSymlinks,
		OnDisk:          c.OnDisk,
		KeyMatchesCert:  c.KeyMatchesCert,
		Health:          certHealthToProto(c.Health),
		LastEnrolled:    rfc3339OrEmpty(c.LastEnrolled),
	}
}

func caInfoToProto(c certificate.CAInfo) *adsys.CAInfo {
	return &adsys.CAInfo{
		Name:             c.Name,
		Hostname:         c.Hostname,
		Templates:        c.Templates,
		RootFingerprints: c.RootFingerprints,
		InstalledInTrust: c.InstalledInTrust,
		Enrolled:         c.Enrolled,
	}
}

func verifyResultToProto(r certificate.VerifyResult) *adsys.CertVerifyResult {
	return &adsys.CertVerifyResult{
		Nickname:          r.Nickname,
		ChainOk:           r.ChainOK,
		ValidityOk:        r.ValidityOK,
		KeyMatchOk:        r.KeyMatchOK,
		RevocationChecked: r.RevocationChecked,
		Revoked:           r.Revoked,
		Messages:          r.Messages,
	}
}

package certificate

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"unicode"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wcce"
	epmpkg "github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	icertpassage "github.com/oiweiwei/go-msrpc/msrpc/icpr/icertpassage/v0"
	"github.com/oiweiwei/go-msrpc/ssp"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
)

// Disposition is an MS-WCCE request disposition.
type Disposition uint32

// MS-WCCE disposition values returned by AD CS.
const (
	DispositionDenied          Disposition = 2
	DispositionIssued          Disposition = 3
	DispositionIssuedOutOfBand Disposition = 4
	DispositionPending         Disposition = 5
	DispositionRevoked         Disposition = 6
)

// SubmitRequest describes an initial MS-ICPR request.
type SubmitRequest struct {
	Server   string
	CAName   string
	Template string
	CSRPEM   string
}

// PollRequest describes a status request for an existing request ID.
type PollRequest struct {
	Server    string
	CAName    string
	RequestID uint32
}

// Request is the deterministic function-adapter form of either a
// submit or poll operation.
type Request struct {
	Submit *SubmitRequest
	Poll   *PollRequest
}

// Response is the typed subset of CertServerRequest's response
// needed by the enrollment lifecycle. CertificateDER is exactly one DER leaf.
type Response struct {
	Disposition    Disposition
	RequestID      uint32
	CertificateDER []byte
	Message        string
}

// Requester submits and polls AD CS requests. Implementations must
// resolve fresh credentials and establish a new authenticated connection for
// every method call.
type Requester interface {
	Submit(context.Context, SubmitRequest) (Response, error)
	Poll(context.Context, PollRequest) (Response, error)
}

// RequesterFunc is a convenient deterministic fake seam.
type RequesterFunc func(context.Context, Request) (Response, error)

// Submit implements Requester.
func (f RequesterFunc) Submit(ctx context.Context, request SubmitRequest) (Response, error) {
	return f(ctx, Request{Submit: &request})
}

// Poll implements Requester.
func (f RequesterFunc) Poll(ctx context.Context, request PollRequest) (Response, error) {
	return f(ctx, Request{Poll: &request})
}

// IssuedCertificateRequester adapts the common deterministic test fake that
// signs every submitted CSR immediately. Poll deliberately fails so tests that
// exercise pending requests must use RequesterFunc explicitly.
func IssuedCertificateRequester(issue func(context.Context, string, string, string, string) (string, error)) Requester {
	return RequesterFunc(func(ctx context.Context, request Request) (Response, error) {
		if request.Submit == nil {
			return Response{}, fmt.Errorf("issued-certificate fake does not support polling")
		}
		certificatePEM, err := issue(ctx, request.Submit.Server, request.Submit.CAName, request.Submit.Template, request.Submit.CSRPEM)
		if err != nil {
			return Response{}, err
		}
		block, rest := pem.Decode([]byte(certificatePEM))
		if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
			return Response{}, fmt.Errorf("issued-certificate fake returned invalid PEM")
		}
		return Response{
			Disposition:    DispositionIssued,
			RequestID:      1,
			CertificateDER: append([]byte(nil), block.Bytes...),
		}, nil
	})
}

// MS-ICPR request flags.
const (
	crInBinary = 0x2
	crInPKCS10 = 0x100
)

// maxIssuedCertBytes bounds the DER leaf accepted from AD CS.
const maxIssuedCertBytes = 1 << 20 // 1 MiB

type rawCertServerRequester func(context.Context, string, *icertpassage.CertServerRequestRequest) (*icertpassage.CertServerRequestResponse, error)

type rpcRequester struct {
	krb5CacheDir string
	request      rawCertServerRequester
}

func newCertificateRequester(krb5CacheDir string) Requester {
	requester := &rpcRequester{krb5CacheDir: krb5CacheDir}
	requester.request = requester.requestRPC
	return requester
}

// SubmitCSR submits an initial request using credentials discovered from the
// environment. Manager callers use newCertificateRequester so the ADSys cache
// directory is searched as well.
func SubmitCSR(ctx context.Context, server, caName, template, csrPEM string) (Response, error) {
	return newCertificateRequester("").Submit(ctx, SubmitRequest{
		Server: server, CAName: caName, Template: template, CSRPEM: csrPEM,
	})
}

// PollCertificate polls an existing request on its exact CA endpoint.
func PollCertificate(ctx context.Context, server, caName string, requestID uint32) (Response, error) {
	return newCertificateRequester("").Poll(ctx, PollRequest{
		Server: server, CAName: caName, RequestID: requestID,
	})
}

func (r *rpcRequester) Submit(ctx context.Context, request SubmitRequest) (Response, error) {
	block, rest := pem.Decode([]byte(request.CSRPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return Response{}, fmt.Errorf("failed to decode exactly one PEM CSR")
	}
	attributes := buildAttributes(request.Template)
	rawRequest := &icertpassage.CertServerRequestRequest{
		Flags:     crInPKCS10 | crInBinary,
		Authority: request.CAName,
		RequestID: 0,
		Attributes: &wcce.CertTransportBlob{
			Length: uint32(len(attributes)), //nolint:gosec // Template attributes are bounded configuration data.
			Buffer: attributes,
		},
		Request: &wcce.CertTransportBlob{
			Length: uint32(len(block.Bytes)), //nolint:gosec // A locally generated CSR is bounded well below uint32.
			Buffer: block.Bytes,
		},
	}
	response, err := r.request(ctx, request.Server, rawRequest)
	if err != nil {
		return Response{}, err
	}
	return typedResponse(response)
}

func (r *rpcRequester) Poll(ctx context.Context, request PollRequest) (Response, error) {
	if request.RequestID == 0 {
		return Response{}, fmt.Errorf("cannot poll certificate request ID 0")
	}
	// go-msrpc v1.4.3 models pctbAttribs and pctbRequest as Go pointers even
	// though their IDL pointers are [ref]. Leaving them nil makes its marshaler
	// emit an empty CERTTRANSBLOB (cb=0, pb=NULL), which is the wire form AD CS
	// requires for a status-only CertServerRequest call.
	rawRequest := &icertpassage.CertServerRequestRequest{
		Flags:      0,
		Authority:  request.CAName,
		RequestID:  request.RequestID,
		Attributes: nil,
		Request:    nil,
	}
	response, err := r.request(ctx, request.Server, rawRequest)
	if err != nil {
		return Response{}, err
	}
	typed, err := typedResponse(response)
	if err != nil {
		return Response{}, err
	}
	if typed.RequestID != 0 && typed.RequestID != request.RequestID {
		return Response{}, fmt.Errorf("certificate poll returned request ID %d instead of %d", typed.RequestID, request.RequestID)
	}
	return typed, nil
}

func typedResponse(response *icertpassage.CertServerRequestResponse) (Response, error) {
	if response == nil {
		return Response{}, fmt.Errorf("CertServerRequest returned a nil response")
	}
	typed := Response{
		Disposition: Disposition(response.Disposition),
		RequestID:   response.RequestID,
		Message:     dispositionMessage(response.DispositionMessage),
	}
	switch typed.Disposition {
	case DispositionDenied, DispositionIssued, DispositionIssuedOutOfBand, DispositionPending, DispositionRevoked:
	default:
		return Response{}, fmt.Errorf("CertServerRequest returned unknown disposition %d", response.Disposition)
	}
	if (typed.Disposition == DispositionIssued || typed.Disposition == DispositionIssuedOutOfBand) && response.EncodedCert != nil {
		if response.EncodedCert.Length != uint32(len(response.EncodedCert.Buffer)) { //nolint:gosec // len cannot exceed the RPC uint32 length.
			return Response{}, fmt.Errorf("encoded certificate length %d does not match buffer length %d", response.EncodedCert.Length, len(response.EncodedCert.Buffer))
		}
		if len(response.EncodedCert.Buffer) > maxIssuedCertBytes {
			return Response{}, fmt.Errorf("server returned oversized certificate (%d bytes, max %d)", len(response.EncodedCert.Buffer), maxIssuedCertBytes)
		}
		typed.CertificateDER = append([]byte(nil), response.EncodedCert.Buffer...)
	}
	return typed, nil
}

func dispositionMessage(blob *wcce.CertTransportBlob) string {
	if blob == nil || len(blob.Buffer) == 0 {
		return ""
	}
	return sanitizeDispositionMessage(decodeUTF16(blob.Buffer))
}

func sanitizeDispositionMessage(message string) string {
	message = strings.Map(func(r rune) rune {
		if r == '\uFFFD' {
			return r
		}
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, message)
	return strings.Join(strings.Fields(message), " ")
}

func validateSingleDERCertificate(der []byte) (*x509.Certificate, error) {
	if len(der) == 0 {
		return nil, fmt.Errorf("server returned empty certificate")
	}
	if len(der) > maxIssuedCertBytes {
		return nil, fmt.Errorf("server returned oversized certificate (%d bytes, max %d)", len(der), maxIssuedCertBytes)
	}
	certificates, err := x509.ParseCertificates(der)
	if err != nil {
		return nil, fmt.Errorf("parsing encoded certificate: %w", err)
	}
	if len(certificates) != 1 || !bytes.Equal(certificates[0].Raw, der) {
		return nil, fmt.Errorf("encoded certificate is not exactly one DER certificate")
	}
	return certificates[0], nil
}

func (r *rpcRequester) requestRPC(ctx context.Context, server string, request *icertpassage.CertServerRequestRequest) (*icertpassage.CertServerRequestResponse, error) {
	ccachePath, err := findKrb5CCachePath(r.krb5CacheDir)
	if err != nil {
		return nil, fmt.Errorf("locating Kerberos credential cache for certificate request: %w", err)
	}
	log.Debugf(ctx, "Using Kerberos ccache %s for certificate request", ccachePath)

	targetName := "host/" + server
	rpcCredential, err := rpcCredentialFromCCachePath(ccachePath)
	if err != nil {
		return nil, fmt.Errorf("loading Kerberos credential cache %s: %w", ccachePath, err)
	}
	krb5Conf, err := newRPCKrb5Config(ccachePath, server, rpcCredential.DomainName())
	if err != nil {
		return nil, fmt.Errorf("configuring Kerberos for certificate request to %s: %w", server, err)
	}
	securityOptions := []dcerpc.Option{
		dcerpc.WithMechanism(ssp.KRB5, krb5Conf),
		dcerpc.WithCredentials(rpcCredential),
		dcerpc.WithSeal(),
		dcerpc.WithTargetName(targetName),
	}

	dialOptions := make([]dcerpc.Option, 0, len(securityOptions)+1)
	dialOptions = append(dialOptions, epmpkg.EndpointMapper(ctx, server, securityOptions...))
	dialOptions = append(dialOptions, securityOptions...)
	connection, err := dcerpc.Dial(ctx, server, dialOptions...)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", server, err)
	}
	defer connection.Close(ctx)

	client, err := icertpassage.NewCertPassageClient(ctx, connection)
	if err != nil {
		return nil, rpcClientError(server, targetName, err)
	}
	response, err := client.CertServerRequest(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("CertServerRequest RPC call failed: %w", err)
	}
	return response, nil
}

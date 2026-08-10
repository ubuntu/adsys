package certificate

import (
	"context"
	"crypto/md5" //nolint:gosec // G501: MD5 is mandated by RFC 4121 §4.1.1.2 for the GSS-API channel bindings field; it is a protocol-defined transform, not a security primitive.
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-ldap/ldap/v3"
	krbclient "github.com/oiweiwei/gokrb5.fork/v9/client"
	"github.com/oiweiwei/gokrb5.fork/v9/credentials"
	"github.com/ubuntu/adsys/internal/consts"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
)

// certAuthority represents a Certificate Authority discovered from AD via LDAP.
type certAuthority struct {
	Name           string   // CN of the CA
	Hostname       string   // DNS hostname of the CA server
	CACertificates [][]byte // every DER value published on the enrollment service
	CACertificate  []byte   // selected active issuing CA certificate
	Chain          *expectedCertificateChain
	Templates      []string // Certificate templates the CA is configured to issue
}

type directoryCertificateSource string

const (
	certificateSourceTrustedRoot directoryCertificateSource = "certification-authorities"
	certificateSourceAIA         directoryCertificateSource = "aia"
)

type directoryCACertificate struct {
	DER    []byte
	Source directoryCertificateSource
}

// templateAttrs represents attributes of a certificate template.
type templateAttrs struct {
	Name                   string
	MinKeySize             int
	Present                bool
	Flags                  uint32
	SchemaVersion          int
	SchemaVersionPresent   bool
	EnrollmentFlags        uint32
	EnrollmentFlagsPresent bool
	PrivateKeyFlags        uint32
	CertificateNameFlags   uint32
	RASignatureCount       int
	SecurityDescriptor     []byte
	DefaultCSPs            []string
	KeyUsage               []byte
	ValidationError        string
}

// LDAPClient abstracts LDAP operations for testing.
type LDAPClient interface {
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

// LDAPConnector abstracts context-aware LDAP connection establishment.
type LDAPConnector interface {
	Connect(context.Context, string) (LDAPClient, error)
}

// LDAPConnectorFunc adapts a context-aware function to LDAPConnector.
type LDAPConnectorFunc func(context.Context, string) (LDAPClient, error)

// Connect invokes the adapted connector function.
func (f LDAPConnectorFunc) Connect(ctx context.Context, server string) (LDAPClient, error) {
	return f(ctx, server)
}

// LegacyLDAPConnector adapts an existing connector which cannot consume a
// context. Production connectors must implement context cancellation directly.
func LegacyLDAPConnector(connect func(string) (LDAPClient, error)) LDAPConnector {
	return LDAPConnectorFunc(func(_ context.Context, server string) (LDAPClient, error) {
		return connect(server)
	})
}

const ldapCandidateTimeout = 10 * time.Second

type ldapServerCandidate struct {
	address string
	host    string
}

type kerberosLDAPConnector struct {
	krb5CacheDir   string
	globalTrustDir string
	allowBootstrap bool
	bind           kerberosLDAPBindFunc
}

type kerberosLDAPBindFunc func(context.Context, *ldap.Conn, string, string, []byte, bool, *saslSecurityConn) error

// newKerberosLDAPConnector returns an LDAPConnector that performs GSSAPI bind
// using the machine's Kerberos credential cache from krb5CacheDir.
//
// The ccache is located by scanning krb5CacheDir for the machine credential
// cache file (the same location the AD backend copies it to). globalTrustDir
// is the adsys-managed trust directory whose CA certificates are accepted (in
// addition to the system trust store) when verifying the DC's StartTLS cert.
//
// During first use, when the DC certificate cannot yet be chained to a
// configured root, LDAP protocol data is additionally protected by the
// Kerberos GSSAPI confidentiality layer. Unknown issuers are never accepted
// after adsys-managed trust has been configured.
func newKerberosLDAPConnector(krb5CacheDir, globalTrustDir string, allowBootstrap bool) LDAPConnector {
	return &kerberosLDAPConnector{
		krb5CacheDir:   krb5CacheDir,
		globalTrustDir: globalTrustDir,
		allowBootstrap: allowBootstrap,
		bind:           gssapiBindWithOptions,
	}
}

func (c *kerberosLDAPConnector) Connect(ctx context.Context, server string) (LDAPClient, error) {
	candidates, err := c.Candidates(ctx, server)
	if err != nil {
		return nil, err
	}
	var candidateErrs []error
	for _, candidate := range candidates {
		candidateCtx, cancel := context.WithTimeout(ctx, ldapCandidateTimeout)
		client, err := c.ConnectCandidate(candidateCtx, candidate)
		cancel()
		if err == nil {
			return client, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		candidateErrs = append(candidateErrs, fmt.Errorf("%s: %w", candidate.address, err))
	}
	return nil, fmt.Errorf("all LDAP candidates failed: %w", errors.Join(candidateErrs...))
}

func (c *kerberosLDAPConnector) Candidates(ctx context.Context, server string) ([]ldapServerCandidate, error) {
	return ldapServerCandidates(ctx, server)
}

func (c *kerberosLDAPConnector) ConnectCandidate(ctx context.Context, candidate ldapServerCandidate) (LDAPClient, error) {
	return c.connectCandidate(ctx, candidate)
}

func ldapServerCandidates(ctx context.Context, server string) ([]ldapServerCandidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	host := tlsServerName(server)
	if _, port, err := net.SplitHostPort(server); err == nil && port != "" {
		return []ldapServerCandidate{{address: server, host: host}}, nil
	}
	fallback := ldapServerCandidate{address: net.JoinHostPort(host, ldap.DefaultLdapPort), host: host}

	_, records, err := net.DefaultResolver.LookupSRV(ctx, "ldap", "tcp", host)
	if err != nil || len(records) == 0 {
		return []ldapServerCandidate{fallback}, nil
	}

	candidates := ldapServerCandidatesFromRecords(records)
	if len(candidates) == 0 {
		return []ldapServerCandidate{fallback}, nil
	}
	return candidates, nil
}

func ldapServerCandidatesFromRecords(records []*net.SRV) []ldapServerCandidate {
	candidates := make([]ldapServerCandidate, 0, len(records))
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		candidateHost := strings.TrimSuffix(strings.ToLower(record.Target), ".")
		if candidateHost == "" {
			continue
		}
		address := net.JoinHostPort(candidateHost, strconv.Itoa(int(record.Port)))
		if _, ok := seen[address]; ok {
			continue
		}
		seen[address] = struct{}{}
		candidates = append(candidates, ldapServerCandidate{address: address, host: candidateHost})
	}
	return candidates
}

// NewKerberosLDAPConnector returns an LDAPConnector that performs a GSSAPI bind
// to a domain controller using the machine's Kerberos credential cache located
// in krb5CacheDir (typically filepath.Join(runDir, "krb5cc")), with StartTLS and
// channel binding. It is exported so other AD-facing managers — such as DFS
// namespace resolution for user mounts — can reuse the same authenticated LDAP
// path. It does not allow the StartTLS bootstrap exception used during first
// certificate enrollment; the DC certificate must already be trusted.
func NewKerberosLDAPConnector(krb5CacheDir, globalTrustDir string) LDAPConnector {
	return newKerberosLDAPConnector(krb5CacheDir, globalTrustDir, false)
}

type ldapCandidateProvider interface {
	LDAPConnector
	Candidates(context.Context, string) ([]ldapServerCandidate, error)
	ConnectCandidate(context.Context, ldapServerCandidate) (LDAPClient, error)
}

type deadlineLDAPClient struct {
	conn      *ldap.Conn
	transport net.Conn
	timeout   time.Duration
}

func (c *deadlineLDAPClient) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	return c.SearchContext(context.Background(), req)
}

func (c *deadlineLDAPClient) SearchContext(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	deadline := time.Now().Add(c.timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := c.transport.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("setting LDAP operation deadline: %w", err)
	}
	cancelDone := make(chan struct{})
	stopCancel := context.AfterFunc(ctx, func() {
		_ = c.transport.SetDeadline(time.Now())
		close(cancelDone)
	})
	defer func() {
		if !stopCancel() {
			<-cancelDone
		}
		_ = c.transport.SetDeadline(time.Time{})
	}()
	return c.conn.Search(req)
}

func (c *deadlineLDAPClient) Close() error {
	return c.conn.Close()
}

func (c kerberosLDAPConnector) connectCandidate(ctx context.Context, candidate ldapServerCandidate) (LDAPClient, error) {
	log.Debugf(ctx, "Connecting to LDAP server: %s", candidate.address)
	dialer := &net.Dialer{}
	rawConn, err := dialer.DialContext(ctx, "tcp", candidate.address)
	if err != nil {
		return nil, fmt.Errorf("connecting to LDAP server %s: %w", candidate.address, err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = rawConn.Close()
		}
	}()
	stopContextInterrupt := interruptConnectionOnDone(ctx, rawConn)
	defer stopContextInterrupt()
	if deadline, ok := ctx.Deadline(); ok {
		if err := rawConn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("setting LDAP candidate deadline: %w", err)
		}
	}

	if err := requestStartTLS(rawConn); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("starting TLS on LDAP connection to %s: %w", candidate.host, err)
	}

	trustState := &ldapTLSTrustState{}
	tlsConn := tls.Client(rawConn, ldapTLSConfigWithTrustState(candidate.host, c.globalTrustDir, c.allowBootstrap, trustState))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("TLS handshake with LDAP server %s: %w", candidate.host, err)
	}

	transport := newSASLSecurityConn(tlsConn)
	conn := ldap.NewConn(transport, true)
	conn.SetTimeout(ldapCandidateTimeout)
	conn.Start()
	closeOnError = false

	tlsState := tlsConn.ConnectionState()
	if len(tlsState.PeerCertificates) == 0 {
		_ = conn.Close()
		return nil, fmt.Errorf("LDAP TLS server %s presented no certificate", candidate.host)
	}
	channelBinding := tlsServerEndPointChannelBinding(tlsState.PeerCertificates[0])
	requireConfidentiality := trustState.bootstrap.Load()
	bind := c.bind
	if bind == nil {
		bind = gssapiBindWithOptions
	}
	if err := bind(ctx, conn, candidate.host, c.krb5CacheDir, channelBinding, requireConfidentiality, transport); err != nil {
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("GSSAPI bind to %s failed: %w", candidate.host, err)
	}
	if requireConfidentiality {
		if err := transport.securityLayerStatus(); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("enabling GSSAPI confidentiality for %s: %w", candidate.host, err)
		}
	}

	stopContextInterrupt()
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := transport.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("clearing LDAP candidate deadline: %w", err)
	}
	log.Debugf(ctx, "LDAP connection established and authenticated to %s", candidate.host)
	return &deadlineLDAPClient{conn: conn, transport: transport, timeout: ldapCandidateTimeout}, nil
}

func interruptConnectionOnDone(ctx context.Context, conn net.Conn) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
		close(done)
	})
	var once sync.Once
	return func() {
		once.Do(func() {
			if !stop() {
				<-done
			}
		})
	}
}

func requestStartTLS(conn net.Conn) error {
	// LDAPMessage(messageID=1, ExtendedRequest(StartTLS OID)).
	request := []byte{
		0x30, 0x1d,
		0x02, 0x01, 0x01,
		0x77, 0x18,
		0x80, 0x16,
		'1', '.', '3', '.', '6', '.', '1', '.', '4', '.', '1', '.', '1', '4', '6', '6', '.', '2', '0', '0', '3', '7',
	}
	if err := writeAll(conn, request); err != nil {
		return err
	}
	tag, response, err := readBERElement(conn)
	if err != nil {
		return fmt.Errorf("reading StartTLS response: %w", err)
	}
	if tag != 0x30 {
		return fmt.Errorf("invalid StartTLS response")
	}
	messageIDTag, messageID, response, err := splitBERElement(response)
	if err != nil {
		return fmt.Errorf("invalid StartTLS message ID: %w", err)
	}
	if messageIDTag != 0x02 {
		return fmt.Errorf("invalid StartTLS message ID tag 0x%02x", messageIDTag)
	}
	if len(messageID) != 1 || messageID[0] != 1 {
		return fmt.Errorf("invalid StartTLS message ID value %x, want 1", messageID)
	}
	tag, protocolOp, _, err := splitBERElement(response)
	if err != nil || tag != 0x78 {
		return fmt.Errorf("invalid StartTLS extended response")
	}
	tag, resultCodeBytes, protocolOp, err := splitBERElement(protocolOp)
	if err != nil || tag != 0x0a || len(resultCodeBytes) == 0 || len(resultCodeBytes) > 4 {
		return fmt.Errorf("invalid StartTLS result code")
	}
	resultCode := uint32(0)
	for _, b := range resultCodeBytes {
		resultCode = resultCode<<8 | uint32(b)
	}
	if resultCode == ldap.LDAPResultSuccess {
		return nil
	}

	_, _, protocolOp, _ = splitBERElement(protocolOp) // matchedDN
	_, diagnostic, _, _ := splitBERElement(protocolOp)
	return fmt.Errorf("LDAP StartTLS failed with result code %d: %s", resultCode, string(diagnostic))
}

func readBERElement(r io.Reader) (byte, []byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	length, err := readBERLength(r, header[1])
	if err != nil {
		return 0, nil, err
	}
	if length > saslReceiveBufferSize {
		return 0, nil, fmt.Errorf("BER element length %d exceeds limit", length)
	}
	content := make([]byte, length)
	if _, err := io.ReadFull(r, content); err != nil {
		return 0, nil, err
	}
	return header[0], content, nil
}

func readBERLength(r io.Reader, first byte) (int, error) {
	if first&0x80 == 0 {
		return int(first), nil
	}
	if first == 0x80 {
		return 0, fmt.Errorf("indefinite BER length is not supported")
	}
	octets := int(first & 0x7f)
	if octets > 4 {
		return 0, fmt.Errorf("BER length uses too many octets: %d", octets)
	}
	buf := make([]byte, octets)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, err
	}
	length := 0
	for _, b := range buf {
		length = length<<8 | int(b)
	}
	return length, nil
}

func splitBERElement(data []byte) (tag byte, content, rest []byte, err error) {
	if len(data) < 2 {
		return 0, nil, nil, io.ErrUnexpectedEOF
	}
	lengthOctets := 0
	switch {
	case data[1]&0x80 == 0:
	case data[1] == 0x80:
		return 0, nil, nil, fmt.Errorf("indefinite BER length is not supported")
	default:
		lengthOctets = int(data[1] & 0x7f)
		if lengthOctets > 4 || len(data) < 2+lengthOctets {
			return 0, nil, nil, fmt.Errorf("invalid BER length")
		}
	}
	contentLength := 0
	if lengthOctets == 0 {
		contentLength = int(data[1])
	} else {
		for _, b := range data[2 : 2+lengthOctets] {
			contentLength = contentLength<<8 | int(b)
		}
	}
	headerLength := 2 + lengthOctets
	if contentLength > len(data)-headerLength {
		return 0, nil, nil, io.ErrUnexpectedEOF
	}
	return data[0], data[headerLength : headerLength+contentLength], data[headerLength+contentLength:], nil
}

type saslSecurityConn struct {
	net.Conn

	stateMu       sync.Mutex
	layer         *saslSecurityLayer
	armedLayer    *saslSecurityLayer
	activationErr error
	rawHeader     []byte
	rawSeen       int
	rawFrameSize  int

	readMu  sync.Mutex
	readBuf []byte
	writeMu sync.Mutex
	closeMu sync.Once
}

func newSASLSecurityConn(conn net.Conn) *saslSecurityConn {
	return &saslSecurityConn{Conn: conn, rawFrameSize: -1}
}

func (c *saslSecurityConn) armSecurityLayer(layer *saslSecurityLayer) error {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.layer != nil || c.armedLayer != nil {
		return fmt.Errorf("SASL security layer is already configured")
	}
	c.armedLayer = layer
	c.rawHeader = nil
	c.rawSeen = 0
	c.rawFrameSize = -1
	c.activationErr = nil
	return nil
}

func (c *saslSecurityConn) securityLayerStatus() error {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.activationErr != nil {
		return c.activationErr
	}
	if c.layer == nil {
		return fmt.Errorf("server completed the bind without activating the negotiated security layer")
	}
	return nil
}

func (c *saslSecurityConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	c.stateMu.Lock()
	layer := c.layer
	c.stateMu.Unlock()
	if layer == nil {
		n, err := c.Conn.Read(p)
		if n > 0 {
			c.observeRawBindResponse(p[:n])
		}
		return n, err
	}

	var lengthBytes [4]byte
	if _, err := io.ReadFull(c.Conn, lengthBytes[:]); err != nil {
		return 0, fmt.Errorf("reading SASL frame length: %w", err)
	}
	length := binary.BigEndian.Uint32(lengthBytes[:])
	if length == 0 || length > saslReceiveBufferSize {
		return 0, fmt.Errorf("invalid SASL frame length %d", length)
	}
	token := make([]byte, int(length))
	if _, err := io.ReadFull(c.Conn, token); err != nil {
		return 0, fmt.Errorf("reading SASL frame: %w", err)
	}
	plaintext, err := layer.unwrap(token)
	if err != nil {
		return 0, fmt.Errorf("unwrapping SASL frame: %w", err)
	}
	n := copy(p, plaintext)
	c.readBuf = append(c.readBuf[:0], plaintext[n:]...)
	return n, nil
}

func (c *saslSecurityConn) observeRawBindResponse(data []byte) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.armedLayer == nil || c.activationErr != nil {
		return
	}
	c.rawSeen += len(data)
	if c.rawFrameSize < 0 && len(c.rawHeader) < 10 {
		need := 10 - len(c.rawHeader)
		if need > len(data) {
			need = len(data)
		}
		c.rawHeader = append(c.rawHeader, data[:need]...)
		if len(c.rawHeader) >= 2 {
			lengthByte := c.rawHeader[1]
			switch {
			case lengthByte&0x80 == 0:
				c.rawFrameSize = 2 + int(lengthByte)
			case lengthByte == 0x80:
				c.activationErr = fmt.Errorf("indefinite BER length in final GSSAPI bind response")
			default:
				lengthOctets := int(lengthByte & 0x7f)
				if lengthOctets > 8 {
					c.activationErr = fmt.Errorf("invalid BER length in final GSSAPI bind response")
				} else if len(c.rawHeader) >= 2+lengthOctets {
					contentLength := uint64(0)
					for _, b := range c.rawHeader[2 : 2+lengthOctets] {
						contentLength = contentLength<<8 | uint64(b)
					}
					if contentLength > saslReceiveBufferSize {
						c.activationErr = fmt.Errorf("final GSSAPI bind response is too large")
					} else {
						c.rawFrameSize = 2 + lengthOctets + int(contentLength)
					}
				}
			}
		}
	}
	if c.rawFrameSize >= 0 && c.rawSeen >= c.rawFrameSize {
		c.layer = c.armedLayer
		c.armedLayer = nil
	}
}

func (c *saslSecurityConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}

	c.stateMu.Lock()
	layer := c.layer
	c.stateMu.Unlock()
	if layer == nil {
		return c.Conn.Write(p)
	}

	maxPlaintext, err := layer.maxPlaintextSize()
	if err != nil {
		return 0, err
	}
	written := 0
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > maxPlaintext {
			chunkSize = maxPlaintext
		}
		token, err := layer.wrap(p[:chunkSize])
		if err != nil {
			return written, err
		}
		frame := make([]byte, 4+len(token))
		binary.BigEndian.PutUint32(frame[:4], uint32(len(token))) //nolint:gosec // Tokens are bounded by the 24-bit SASL limit.
		copy(frame[4:], token)
		if err := writeAll(c.Conn, frame); err != nil {
			return written, err
		}
		written += chunkSize
		p = p[chunkSize:]
	}
	return written, nil
}

func (c *saslSecurityConn) Close() error {
	var err error
	c.closeMu.Do(func() {
		c.stateMu.Lock()
		layer := c.layer
		armedLayer := c.armedLayer
		c.layer = nil
		c.armedLayer = nil
		c.stateMu.Unlock()
		if layer != nil {
			layer.Close()
		}
		if armedLayer != nil && armedLayer != layer {
			armedLayer.Close()
		}
		err = c.Conn.Close()
	})
	return err
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		data = data[n:]
	}
	return nil
}

type ldapTLSTrustState struct {
	bootstrap atomic.Bool
}

func ldapTLSConfigWithTrustState(server, globalTrustDir string, allowBootstrap bool, state *ldapTLSTrustState) *tls.Config {
	//nolint:gosec // G123: ClientSessionCache is a zero-capacity cache, so no
	// client-side session resumption occurs and VerifyPeerCertificate runs on
	// every handshake; InsecureSkipVerify is paired with manual verification.
	return &tls.Config{
		MinVersion:            tls.VersionTLS12,
		ServerName:            tlsServerName(server),
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: verifyPeerCertificateWithTrustState(server, globalTrustDir, allowBootstrap, state),
		// Disable session resumption to ensure certificate verification
		// is performed on every connection (gosec G123).
		ClientSessionCache: tls.NewLRUClientSessionCache(0),
	}
}

// verifyPeerCertificate returns a callback that validates the server's
// certificate chain against the system trust store and any adsys-managed
// CA certificates. This is necessary because the AD root CA may not yet be
// in the system trust store on first enrollment, and we want to accept
// certificates that chain to CAs already installed by adsys in addition
// to the system trust store.
//
// Hostname verification is performed separately from chain verification so that
// it can fall back to the certificate's Common Name: AD domain controller
// certificates issued from legacy templates frequently carry only a CN and no
// Subject Alternative Name, which crypto/x509 refuses to match (since Go 1.15)
// when DNSName is set on Verify.
//
// When allowBootstrap is true, a chain that cannot be built because the issuing
// CA is unknown (x509.UnknownAuthorityError, which also covers a missing
// intermediate in a multi-tier PKI) is tolerated: on the first enrollment the
// enterprise CA is only discovered and installed later in the same run, so the
// DC certificate provably cannot chain to a trusted root yet. In that case all
// LDAP protocol data is protected by GSSAPI confidentiality after mutual
// Kerberos authentication, so a relaying TLS endpoint cannot inspect or alter
// discovery results even when the DC does not enforce channel binding. Hostname
// matching is still enforced, and any other verification failure remains fatal.
// Once adsys-managed trust exists, unknown authorities are always rejected.
func verifyPeerCertificateWithTrustState(server, globalTrustDir string, allowBootstrap bool, state *ldapTLSTrustState) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no server certificate presented")
		}

		certs := make([]*x509.Certificate, 0, len(rawCerts))
		for _, rawCert := range rawCerts {
			cert, err := x509.ParseCertificate(rawCert)
			if err != nil {
				return fmt.Errorf("failed to parse server certificate: %w", err)
			}
			certs = append(certs, cert)
		}

		// Build the verification pool from the system roots plus any
		// adsys-managed CA certificates in the trust directory.
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}

		// Add any CA certificates already installed by adsys
		managedTrustExists := addAdsysCAsToPool(pool, globalTrustDir)

		// Verify the chain to a trusted root. DNSName is intentionally left
		// empty so crypto/x509 does not perform hostname matching here; we do
		// it below with a Common Name fallback.
		opts := x509.VerifyOptions{
			Roots:         pool,
			Intermediates: x509.NewCertPool(),
		}
		for i, cert := range certs {
			if i == 0 {
				continue // leaf
			}
			opts.Intermediates.AddCert(cert)
		}

		if _, err := certs[0].Verify(opts); err != nil {
			// On the first enrollment the enterprise CA is not in any trust
			// store yet (adsys installs it later in this same run), so the DC
			// certificate cannot chain to a trusted root. When bootstrapping is
			// allowed and no managed trust exists, tolerate only this "unknown
			// authority" case. The connector requires GSSAPI confidentiality
			// for every subsequent LDAP message on this connection. Any other
			// failure remains fatal.
			var unknownAuthority x509.UnknownAuthorityError
			if !allowBootstrap || managedTrustExists || !errors.As(err, &unknownAuthority) {
				return fmt.Errorf("server certificate verification failed: %w", err)
			}
			if hostErr := verifyHostnameWithCNFallback(certs[0], tlsServerName(server)); hostErr != nil {
				return fmt.Errorf("server certificate verification failed: %w", hostErr)
			}
			log.Warningf(context.Background(),
				"Server certificate for %q is not signed by an installed CA yet; requiring GSSAPI confidentiality for bootstrap enrollment: %v",
				tlsServerName(server), err)
			if state != nil {
				state.bootstrap.Store(true)
			}
			return nil
		}

		if err := verifyHostnameWithCNFallback(certs[0], tlsServerName(server)); err != nil {
			return fmt.Errorf("server certificate verification failed: %w", err)
		}
		return nil
	}
}

// verifyHostnameWithCNFallback checks that host matches the certificate's
// Subject Alternative Names, falling back to the Subject Common Name when the
// certificate carries no SAN entries. The chain itself must already have been
// verified against a trusted root by the caller.
//
// Modern certificates carry SANs and are matched strictly. The CN fallback
// exists solely for AD domain controller certificates issued from legacy
// templates, which often present only a CN; this mirrors what Windows and Samba
// accept when connecting to such DCs.
func verifyHostnameWithCNFallback(cert *x509.Certificate, host string) error {
	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 {
		return cert.VerifyHostname(host)
	}

	cn := cert.Subject.CommonName
	if cn == "" {
		return fmt.Errorf("certificate has no subject alternative names and no common name to match against %q", host)
	}
	if !matchHostname(cn, host) {
		return fmt.Errorf("certificate common name %q does not match server host %q", cn, host)
	}
	log.Debugf(context.Background(), "Server certificate for %q has no SAN; accepted legacy Common Name %q", host, cn)
	return nil
}

// matchHostname reports whether host matches the certificate name pattern. The
// comparison is case-insensitive, ignores a trailing dot, and supports a single
// leading "*" wildcard label, mirroring how crypto/x509 historically matched
// the Common Name.
func matchHostname(pattern, host string) bool {
	pattern = strings.TrimSuffix(strings.ToLower(pattern), ".")
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if pattern == "" || host == "" {
		return false
	}

	patternParts := strings.Split(pattern, ".")
	hostParts := strings.Split(host, ".")
	if len(patternParts) != len(hostParts) {
		return false
	}
	for i, p := range patternParts {
		if i == 0 && p == "*" {
			continue
		}
		if p != hostParts[i] {
			return false
		}
	}
	return true
}

// addAdsysCAsToPool adds CA certificates from the adsys-managed trust
// directories to the given cert pool, so AD root CAs already installed by
// adsys (but not necessarily rebuilt into the system bundle yet) are trusted.
// The default global trust directory is always included; any additional dirs
// (e.g. a non-default configured directory) are merged in and de-duplicated.
func addAdsysCAsToPool(pool *x509.CertPool, dirs ...string) bool {
	seen := make(map[string]bool, len(dirs)+1)
	added := false
	for _, dir := range append([]string{consts.DefaultGlobalTrustDir}, dirs...) {
		if dir == "" || seen[dir] {
			continue
		}
		seen[dir] = true
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if !strings.HasSuffix(entry.Name(), ".crt") && !strings.HasSuffix(entry.Name(), ".pem") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				continue
			}
			added = pool.AppendCertsFromPEM(data) || added
		}
	}
	return added
}

func tlsServerName(server string) string {
	host, _, err := net.SplitHostPort(server)
	if err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(server, "[]")
}

// gssapiBindWithOptions performs a GSSAPI/Kerberos bind on an LDAP connection.
// It locates the machine's Kerberos credential cache by checking:
//  1. KRB5CCNAME environment variable
//  2. The krb5CacheDir managed by the AD backend
//  3. Default /tmp/krb5cc_0
func gssapiBindWithOptions(ctx context.Context, conn *ldap.Conn, server, krb5CacheDir string, channelBinding []byte, requireConfidentiality bool, transport *saslSecurityConn) error {
	ccachePath, err := findKrb5CCachePath(krb5CacheDir)
	if err != nil {
		return fmt.Errorf("locating Kerberos credential cache: %w", err)
	}

	ccache, err := credentials.LoadCCache(ccachePath)
	if err != nil {
		return fmt.Errorf("loading Kerberos credential cache %s: %w", ccachePath, err)
	}
	defer clearCCache(ccache)

	krb5Conf, err := newKerberosClientConfig(ctx, server, ccache.DefaultPrincipal.Realm)
	if err != nil {
		return fmt.Errorf("configuring Kerberos client for LDAP server %s: %w", server, err)
	}

	// Bind KDC/TGS network operations (used by the InitSecContext ->
	// GetServiceTicket call below) to ctx: gokrb5's default KDCDialer only
	// bounds the dial with a fixed 5-minute timeout and otherwise uses
	// independent sockets, so without this a canceled or expired candidate
	// context would not interrupt an in-flight or subsequent KDC/referral
	// request.
	cl, err := krbclient.NewFromCCache(ccache, krb5Conf, krbclient.Dialer(newContextKDCDialer(ctx)))
	if err != nil {
		if cl != nil {
			cl.Destroy()
		}
		return fmt.Errorf("creating Kerberos client from ccache: %w", err)
	}

	return bindKerberosClient(ctx, cl, server, channelBinding, requireConfidentiality, transport, func(client ldap.GSSAPIClient, spn string) error {
		return conn.GSSAPIBind(client, spn, "")
	})
}

func bindKerberosClient(ctx context.Context, cl *krbclient.Client, server string, channelBinding []byte, requireConfidentiality bool, transport *saslSecurityConn, bind func(ldap.GSSAPIClient, string) error) error {
	spn := fmt.Sprintf("ldap/%s", server)
	log.Debugf(ctx, "Performing GSSAPI bind using SPN: %s", spn)
	gssClient := newGSSAPIClient(cl, channelBinding)
	gssClient.requireSecurityLayer = requireConfidentiality
	gssClient.securityTransport = transport
	defer gssClient.DeleteSecContext() //nolint:errcheck // Cleanup has no failure mode and is idempotent.

	if err := bind(gssClient, spn); err != nil {
		return fmt.Errorf("GSSAPI bind failed for SPN %s: %w", spn, err)
	}

	log.Debugf(ctx, "GSSAPI bind successful for SPN: %s", spn)
	return nil
}

func clearCCache(ccache *credentials.CCache) {
	if ccache == nil {
		return
	}
	for _, credential := range ccache.Credentials {
		if credential == nil {
			continue
		}
		clearEncryptionKey(&credential.Key)
		clear(credential.Ticket)
		clear(credential.SecondTicket)
		credential.Ticket = nil
		credential.SecondTicket = nil
	}
}

// tlsServerEndPointChannelBinding computes the GSS-API channel bindings hash for
// the "tls-server-end-point" channel binding type (RFC 5929 §4) from the given
// server certificate.
//
// The application data is "tls-server-end-point:" followed by the certificate
// hash; the GSS channel bindings structure (with empty addresses) is then
// MD5-hashed per RFC 4121 §4.1.1.2 to produce the 16-byte Bnd value.
func tlsServerEndPointChannelBinding(cert *x509.Certificate) []byte {
	appData := append([]byte("tls-server-end-point:"), certHashForChannelBinding(cert)...)
	return gssChannelBindingsHash(appData)
}

// certHashForChannelBinding hashes the certificate's DER encoding using the
// hash algorithm mandated by RFC 5929 §4.1: the certificate's own signature
// hash, but with MD5 and SHA-1 (and unknown/hashless algorithms such as
// Ed25519) upgraded to SHA-256.
func certHashForChannelBinding(cert *x509.Certificate) []byte {
	switch cert.SignatureAlgorithm {
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		sum := sha512.Sum384(cert.Raw)
		return sum[:]
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		sum := sha512.Sum512(cert.Raw)
		return sum[:]
	default:
		sum := sha256.Sum256(cert.Raw)
		return sum[:]
	}
}

// gssChannelBindingsHash serializes a gss_channel_bindings_struct with empty
// initiator/acceptor addresses and the given application data, then returns its
// MD5 hash (RFC 4121 §4.1.1.2 / RFC 1964 §1.1.1). All integer fields are
// little-endian.
func gssChannelBindingsHash(appData []byte) []byte {
	buf := make([]byte, 0, 20+len(appData))
	var zero [4]byte
	buf = append(buf, zero[:]...) // initiator_addrtype = 0
	buf = append(buf, zero[:]...) // initiator_address length = 0
	buf = append(buf, zero[:]...) // acceptor_addrtype = 0
	buf = append(buf, zero[:]...) // acceptor_address length = 0
	var l [4]byte
	binary.LittleEndian.PutUint32(l[:], uint32(len(appData))) //nolint:gosec // G115: appData is a fixed short prefix plus a hash digest, well within uint32.
	buf = append(buf, l[:]...)                                // application_data length
	buf = append(buf, appData...)

	sum := md5.Sum(buf) //nolint:gosec // G401: MD5 required by RFC 4121 §4.1.1.2 for the channel bindings field.
	return sum[:]
}

// findKrb5CCachePath locates the machine's Kerberos credential cache file.
func findKrb5CCachePath(krb5CacheDir string) (string, error) {
	// 1. Check KRB5CCNAME environment variable
	if envPath := os.Getenv("KRB5CCNAME"); envPath != "" {
		envPath = strings.TrimPrefix(envPath, "FILE:")
		if _, err := os.Stat(envPath); err == nil { //nolint:gosec // G703: envPath is from KRB5CCNAME, a system-controlled env var
			log.Debugf(context.Background(), "Using Kerberos ccache from KRB5CCNAME: %s", envPath)
			return envPath, nil
		}
	}

	// 2. Look for a machine ccache in the AD backend's cache directory.
	// The directory can hold several tickets (e.g. user@DOMAIN alongside the
	// machine ticket); prefer the machine cache (filenames without '@') so
	// LDAP/RPC operations bind with the correct principal, and only fall back
	// to another regular file if no machine cache is present.
	if krb5CacheDir != "" {
		if entries, err := os.ReadDir(krb5CacheDir); err == nil {
			var fallback string
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				path := filepath.Join(krb5CacheDir, entry.Name())
				if !strings.Contains(entry.Name(), "@") {
					log.Debugf(context.Background(), "Using machine Kerberos ccache from cache directory: %s", path)
					return path, nil
				}
				if fallback == "" {
					fallback = path
				}
			}
			if fallback != "" {
				log.Debugf(context.Background(), "Using Kerberos ccache from cache directory: %s", fallback)
				return fallback, nil
			}
		}
	}

	// 3. Default machine ccache location
	defaultPath := "/tmp/krb5cc_0"
	if _, err := os.Stat(defaultPath); err == nil {
		log.Debugf(context.Background(), "Using default Kerberos ccache: %s", defaultPath)
		return defaultPath, nil
	}

	return "", fmt.Errorf("no Kerberos credential cache found (checked KRB5CCNAME, %s, %s)", krb5CacheDir, defaultPath)
}

// fetchCertificationAuthorities queries LDAP for all enrollment services
// (pKIEnrollmentService objects) under the configuration naming context.
//
// This implements [MS-CAESO] 4.4.5.3.1.2 — Initialize CAs.
func fetchCertificationAuthorities(conn LDAPClient, configDN string) ([]certAuthority, error) {
	return fetchCertificationAuthoritiesContext(context.Background(), conn, configDN)
}

func fetchCertificationAuthoritiesContext(ctx context.Context, conn LDAPClient, configDN string) ([]certAuthority, error) {
	baseDN := fmt.Sprintf("CN=Enrollment Services,CN=Public Key Services,CN=Services,%s", configDN)
	log.Debugf(ctx, "Searching LDAP for enrollment services under: %s", baseDN)

	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=pKIEnrollmentService)",
		[]string{"cn", "dNSHostName", "cACertificate", "certificateTemplates"},
		nil,
	)

	result, err := ldapSearchContext(ctx, conn, searchReq)
	if err != nil {
		return nil, fmt.Errorf("LDAP search for enrollment services failed: %w", err)
	}
	log.Debugf(ctx, "LDAP returned %d enrollment service entries", len(result.Entries))

	var cas []certAuthority
	for _, entry := range result.Entries {
		cn := entry.GetAttributeValue("cn")
		hostname := entry.GetAttributeValue("dNSHostName")
		caCertValues := entry.GetRawAttributeValues("cACertificate")
		templates := entry.GetAttributeValues("certificateTemplates")

		if cn == "" || hostname == "" {
			continue
		}

		rawCertificates := make([][]byte, 0, len(caCertValues))
		for _, value := range caCertValues {
			rawCertificates = append(rawCertificates, append([]byte(nil), value...))
		}
		ca := certAuthority{
			Name:           cn,
			Hostname:       hostname,
			CACertificates: rawCertificates,
			Templates:      templates,
		}
		log.Debugf(ctx, "Discovered CA: %s (host: %s, certificates: %d, templates: %d)", cn, hostname, len(rawCertificates), len(templates))
		cas = append(cas, ca)
	}

	return cas, nil
}

// fetchDirectoryCACertificatesContext keeps the publication container attached
// to every certificate. Only Certification Authorities publishes trust
// anchors; AIA publishes issuer candidates.
func fetchDirectoryCACertificatesContext(ctx context.Context, conn LDAPClient, configDN string) ([]directoryCACertificate, error) {
	containers := []struct {
		baseDN string
		source directoryCertificateSource
	}{
		{
			baseDN: fmt.Sprintf("CN=Certification Authorities,CN=Public Key Services,CN=Services,%s", configDN),
			source: certificateSourceTrustedRoot,
		},
		{
			baseDN: fmt.Sprintf("CN=AIA,CN=Public Key Services,CN=Services,%s", configDN),
			source: certificateSourceAIA,
		},
	}

	var certificates []directoryCACertificate
	for _, container := range containers {
		searchReq := ldap.NewSearchRequest(
			container.baseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0, 0, false,
			"(cACertificate=*)",
			[]string{"cACertificate"},
			nil,
		)
		result, err := ldapSearchContext(ctx, conn, searchReq)
		if err != nil {
			return nil, fmt.Errorf("LDAP search for CA certificates under %s failed: %w", container.baseDN, err)
		}
		for _, entry := range result.Entries {
			for _, value := range entry.GetRawAttributeValues("cACertificate") {
				certificates = append(certificates, directoryCACertificate{
					DER:    append([]byte(nil), value...),
					Source: container.source,
				})
			}
		}
	}
	return certificates, nil
}

// fetchTemplateAttrs queries LDAP for a specific certificate template's
// minimum key size. Autoenrollment authorization uses the bulk lookup below.
func fetchTemplateAttrs(conn LDAPClient, configDN, templateName string) (templateAttrs, error) {
	return fetchTemplateAttrsContext(context.Background(), conn, configDN, templateName)
}

func fetchTemplateAttrsContext(ctx context.Context, conn LDAPClient, configDN, templateName string) (templateAttrs, error) {
	baseDN := fmt.Sprintf("CN=Certificate Templates,CN=Public Key Services,CN=Services,%s", configDN)
	log.Debugf(ctx, "Fetching LDAP attributes for certificate template: %s", templateName)

	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(cn=%s)", ldap.EscapeFilter(templateName)),
		[]string{"cn", "msPKI-Minimal-Key-Size"},
		nil,
	)

	result, err := ldapSearchContext(ctx, conn, searchReq)
	if err != nil {
		// Surface the LDAP failure so callers can log it, while still returning a
		// safe default key size to let enrollment proceed.
		return templateAttrs{Name: templateName, MinKeySize: 2048}, fmt.Errorf("LDAP search for certificate template %s failed: %w", templateName, err)
	}

	if len(result.Entries) == 0 {
		log.Debugf(ctx, "Template %s not found in LDAP, defaulting to 2048-bit key size", templateName)
		return templateAttrs{Name: templateName, MinKeySize: 2048}, nil
	}

	entry := result.Entries[0]
	minKeySize := 2048
	if v := entry.GetAttributeValue("msPKI-Minimal-Key-Size"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			minKeySize = parsed
		}
	}

	return templateAttrs{
		Name:       templateName,
		MinKeySize: minKeySize,
	}, nil
}

func fetchTemplateAttrsWithConnector(ctx context.Context, connect LDAPConnector, server string, templateNames []string) (map[string]templateAttrs, error) {
	if len(templateNames) == 0 {
		return map[string]templateAttrs{}, nil
	}
	return runLDAPTransaction(ctx, connect, server, func(candidateCtx context.Context, conn LDAPClient) (map[string]templateAttrs, error) {
		configDN, err := fetchConfigDNContext(candidateCtx, conn)
		if err != nil {
			return nil, err
		}
		return fetchTemplateAttrsBulkContext(candidateCtx, conn, configDN, templateNames)
	})
}

// fetchTemplateAttrsBulkContext queries LDAP once for all requested
// certificate templates using a single escaped OR filter, returning their
// attributes keyed by every originally requested template (CN) spelling.
//
// Querying once instead of once per template avoids the failure mode where a
// single slow or timed-out lookup (all of them share the same bounded
// candidate transaction) discards every key size already fetched for the
// other templates, forcing every template back to the 2048-bit default.
// Templates that LDAP does not return retain the 2048-bit compatibility
// default for non-enrollment consumers but carry a validation error, so the
// autoenrollment eligibility path skips them rather than falling back.
//
// AD's CN matching is case-insensitive, so requested names are deduplicated
// and matched against returned entries case-insensitively: requesting
// "machine" and "Machine" only issues one filter clause, and a single
// returned entry (regardless of its case) populates the result under every
// originally requested spelling. Result entries LDAP returns that were not
// requested are ignored. If LDAP itself returns two entries that collide
// case-insensitively with conflicting attributes, the lookup fails closed
// with an explicit error instead of nondeterministically picking one.
func fetchTemplateAttrsBulkContext(ctx context.Context, conn LDAPClient, configDN string, templateNames []string) (map[string]templateAttrs, error) {
	attrsByName := make(map[string]templateAttrs, len(templateNames))
	if len(templateNames) == 0 {
		return attrsByName, nil
	}

	// Group requested names case-insensitively (AD CN matching is
	// case-insensitive) while keeping every distinct originally requested
	// spelling, so the returned map has an entry for each key callers
	// expect (e.g. both "machine" and "Machine" if both were requested).
	type requestGroup struct {
		filterName string   // representative spelling used to build the LDAP filter
		names      []string // every distinct originally requested spelling for this group
	}
	groupOrder := make([]string, 0, len(templateNames))
	groups := make(map[string]*requestGroup, len(templateNames))
	for _, name := range templateNames {
		folded := strings.ToLower(name)
		group, ok := groups[folded]
		if !ok {
			group = &requestGroup{filterName: name}
			groups[folded] = group
			groupOrder = append(groupOrder, folded)
		}
		alreadyRequested := false
		for _, existing := range group.names {
			if existing == name {
				alreadyRequested = true
				break
			}
		}
		if !alreadyRequested {
			group.names = append(group.names, name)
		}
	}

	filterNames := make([]string, 0, len(groupOrder))
	for _, folded := range groupOrder {
		filterNames = append(filterNames, groups[folded].filterName)
	}

	baseDN := fmt.Sprintf("CN=Certificate Templates,CN=Public Key Services,CN=Services,%s", configDN)
	log.Debugf(ctx, "Fetching LDAP attributes for %d certificate template(s)", len(filterNames))

	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		templateNamesFilter(filterNames),
		[]string{
			"cn",
			"flags",
			"msPKI-Template-Schema-Version",
			"msPKI-Enrollment-Flag",
			"nTSecurityDescriptor",
			"msPKI-Minimal-Key-Size",
			"msPKI-Private-Key-Flag",
			"msPKI-Certificate-Name-Flag",
			"msPKI-RA-Signature",
			"pKIDefaultCSPs",
			"msPKI-CSPs",
			"pKIKeyUsage",
		},
		[]ldap.Control{securityDescriptorFlagsControl()},
	)

	result, err := ldapSearchContext(ctx, conn, searchReq)
	if err != nil {
		return nil, fmt.Errorf("LDAP search for certificate templates failed: %w", err)
	}

	foundByFold := make(map[string]templateAttrs, len(groupOrder))
	for _, entry := range result.Entries {
		cn := entry.GetAttributeValue("cn")
		if cn == "" {
			continue
		}
		folded := strings.ToLower(cn)
		// Defensively ignore entries that were not actually requested, even
		// though the filter itself is built from the same folded names:
		// unrequested entries must never leak into the returned map.
		if _, requested := groups[folded]; !requested {
			continue
		}

		attrs := parseTemplateLDAPEntry(entry)

		if existing, ok := foundByFold[folded]; ok {
			if !templateAttrsEquivalent(existing, attrs) {
				return nil, fmt.Errorf("ambiguous certificate template %q: LDAP returned conflicting entries %q and %q", folded, existing.Name, attrs.Name)
			}
			continue
		}
		foundByFold[folded] = attrs
	}

	for _, folded := range groupOrder {
		group := groups[folded]
		attrs, ok := foundByFold[folded]
		if !ok {
			log.Debugf(ctx, "Template %s not found in LDAP, defaulting to 2048-bit key size", group.filterName)
		}
		for _, name := range group.names {
			if ok {
				attrsByName[name] = attrs
			} else {
				attrsByName[name] = templateAttrs{
					Name:            name,
					MinKeySize:      2048,
					ValidationError: "template was not returned by LDAP",
				}
			}
		}
	}

	return attrsByName, nil
}

const securityDescriptorFlagsControlOID = "1.2.840.113556.1.4.801"

func securityDescriptorFlagsControl() ldap.Control {
	// SDFlagsRequestValue ::= SEQUENCE { Flags INTEGER }. DACL_SECURITY_INFORMATION
	// is 0x4, so its complete minimal BER encoding is 30 03 02 01 04.
	return ldap.NewControlString(securityDescriptorFlagsControlOID, true, string([]byte{0x30, 0x03, 0x02, 0x01, 0x04}))
}

func parseTemplateLDAPEntry(entry *ldap.Entry) templateAttrs {
	attrs := templateAttrs{
		Name:       entry.GetAttributeValue("cn"),
		MinKeySize: 2048,
		Present:    true,
	}
	addError := func(format string, args ...any) {
		message := fmt.Sprintf(format, args...)
		if attrs.ValidationError == "" {
			attrs.ValidationError = message
		} else {
			attrs.ValidationError += "; " + message
		}
	}

	var err error
	var present bool
	attrs.Flags, present, err = ldapUint32Attribute(entry, "flags")
	if err != nil {
		addError("%v", err)
	} else if !present {
		addError("flags is missing")
	}
	schema, schemaPresent, schemaErr := ldapUint32Attribute(entry, "msPKI-Template-Schema-Version")
	if schemaErr != nil {
		addError("%v", schemaErr)
	} else if schemaPresent {
		attrs.SchemaVersion = int(schema)
		attrs.SchemaVersionPresent = true
	}
	attrs.EnrollmentFlags, attrs.EnrollmentFlagsPresent, err = ldapUint32Attribute(entry, "msPKI-Enrollment-Flag")
	if err != nil {
		addError("%v", err)
	}
	attrs.PrivateKeyFlags, _, err = ldapUint32Attribute(entry, "msPKI-Private-Key-Flag")
	if err != nil {
		addError("%v", err)
	}
	attrs.CertificateNameFlags, _, err = ldapUint32Attribute(entry, "msPKI-Certificate-Name-Flag")
	if err != nil {
		addError("%v", err)
	}
	raSignature, raPresent, raErr := ldapUint32Attribute(entry, "msPKI-RA-Signature")
	if raErr != nil {
		addError("%v", raErr)
	} else if raPresent {
		attrs.RASignatureCount = int(raSignature)
	}
	minKeySize, minKeyPresent, minKeyErr := ldapUint32Attribute(entry, "msPKI-Minimal-Key-Size")
	if minKeyErr != nil {
		addError("%v", minKeyErr)
	} else if minKeyPresent {
		if minKeySize == 0 || minKeySize > 16384 {
			addError("msPKI-Minimal-Key-Size %d is outside the supported range", minKeySize)
		} else {
			attrs.MinKeySize = max(2048, int(minKeySize))
		}
	}

	descriptors := entry.GetRawAttributeValues("nTSecurityDescriptor")
	if len(descriptors) != 1 || len(descriptors[0]) == 0 {
		addError("nTSecurityDescriptor must have exactly one non-empty binary value")
	} else {
		attrs.SecurityDescriptor = append([]byte(nil), descriptors[0]...)
	}
	attrs.DefaultCSPs = append(attrs.DefaultCSPs, entry.GetAttributeValues("pKIDefaultCSPs")...)
	attrs.DefaultCSPs = append(attrs.DefaultCSPs, entry.GetAttributeValues("msPKI-CSPs")...)
	for _, provider := range attrs.DefaultCSPs {
		if strings.TrimSpace(provider) == "" {
			addError("CSP/KSP list contains an empty provider")
			break
		}
	}
	keyUsages := entry.GetRawAttributeValues("pKIKeyUsage")
	if len(keyUsages) > 1 {
		addError("pKIKeyUsage has multiple values")
	} else if len(keyUsages) == 1 {
		if len(keyUsages[0]) == 0 || len(keyUsages[0]) > 8 {
			addError("pKIKeyUsage has invalid length %d", len(keyUsages[0]))
		} else {
			attrs.KeyUsage = append([]byte(nil), keyUsages[0]...)
		}
	}
	return attrs
}

func ldapUint32Attribute(entry *ldap.Entry, name string) (uint32, bool, error) {
	values := entry.GetAttributeValues(name)
	if len(values) == 0 {
		return 0, false, nil
	}
	if len(values) != 1 {
		return 0, true, fmt.Errorf("%s has %d values, want one", name, len(values))
	}
	value := strings.TrimSpace(values[0])
	if value == "" {
		return 0, true, fmt.Errorf("%s is empty", name)
	}
	if strings.HasPrefix(value, "-") {
		parsed, err := strconv.ParseInt(value, 10, 32)
		if err != nil {
			return 0, true, fmt.Errorf("%s signed 32-bit value %q is malformed or out of range: %w", name, value, err)
		}
		return uint32(int32(parsed)), true, nil //nolint:gosec // G115: the signed AD INTEGER bit pattern is intentionally preserved as uint32.
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, true, fmt.Errorf("%s unsigned 32-bit value %q is malformed or out of range: %w", name, value, err)
	}
	return uint32(parsed), true, nil
}

func templateAttrsEquivalent(a, b templateAttrs) bool {
	a.Name = strings.ToLower(a.Name)
	b.Name = strings.ToLower(b.Name)
	return a.Name == b.Name &&
		a.MinKeySize == b.MinKeySize &&
		a.Present == b.Present &&
		a.Flags == b.Flags &&
		a.SchemaVersion == b.SchemaVersion &&
		a.SchemaVersionPresent == b.SchemaVersionPresent &&
		a.EnrollmentFlags == b.EnrollmentFlags &&
		a.EnrollmentFlagsPresent == b.EnrollmentFlagsPresent &&
		a.PrivateKeyFlags == b.PrivateKeyFlags &&
		a.CertificateNameFlags == b.CertificateNameFlags &&
		a.RASignatureCount == b.RASignatureCount &&
		a.ValidationError == b.ValidationError &&
		slices.Equal(a.SecurityDescriptor, b.SecurityDescriptor) &&
		slices.Equal(a.DefaultCSPs, b.DefaultCSPs) &&
		slices.Equal(a.KeyUsage, b.KeyUsage)
}

// templateNamesFilter builds an LDAP OR filter matching the given,
// already-deduplicated certificate template common names.
func templateNamesFilter(names []string) string {
	var filter strings.Builder
	filter.WriteString("(|")
	for _, name := range names {
		filter.WriteString("(cn=")
		filter.WriteString(ldap.EscapeFilter(name))
		filter.WriteByte(')')
	}
	filter.WriteByte(')')
	return filter.String()
}

// fetchConfigDN retrieves the configuration naming context from the LDAP
// root DSE of the given server.
func fetchConfigDN(conn LDAPClient) (string, error) {
	return fetchConfigDNContext(context.Background(), conn)
}

func fetchConfigDNContext(ctx context.Context, conn LDAPClient) (string, error) {
	log.Debug(ctx, "Fetching configuration naming context from LDAP root DSE")
	searchReq := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"configurationNamingContext"},
		nil,
	)

	result, err := ldapSearchContext(ctx, conn, searchReq)
	if err != nil {
		return "", fmt.Errorf("failed to query root DSE: %w", err)
	}

	if len(result.Entries) == 0 {
		return "", fmt.Errorf("root DSE returned no entries")
	}

	configDN := result.Entries[0].GetAttributeValue("configurationNamingContext")
	if configDN == "" {
		return "", fmt.Errorf("configurationNamingContext not found in root DSE")
	}

	log.Debugf(ctx, "Configuration naming context: %s", configDN)
	return configDN, nil
}

func ldapSearchContext(ctx context.Context, conn LDAPClient, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if contextClient, ok := conn.(interface {
		SearchContext(context.Context, *ldap.SearchRequest) (*ldap.SearchResult, error)
	}); ok {
		return contextClient.SearchContext(ctx, req)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return conn.Search(req)
}

// discoverCAsAndTemplates connects to the DC via LDAP and discovers all
// CAs and their supported templates. This is the main entry point for
// LDAP-based discovery, replacing both the Samba LDAP queries and the
// CEPCES GET-SUPPORTED-TEMPLATES call.
func discoverCAsAndTemplates(ctx context.Context, connect LDAPConnector, server string) ([]certAuthority, error) {
	log.Debugf(ctx, "Discovering CAs and certificate templates from DC: %s", server)
	return runLDAPTransaction(ctx, connect, server, func(candidateCtx context.Context, conn LDAPClient) ([]certAuthority, error) {
		configDN, err := fetchConfigDNContext(candidateCtx, conn)
		if err != nil {
			return nil, err
		}
		cas, err := fetchCertificationAuthoritiesContext(candidateCtx, conn, configDN)
		if err != nil {
			return nil, err
		}
		directoryCertificates, err := fetchDirectoryCACertificatesContext(candidateCtx, conn, configDN)
		if err != nil {
			return nil, err
		}
		cas, err = resolveCAChains(cas, directoryCertificates, time.Now())
		if err != nil {
			return nil, err
		}
		log.Debugf(candidateCtx, "Discovery complete: found %d CAs on %s", len(cas), server)
		return cas, nil
	})
}

type enrollmentDirectoryData struct {
	CAs             []certAuthority
	TemplateAttrs   map[string]templateAttrs
	MachineIdentity machineDirectoryIdentity
	PublishedCAs    int
}

// discoverEnrollmentDirectoryData performs CA, chain, machine-token and
// template authorization discovery as one bounded LDAP transaction. If a
// candidate DC fails at any step, runLDAPTransaction restarts the whole
// sequence on the next candidate instead of combining security data from
// different directory snapshots.
func discoverEnrollmentDirectoryData(ctx context.Context, connect LDAPConnector, server, objectName, domain string) (enrollmentDirectoryData, error) {
	identity, err := enrollmentMachineIdentity(objectName, domain)
	if err != nil {
		return enrollmentDirectoryData{}, err
	}
	return runLDAPTransaction(ctx, connect, server, func(candidateCtx context.Context, conn LDAPClient) (enrollmentDirectoryData, error) {
		contexts, err := fetchNamingContextsContext(candidateCtx, conn)
		if err != nil {
			return enrollmentDirectoryData{}, err
		}
		cas, err := fetchCertificationAuthoritiesContext(candidateCtx, conn, contexts.configuration)
		if err != nil {
			return enrollmentDirectoryData{}, err
		}
		directoryCertificates, err := fetchDirectoryCACertificatesContext(candidateCtx, conn, contexts.configuration)
		if err != nil {
			return enrollmentDirectoryData{}, err
		}
		cas, err = resolveCAChains(cas, directoryCertificates, time.Now())
		if err != nil {
			return enrollmentDirectoryData{}, err
		}
		if len(cas) == 0 {
			return enrollmentDirectoryData{
				CAs:             []certAuthority{},
				TemplateAttrs:   map[string]templateAttrs{},
				MachineIdentity: identity,
				PublishedCAs:    0,
			}, nil
		}

		token, err := fetchMachineTokenContext(candidateCtx, conn, contexts.defaultDomain, identity)
		if err != nil {
			return enrollmentDirectoryData{}, err
		}
		var templateNames []string
		for _, ca := range cas {
			templateNames = append(templateNames, ca.Templates...)
		}
		attrsByName, err := fetchTemplateAttrsBulkContext(candidateCtx, conn, contexts.configuration, templateNames)
		if err != nil {
			return enrollmentDirectoryData{}, err
		}
		publishedCAs := len(cas)
		cas = filterMachineAutoEnrollmentTemplates(candidateCtx, cas, attrsByName, token)
		return enrollmentDirectoryData{
			CAs:             cas,
			TemplateAttrs:   attrsByName,
			MachineIdentity: identity,
			PublishedCAs:    publishedCAs,
		}, nil
	})
}

func runLDAPTransaction[T any](ctx context.Context, connect LDAPConnector, server string, operation func(context.Context, LDAPClient) (T, error)) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, err
	}

	candidates := []ldapServerCandidate{{address: server, host: tlsServerName(server)}}
	provider, hasCandidates := connect.(ldapCandidateProvider)
	if hasCandidates {
		var err error
		candidates, err = provider.Candidates(ctx, server)
		if err != nil {
			return zero, err
		}
	}
	if len(candidates) == 0 {
		return zero, fmt.Errorf("no LDAP candidates found for %s", server)
	}

	var candidateErrs []error
	for _, candidate := range candidates {
		candidateCtx, cancel := context.WithTimeout(ctx, ldapCandidateTimeout)
		var conn LDAPClient
		var err error
		if hasCandidates {
			conn, err = provider.ConnectCandidate(candidateCtx, candidate)
		} else {
			conn, err = connect.Connect(candidateCtx, candidate.address)
		}
		if err == nil {
			var result T
			result, err = operation(candidateCtx, conn)
			closeErr := conn.Close()
			if err == nil && closeErr != nil {
				err = fmt.Errorf("closing LDAP connection: %w", closeErr)
			}
			if err == nil {
				cancel()
				return result, nil
			}
		}
		cancel()
		if ctx.Err() != nil {
			return zero, ctx.Err()
		}
		candidateErrs = append(candidateErrs, fmt.Errorf("%s: %w", candidate.address, err))
	}
	return zero, fmt.Errorf("all LDAP candidates failed: %w", errors.Join(candidateErrs...))
}

// dcHostnameFromDomain derives the DC hostname from the domain name.
// LDAP SRV discovery resolves the ordered domain controller candidates.
func dcHostnameFromDomain(domain string) string {
	return strings.ToLower(domain)
}

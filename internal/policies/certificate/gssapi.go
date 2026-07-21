package certificate

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/go-ldap/ldap/v3"
	asn1 "github.com/jcmturner/gofork/encoding/asn1"
	"github.com/oiweiwei/gokrb5.fork/v9/asn1tools"
	krbclient "github.com/oiweiwei/gokrb5.fork/v9/client"
	"github.com/oiweiwei/gokrb5.fork/v9/crypto"
	"github.com/oiweiwei/gokrb5.fork/v9/gssapi"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/chksumtype"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/etypeID"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/keyusage"
	"github.com/oiweiwei/gokrb5.fork/v9/messages"
	"github.com/oiweiwei/gokrb5.fork/v9/spnego"
	"github.com/oiweiwei/gokrb5.fork/v9/types"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
)

// gssapiClient implements the go-ldap GSSAPIClient interface using gokrb5.
//
// It handles the three-phase GSSAPI/SASL handshake that go-ldap's
// GSSAPIBindRequestWithAPOptions drives:
//
//  1. InitSecContext(target, nil) → AP-REQ token (client → server)
//  2. InitSecContext(target, apRep) → verify AP-REP, extract subkey (server → client)
//  3. NegotiateSaslAuth(saslChallenge) → unwrap challenge, wrap response (RFC 4752)
type gssapiClient struct {
	client         *krbclient.Client
	sessionKey     types.EncryptionKey
	ticketKey      types.EncryptionKey // original key from the service ticket (before subkey extraction)
	channelBinding []byte              // tls-server-end-point channel binding token (16-byte MD5), nil when none
	established    bool
	sendSeq        uint64
	recvSeq        uint64
	sequenceReady  bool

	requireSecurityLayer bool
	securityTransport    *saslSecurityConn
	destroyOnce          sync.Once
}

var _ ldap.GSSAPIClient = (*gssapiClient)(nil)

// newGSSAPIClient creates a GSSAPIClient adapter from a gokrb5 client.
//
// channelBinding is the 16-byte tls-server-end-point channel binding token
// (RFC 5929) derived from the LDAP server's TLS certificate. It is embedded in
// the AP-REQ authenticator checksum so the bind succeeds against Domain
// Controllers that enforce LDAP channel binding (CBT/EPA). Pass nil to bind
// without channel binding.
func newGSSAPIClient(cl *krbclient.Client, channelBinding []byte) *gssapiClient {
	return &gssapiClient{client: cl, channelBinding: append([]byte(nil), channelBinding...)}
}

// InitSecContext implements ldap.GSSAPIClient.
func (g *gssapiClient) InitSecContext(target string, token []byte) ([]byte, bool, error) {
	return g.InitSecContextWithOptions(target, token, nil)
}

// InitSecContextWithOptions implements ldap.GSSAPIClient.
//
// First call (token == nil): obtains a service ticket for the target SPN and
// produces an AP-REQ token with mutual authentication requested.
//
// Second call (token != nil): verifies the server's AP-REP and extracts the
// session subkey if the server provided one (RFC 4121 §2). The subkey becomes
// the key for all subsequent GSSAPI wrap/unwrap operations.
func (g *gssapiClient) InitSecContextWithOptions(target string, token []byte, options []int) ([]byte, bool, error) {
	if token == nil {
		return g.initContextAPREQ(target, options)
	}
	return g.processAPREP(token)
}

// initContextAPREQ handles the first InitSecContext call: it obtains a service
// ticket from the KDC and produces an AP-REQ token.
func (g *gssapiClient) initContextAPREQ(target string, options []int) ([]byte, bool, error) {
	tkt, key, err := g.client.GetServiceTicket(target)
	if err != nil {
		return nil, false, fmt.Errorf("getting service ticket for %s: %w", target, err)
	}
	g.sessionKey = key
	g.ticketKey = key

	gssFlags := []int{
		gssapi.ContextFlagInteg,
		gssapi.ContextFlagConf,
		gssapi.ContextFlagMutual,
		gssapi.ContextFlagSequence,
	}

	// Build AP options: merge caller-provided options with mutual-required
	// (bit 2 per RFC 4120). We allocate a new slice to avoid mutating the
	// caller's backing array.
	apOptions := make([]int, len(options)+1)
	copy(apOptions, options)
	apOptions[len(options)] = 2

	tokenBytes, initialSequence, err := buildKRB5APREQToken(g.client, tkt, key, gssFlags, apOptions, g.channelBinding)
	if err != nil {
		return nil, false, err
	}
	g.sendSeq = initialSequence

	return tokenBytes, true, nil
}

// buildKRB5APREQToken builds a Kerberos GSS-API AP-REQ MechToken.
//
// It mirrors spnego.NewKRB5TokenAPREQ followed by KRB5Token.Marshal, but writes
// the supplied channel-binding token into the authenticator checksum's Bnd
// field (RFC 4121 §4.1.1, bytes 4..19). The upstream helper hardcodes that
// field to zeros, which makes the bind fail against Domain Controllers that
// enforce LDAP channel binding (LDAP result code 49 with data 80090346 /
// SEC_E_BAD_BINDINGS).
func buildKRB5APREQToken(cl *krbclient.Client, tkt messages.Ticket, key types.EncryptionKey, gssFlags, apOptions []int, channelBinding []byte) ([]byte, uint64, error) {
	auth, err := types.NewAuthenticator(cl.Credentials.Domain(), cl.Credentials.CName())
	if err != nil {
		return nil, 0, fmt.Errorf("creating Kerberos authenticator: %w", err)
	}
	auth.Cksum = types.Checksum{
		CksumType: chksumtype.GSSAPI,
		Checksum:  gssAPIBindingChecksum(gssFlags, channelBinding),
	}

	apReq, err := messages.NewAPReq(tkt, key, auth)
	if err != nil {
		return nil, 0, fmt.Errorf("creating AP-REQ: %w", err)
	}
	for _, o := range apOptions {
		types.SetFlag(&apReq.APOptions, o)
	}

	// Marshal as a KRB5 GSS MechToken: KRB5 OID | TOK_ID(AP-REQ=0x0100) |
	// AP-REQ, wrapped in a GSS application tag (mirrors KRB5Token.Marshal).
	oid, err := asn1.Marshal(gssapi.OIDKRB5.OID())
	if err != nil {
		return nil, 0, fmt.Errorf("marshalling KRB5 OID: %w", err)
	}
	apReqBytes, err := apReq.Marshal()
	if err != nil {
		return nil, 0, fmt.Errorf("marshalling AP-REQ: %w", err)
	}

	token := append(oid, 0x01, 0x00) // TOK_ID_KRB_AP_REQ
	token = append(token, apReqBytes...)
	return asn1tools.AddASNAppTag(token, 0), uint64(auth.SeqNumber), nil //nolint:gosec // NewAuthenticator generates a non-negative 30-bit value.
}

// gssAPIBindingChecksum builds the RFC 4121 §4.1.1 GSS-API authenticator
// checksum carried in the AP-REQ:
//
//	Lgth(4) | Bnd(16) | Flags(4) [ | DlgOpt(2) | Dlgth(2) | Deleg(n) ]
//
// All integer fields are little-endian. The 16-byte Bnd field carries the
// channel-binding MD5 hash; it is left as zeros when channelBinding is not
// exactly 16 bytes (i.e. no channel binding is in effect).
func gssAPIBindingChecksum(flags []int, channelBinding []byte) []byte {
	a := make([]byte, 24)
	binary.LittleEndian.PutUint32(a[:4], 16)
	if len(channelBinding) == 16 {
		copy(a[4:20], channelBinding)
	}
	for _, i := range flags {
		if i == gssapi.ContextFlagDeleg {
			a = append(a, make([]byte, 28-len(a))...)
		}
		f := binary.LittleEndian.Uint32(a[20:24])
		f |= uint32(i) //nolint:gosec // G115: GSS-API context flag values are small constants.
		binary.LittleEndian.PutUint32(a[20:24], f)
	}
	return a
}

// processAPREP handles the second InitSecContext call: it verifies the server's
// AP-REP token and extracts the subkey if present.
func (g *gssapiClient) processAPREP(token []byte) ([]byte, bool, error) {
	var krb5Token spnego.KRB5Token
	if err := krb5Token.Unmarshal(token); err != nil {
		return nil, false, fmt.Errorf("unmarshalling server token: %w", err)
	}

	if krb5Token.IsKRBError() {
		return nil, false, fmt.Errorf("server returned Kerberos error %d: %s",
			krb5Token.KRBError.ErrorCode, krb5Token.KRBError.EText)
	}

	if !krb5Token.IsAPRep() {
		return nil, false, fmt.Errorf("expected AP-REP from server, got unexpected token type")
	}

	if err := krb5Token.APRep.DecryptEncPart(g.sessionKey); err != nil {
		return nil, false, fmt.Errorf("decrypting AP-REP: %w", err)
	}

	// If the server provided a subkey in the AP-REP, it becomes the session
	// key for all subsequent GSSAPI operations (RFC 4121 §2). This is the
	// most critical handoff in the entire flow — using the wrong key after
	// this point causes every checksum in NegotiateSaslAuth to fail.
	if krb5Token.APRep.DecryptedEncPart.Subkey.KeyType != 0 {
		g.sessionKey = krb5Token.APRep.DecryptedEncPart.Subkey
		log.Debug(context.Background(), "gssapi: AP-REP subkey extracted")
	} else {
		log.Debug(context.Background(), "gssapi: no subkey in AP-REP, using ticket session key")
	}
	if krb5Token.APRep.DecryptedEncPart.SequenceNumber < 0 {
		return nil, false, fmt.Errorf("server AP-REP contains negative sequence number %d", krb5Token.APRep.DecryptedEncPart.SequenceNumber)
	}
	g.recvSeq = uint64(krb5Token.APRep.DecryptedEncPart.SequenceNumber)
	g.sequenceReady = true

	g.established = true
	return nil, false, nil
}

// NegotiateSaslAuth implements ldap.GSSAPIClient.
//
// It handles the final SASL negotiation step (RFC 4752 §3.1):
//  1. Unwrap the server's GSSAPI wrap token to extract the 4-byte SASL payload
//     describing supported security layers and max buffer size.
//  2. Build a response selecting auth-only on a verified TLS connection, or
//     confidentiality during first-use bootstrap.
//  3. Wrap the response as an integrity-only GSSAPI wrap token.
//
// The confidentiality layer is mandatory when StartTLS could not be chained
// to a configured trust anchor. This prevents a CBT-disabled DC from being
// used as a GSSAPI relay during first-use CA discovery.
func (g *gssapiClient) NegotiateSaslAuth(token []byte, authzid string) ([]byte, error) {
	if !g.sequenceReady {
		return nil, fmt.Errorf("GSSAPI sequence state was not established by AP-REQ/AP-REP")
	}
	payload, err := g.unwrapServerToken(token)
	if err != nil {
		return nil, fmt.Errorf("unwrapping server SASL token: %w", err)
	}

	if len(payload) < 4 {
		return nil, fmt.Errorf("server SASL payload too short: got %d bytes, need at least 4", len(payload))
	}

	// Byte 0: supported security layers bitmask
	//   bit 0 (0x01) = no security layer (auth only)
	//   bit 1 (0x02) = integrity only
	//   bit 2 (0x04) = confidentiality
	//
	if !g.requireSecurityLayer {
		if payload[0]&0x01 == 0 {
			return nil, fmt.Errorf("server does not support auth-only security layer (bitmask: %02x)", payload[0])
		}
		return g.wrapSASLResponse(authzid)
	}

	if payload[0]&0x04 == 0 {
		return nil, fmt.Errorf("server does not support the confidentiality security layer required for bootstrap (bitmask: %02x)", payload[0])
	}
	if g.securityTransport == nil {
		return nil, fmt.Errorf("bootstrap confidentiality transport is unavailable")
	}

	maxBuffer := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if maxBuffer == 0 {
		return nil, fmt.Errorf("server advertised a zero receive buffer for the confidentiality security layer")
	}
	response, err := g.wrapSASLResponseForLayer(authzid, 0x04, saslReceiveBufferSize)
	if err != nil {
		return nil, err
	}
	layer, err := newSASLSecurityLayer(g.sessionKey, !keysEqual(g.sessionKey, g.ticketKey), maxBuffer, g.sendSeq, g.recvSeq)
	if err != nil {
		return nil, err
	}
	if err := g.securityTransport.armSecurityLayer(layer); err != nil {
		layer.Close()
		return nil, err
	}
	return response, nil
}

const saslReceiveBufferSize = 0xFFFFFF

func (g *gssapiClient) wrapSASLResponseForLayer(authzid string, securityLayer byte, receiveBuffer int) ([]byte, error) {
	if receiveBuffer < 0 || receiveBuffer > saslReceiveBufferSize {
		return nil, fmt.Errorf("invalid SASL receive buffer size %d", receiveBuffer)
	}
	response := make([]byte, 4, 4+len(authzid))
	response[0] = securityLayer
	response[1] = byte(receiveBuffer >> 16)
	response[2] = byte(receiveBuffer >> 8) //nolint:gosec // The value is range-checked against the 24-bit SASL limit.
	response[3] = byte(receiveBuffer)      //nolint:gosec // The value is range-checked against the 24-bit SASL limit.
	if authzid != "" {
		response = append(response, []byte(authzid)...)
	}

	return g.wrapSASLPayload(response)
}

// unwrapServerToken unwraps a GSSAPI wrap token (RFC 4121) from the server
// (acceptor) and returns the plaintext payload. It handles both sealed
// (encrypted) and integrity-only tokens.
//
// For integrity-only tokens, RRC is undone before unmarshalling so that the
// library's Verify() operates on correctly positioned payload and checksum.
//
// For sealed tokens, the ciphertext is decrypted after undoing RRC.
func (g *gssapiClient) unwrapServerToken(token []byte) ([]byte, error) {
	if len(token) < gssapi.HdrLen {
		return nil, fmt.Errorf("token too short: %d bytes, need at least %d", len(token), gssapi.HdrLen)
	}

	// Check token ID: 0x05 0x04 = GSS Wrap per RFC 4121.
	if token[0] != 0x05 || token[1] != 0x04 {
		return nil, fmt.Errorf("unexpected token ID: %02x%02x, expected 0504", token[0], token[1])
	}
	if token[2]&0x01 == 0 {
		return nil, fmt.Errorf("server token is missing the acceptor flag")
	}
	if token[3] != gssapi.FillerByte {
		return nil, fmt.Errorf("server token has invalid filler byte %02x", token[3])
	}

	isSealed := token[2]&0x02 != 0
	rrc := binary.BigEndian.Uint16(token[6:8])
	sequence := binary.BigEndian.Uint64(token[8:16])
	if g.sequenceReady && sequence != g.recvSeq {
		return nil, fmt.Errorf("unexpected server token sequence number: got %d, want %d", sequence, g.recvSeq)
	}

	log.Debugf(context.Background(), "gssapi: unwrapServerToken: len=%d flags=0x%02x sealed=%v EC=%d RRC=%d",
		len(token), token[2], isSealed,
		binary.BigEndian.Uint16(token[4:6]), rrc)

	var payload []byte
	var err error
	if isSealed {
		payload, err = g.unwrapSealed(token, rrc)
	} else {
		payload, err = g.unwrapIntegrity(token, rrc)
	}
	if err == nil && g.sequenceReady {
		g.recvSeq++
	}
	return payload, err
}

// unwrapIntegrity verifies and extracts the payload from an integrity-only
// GSSAPI wrap token sent by the acceptor.
//
// Per RFC 4121, the data portion ({payload | checksum}) may be right-rotated
// by RRC bytes. We undo this and zero the RRC field before calling the
// library's Unmarshal, since the checksum is computed with RRC=0.
func (g *gssapiClient) unwrapIntegrity(token []byte, rrc uint16) ([]byte, error) {
	// Work on a copy to avoid mutating the caller's buffer.
	buf := make([]byte, len(token))
	copy(buf, token)

	// Undo RRC rotation on the data portion (everything after the 16-byte header).
	if rrc > 0 {
		data := buf[gssapi.HdrLen:]
		if len(data) > 0 {
			rotateLeft(data, int(rrc))
		}
		// Zero RRC in the header: the checksum was computed with RRC=0
		// per RFC 4121 §4.2.4.
		binary.BigEndian.PutUint16(buf[6:8], 0)
	}

	var wrapToken gssapi.WrapToken
	if err := wrapToken.Unmarshal(buf, true); err != nil {
		return nil, fmt.Errorf("unmarshalling integrity token: %w", err)
	}

	log.Debugf(context.Background(), "gssapi: unwrapIntegrity: flags=0x%02x EC=%d RRC=%d seqNum=%d payloadLen=%d",
		wrapToken.Flags, wrapToken.EC, wrapToken.RRC, wrapToken.SndSeqNum,
		len(wrapToken.Payload))

	// RFC 4121 §2: Wrap tokens always use SEAL key usage, even for integrity-only
	// (conf_flag=FALSE). SIGN key usage is only for MIC tokens.
	if ok, err := wrapToken.Verify(g.sessionKey, keyusage.GSSAPI_ACCEPTOR_SEAL); !ok {
		// Try with the original ticket session key as fallback — some servers
		// may not use the AP-REP subkey for the SASL challenge.
		if !keysEqual(g.ticketKey, g.sessionKey) {
			log.Debug(context.Background(), "gssapi: subkey verification failed, trying ticket session key")
			if ok2, _ := wrapToken.Verify(g.ticketKey, keyusage.GSSAPI_ACCEPTOR_SEAL); ok2 {
				log.Debug(context.Background(), "gssapi: ticket session key worked — server is not using AP-REP subkey for SASL")
				g.sessionKey = g.ticketKey
				return wrapToken.Payload, nil
			}
		}
		return nil, fmt.Errorf("integrity token verification failed: %w", err)
	}

	return wrapToken.Payload, nil
}

// unwrapSealed decrypts and extracts the payload from a sealed (encrypted)
// GSSAPI wrap token sent by the acceptor.
//
// Per RFC 4121 §4.2.4, the ciphertext (after undoing RRC) decrypts to:
//
//	{confounder | payload | EC-padding | header-copy(16 bytes)}
//
// DecryptMessage handles the confounder and HMAC internally, returning:
//
//	{payload | EC-padding | header-copy(16 bytes)}
func (g *gssapiClient) unwrapSealed(token []byte, rrc uint16) ([]byte, error) {
	return unwrapSealedToken(token, g.sessionKey, rrc, nil, keyusage.GSSAPI_ACCEPTOR_SEAL)
}

func unwrapSealedToken(token []byte, key types.EncryptionKey, rrc uint16, expectedSeq *uint64, usage uint32) ([]byte, error) {
	ec := binary.BigEndian.Uint16(token[4:6])
	seq := binary.BigEndian.Uint64(token[8:16])
	if expectedSeq != nil && seq != *expectedSeq {
		return nil, fmt.Errorf("unexpected sealed token sequence number: got %d, want %d", seq, *expectedSeq)
	}

	// Copy the ciphertext portion (after the 16-byte header).
	ciphertext := make([]byte, len(token)-gssapi.HdrLen)
	copy(ciphertext, token[gssapi.HdrLen:])
	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, fmt.Errorf("resolving sealed token encryption type %d: %w", key.KeyType, err)
	}
	minCiphertextLen := encType.GetConfounderByteSize() + encType.GetHMACBitLength()/8 + gssapi.HdrLen + int(ec)
	if len(ciphertext) < minCiphertextLen {
		return nil, fmt.Errorf("sealed token ciphertext too short for encryption type %d: got %d bytes, need at least %d",
			key.KeyType, len(ciphertext), minCiphertextLen)
	}
	switch key.KeyType {
	case etypeID.DES3_CBC_SHA1_KD, etypeID.DES_CBC_MD5, etypeID.DES_CBC_CRC:
		encryptedLength := len(ciphertext) - encType.GetHMACBitLength()/8
		if encryptedLength%encType.GetMessageBlockByteSize() != 0 {
			return nil, fmt.Errorf("sealed token ciphertext length %d is not aligned for encryption type %d",
				len(ciphertext), key.KeyType)
		}
	}

	if rrc > 0 {
		rotateLeft(ciphertext, int(rrc))
	}

	plaintext, err := crypto.DecryptMessage(ciphertext, key, usage)
	if err != nil {
		return nil, fmt.Errorf("decrypting sealed token: %w", err)
	}

	if len(plaintext) < gssapi.HdrLen+int(ec) {
		return nil, fmt.Errorf("decrypted sealed token too short: got %d bytes, need at least %d",
			len(plaintext), gssapi.HdrLen+int(ec))
	}

	headerOffset := len(plaintext) - gssapi.HdrLen
	headerCopy := plaintext[headerOffset:]
	expectedHeader := append([]byte(nil), token[:gssapi.HdrLen]...)
	binary.BigEndian.PutUint16(expectedHeader[6:8], 0)
	if !bytes.Equal(headerCopy, expectedHeader) {
		return nil, fmt.Errorf("sealed token encrypted header does not match the outer header")
	}

	payloadEnd := headerOffset - int(ec)
	if payloadEnd < 0 {
		return nil, fmt.Errorf("sealed token EC padding %d exceeds decrypted payload length %d", ec, headerOffset)
	}
	return plaintext[:payloadEnd], nil
}

// wrapSASLResponse builds the client's SASL response wrapped in an
// integrity-only GSSAPI wrap token (RFC 4752 §3.1, conf_flag=FALSE).
func (g *gssapiClient) wrapSASLResponse(authzid string) ([]byte, error) {
	return g.wrapSASLResponseForLayer(authzid, 0x01, 0)
}

func (g *gssapiClient) wrapSASLPayload(response []byte) ([]byte, error) {
	encType, err := crypto.GetEtype(g.sessionKey.KeyType)
	if err != nil {
		return nil, fmt.Errorf("resolving encryption type for key type %d: %w", g.sessionKey.KeyType, err)
	}

	// Per RFC 4752, the SASL response uses conf_flag=FALSE (integrity only).
	// Per RFC 4121 §2, Wrap tokens always use SEAL key usage (24 for initiator),
	// even when conf_flag=FALSE. SIGN key usage is only for MIC tokens.
	//
	// Per RFC 4121 §4.2.2, the AcceptorSubkey flag (bit 2) must be set when the
	// acceptor's subkey (from AP-REP) protects the message.
	var flags byte
	if !keysEqual(g.sessionKey, g.ticketKey) {
		flags = 0x04 // AcceptorSubkey: the acceptor's subkey is used
	}
	respToken := gssapi.WrapToken{
		Flags:     flags,
		EC:        uint16(encType.GetHMACBitLength() / 8), //nolint:gosec // G115: HMAC byte length is a small constant within uint16
		RRC:       0,
		SndSeqNum: g.sendSeq,
		Payload:   response,
	}

	// RFC 4121 §2: Wrap tokens always use SEAL key usage, even for integrity-only
	// (conf_flag=FALSE). SIGN key usage is only for MIC tokens.
	if err := respToken.SetCheckSum(g.sessionKey, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, fmt.Errorf("computing SASL response checksum: %w", err)
	}

	tokenBytes, err := respToken.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshalling SASL response token: %w", err)
	}

	if g.sequenceReady {
		g.sendSeq++
	}
	return tokenBytes, nil
}

// DeleteSecContext implements ldap.GSSAPIClient.
func (g *gssapiClient) DeleteSecContext() error {
	g.destroyOnce.Do(func() {
		clearEncryptionKey(&g.sessionKey)
		clearEncryptionKey(&g.ticketKey)
		clear(g.channelBinding)
		g.channelBinding = nil
		g.established = false
		g.sendSeq = 0
		g.recvSeq = 0
		g.sequenceReady = false
		if g.client != nil {
			g.client.Destroy()
			g.client = nil
		}
	})
	return nil
}

// saslSecurityLayer protects LDAP protocol data after bootstrap GSSAPI bind.
// The TLS certificate is still hostname-checked, while this layer gives the
// LDAP messages end-to-end Kerberos confidentiality and integrity.
type saslSecurityLayer struct {
	mu             sync.Mutex
	key            types.EncryptionKey
	acceptorSubkey bool
	maxSendToken   int
	sendSeq        uint64
	recvSeq        uint64
	closed         bool
}

func newSASLSecurityLayer(key types.EncryptionKey, acceptorSubkey bool, maxSendToken int, sendSeq, recvSeq uint64) (*saslSecurityLayer, error) {
	if _, err := crypto.GetEtype(key.KeyType); err != nil {
		return nil, fmt.Errorf("resolving SASL security layer encryption type %d: %w", key.KeyType, err)
	}
	if len(key.KeyValue) == 0 {
		return nil, fmt.Errorf("SASL security layer has no session key")
	}
	return &saslSecurityLayer{
		key: types.EncryptionKey{
			KeyType:  key.KeyType,
			KeyValue: append([]byte(nil), key.KeyValue...),
		},
		acceptorSubkey: acceptorSubkey,
		maxSendToken:   maxSendToken,
		sendSeq:        sendSeq,
		recvSeq:        recvSeq,
	}, nil
}

func (s *saslSecurityLayer) maxPlaintextSize() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, fmt.Errorf("SASL security context is closed")
	}
	encType, err := crypto.GetEtype(s.key.KeyType)
	if err != nil {
		return 0, err
	}
	overhead := 2*gssapi.HdrLen + encType.GetConfounderByteSize() + encType.GetHMACBitLength()/8 + encType.GetMessageBlockByteSize() - 1
	if s.maxSendToken <= overhead {
		return 0, fmt.Errorf("server SASL receive buffer %d is too small for encryption overhead %d", s.maxSendToken, overhead)
	}
	return s.maxSendToken - overhead, nil
}

func (s *saslSecurityLayer) wrap(payload []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fmt.Errorf("SASL security context is closed")
	}
	encType, err := crypto.GetEtype(s.key.KeyType)
	if err != nil {
		return nil, err
	}
	blockSize := encType.GetMessageBlockByteSize()
	ec := 0
	if blockSize > 0 {
		ec = (blockSize - len(payload)%blockSize) % blockSize
	}

	flags := byte(0x02)
	if s.acceptorSubkey {
		flags |= 0x04
	}
	header := make([]byte, gssapi.HdrLen)
	copy(header[:2], []byte{0x05, 0x04})
	header[2] = flags
	header[3] = gssapi.FillerByte
	binary.BigEndian.PutUint16(header[4:6], uint16(ec)) //nolint:gosec // EC is bounded by an encryption block.
	binary.BigEndian.PutUint64(header[8:16], s.sendSeq)

	plaintext := make([]byte, 0, len(payload)+ec+gssapi.HdrLen)
	plaintext = append(plaintext, payload...)
	plaintext = append(plaintext, bytes.Repeat([]byte{gssapi.FillerByte}, ec)...)
	plaintext = append(plaintext, header...)
	_, ciphertext, err := encType.EncryptMessage(s.key.KeyValue, plaintext, keyusage.GSSAPI_INITIATOR_SEAL)
	if err != nil {
		return nil, fmt.Errorf("encrypting SASL security layer token: %w", err)
	}
	token := append(header, ciphertext...)
	if len(token) > s.maxSendToken {
		return nil, fmt.Errorf("SASL security layer token is %d bytes, exceeding server limit %d", len(token), s.maxSendToken)
	}
	s.sendSeq++
	return token, nil
}

func (s *saslSecurityLayer) unwrap(token []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fmt.Errorf("SASL security context is closed")
	}
	if len(token) < gssapi.HdrLen {
		return nil, fmt.Errorf("SASL security layer token too short: %d", len(token))
	}
	if token[0] != 0x05 || token[1] != 0x04 || token[2]&0x01 == 0 || token[2]&0x02 == 0 {
		return nil, fmt.Errorf("invalid acceptor confidentiality token")
	}
	if token[3] != gssapi.FillerByte {
		return nil, fmt.Errorf("invalid acceptor confidentiality token filler")
	}
	payload, err := unwrapSealedToken(token, s.key, binary.BigEndian.Uint16(token[6:8]), &s.recvSeq, keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil {
		return nil, err
	}
	s.recvSeq++
	return payload, nil
}

func (s *saslSecurityLayer) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	clearEncryptionKey(&s.key)
}

func clearEncryptionKey(key *types.EncryptionKey) {
	if key == nil {
		return
	}
	clear(key.KeyValue)
	*key = types.EncryptionKey{}
}

// rotateLeft rotates a byte slice left by count positions, undoing the RRC
// (right rotation count) applied by RFC 4121 wrap tokens.
func rotateLeft(data []byte, count int) {
	n := len(data)
	if n == 0 {
		return
	}
	count = count % n
	if count == 0 {
		return
	}
	tmp := make([]byte, n)
	copy(tmp, data[count:])
	copy(tmp[n-count:], data[:count])
	copy(data, tmp)
}

// keysEqual returns true if two encryption keys have the same key value.
func keysEqual(a, b types.EncryptionKey) bool {
	if len(a.KeyValue) != len(b.KeyValue) {
		return false
	}
	for i := range a.KeyValue {
		if a.KeyValue[i] != b.KeyValue[i] {
			return false
		}
	}
	return true
}

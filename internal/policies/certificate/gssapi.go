package certificate

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/go-ldap/ldap/v3"
	asn1 "github.com/jcmturner/gofork/encoding/asn1"
	"github.com/oiweiwei/gokrb5.fork/v9/asn1tools"
	krbclient "github.com/oiweiwei/gokrb5.fork/v9/client"
	"github.com/oiweiwei/gokrb5.fork/v9/crypto"
	"github.com/oiweiwei/gokrb5.fork/v9/gssapi"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/chksumtype"
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
}

// newGSSAPIClient creates a GSSAPIClient adapter from a gokrb5 client.
//
// channelBinding is the 16-byte tls-server-end-point channel binding token
// (RFC 5929) derived from the LDAP server's TLS certificate. It is embedded in
// the AP-REQ authenticator checksum so the bind succeeds against Domain
// Controllers that enforce LDAP channel binding (CBT/EPA). Pass nil to bind
// without channel binding.
func newGSSAPIClient(cl *krbclient.Client, channelBinding []byte) ldap.GSSAPIClient {
	return &gssapiClient{client: cl, channelBinding: channelBinding}
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
	}

	// Build AP options: merge caller-provided options with mutual-required
	// (bit 2 per RFC 4120). We allocate a new slice to avoid mutating the
	// caller's backing array.
	apOptions := make([]int, len(options)+1)
	copy(apOptions, options)
	apOptions[len(options)] = 2

	tokenBytes, err := buildKRB5APREQToken(g.client, tkt, key, gssFlags, apOptions, g.channelBinding)
	if err != nil {
		return nil, false, err
	}

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
func buildKRB5APREQToken(cl *krbclient.Client, tkt messages.Ticket, key types.EncryptionKey, gssFlags, apOptions []int, channelBinding []byte) ([]byte, error) {
	auth, err := types.NewAuthenticator(cl.Credentials.Domain(), cl.Credentials.CName())
	if err != nil {
		return nil, fmt.Errorf("creating Kerberos authenticator: %w", err)
	}
	auth.Cksum = types.Checksum{
		CksumType: chksumtype.GSSAPI,
		Checksum:  gssAPIBindingChecksum(gssFlags, channelBinding),
	}

	apReq, err := messages.NewAPReq(tkt, key, auth)
	if err != nil {
		return nil, fmt.Errorf("creating AP-REQ: %w", err)
	}
	for _, o := range apOptions {
		types.SetFlag(&apReq.APOptions, o)
	}

	// Marshal as a KRB5 GSS MechToken: KRB5 OID | TOK_ID(AP-REQ=0x0100) |
	// AP-REQ, wrapped in a GSS application tag (mirrors KRB5Token.Marshal).
	oid, err := asn1.Marshal(gssapi.OIDKRB5.OID())
	if err != nil {
		return nil, fmt.Errorf("marshalling KRB5 OID: %w", err)
	}
	apReqBytes, err := apReq.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshalling AP-REQ: %w", err)
	}

	token := append(oid, 0x01, 0x00) // TOK_ID_KRB_AP_REQ
	token = append(token, apReqBytes...)
	return asn1tools.AddASNAppTag(token, 0), nil
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

	g.established = true
	return nil, false, nil
}

// NegotiateSaslAuth implements ldap.GSSAPIClient.
//
// It handles the final SASL negotiation step (RFC 4752 §3.1):
//  1. Unwrap the server's GSSAPI wrap token to extract the 4-byte SASL payload
//     describing supported security layers and max buffer size.
//  2. Build a response selecting "no security layer" (auth only).
//  3. Wrap the response as an integrity-only GSSAPI wrap token.
//
// Auth-only (no SASL security layer) is selected because go-ldap does not
// support wrapping/unwrapping individual LDAP messages after the SASL bind.
// Message-level protection is provided by StartTLS, which is negotiated
// before the GSSAPI bind and verified against the system trust store plus
// any adsys-managed CA certificates.
func (g *gssapiClient) NegotiateSaslAuth(token []byte, authzid string) ([]byte, error) {
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
	// We require auth-only (0x01) because go-ldap cannot wrap/unwrap
	// individual LDAP messages after the SASL bind. Message-level
	// protection is provided by StartTLS.
	if payload[0]&0x01 == 0 {
		return nil, fmt.Errorf("server does not support auth-only security layer (bitmask: %02x); "+
			"integrity/confidentiality SASL layers are not supported by go-ldap", payload[0])
	}

	return g.wrapSASLResponse(authzid)
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

	isSealed := token[2]&0x02 != 0
	rrc := binary.BigEndian.Uint16(token[6:8])

	log.Debugf(context.Background(), "gssapi: unwrapServerToken: len=%d flags=0x%02x sealed=%v EC=%d RRC=%d",
		len(token), token[2], isSealed,
		binary.BigEndian.Uint16(token[4:6]), rrc)

	if isSealed {
		return g.unwrapSealed(token, rrc)
	}
	return g.unwrapIntegrity(token, rrc)
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
	ec := binary.BigEndian.Uint16(token[4:6])

	// Copy the ciphertext portion (after the 16-byte header).
	ciphertext := make([]byte, len(token)-gssapi.HdrLen)
	copy(ciphertext, token[gssapi.HdrLen:])

	// Undo RRC rotation on the ciphertext.
	if rrc > 0 && len(ciphertext) > 0 {
		rotateLeft(ciphertext, int(rrc))
	}

	plaintext, err := crypto.DecryptMessage(ciphertext, g.sessionKey, keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil {
		return nil, fmt.Errorf("decrypting sealed token: %w", err)
	}

	// Strip the trailing header copy (16 bytes).
	if len(plaintext) < gssapi.HdrLen {
		return nil, fmt.Errorf("decrypted payload too short: %d bytes", len(plaintext))
	}
	payload := plaintext[:len(plaintext)-gssapi.HdrLen]

	// Strip EC padding zeros.
	if ec > 0 && len(payload) >= int(ec) {
		payload = payload[:len(payload)-int(ec)]
	}

	return payload, nil
}

// wrapSASLResponse builds the client's SASL response wrapped in an
// integrity-only GSSAPI wrap token (RFC 4752 §3.1, conf_flag=FALSE).
func (g *gssapiClient) wrapSASLResponse(authzid string) ([]byte, error) {
	// Build response: select no security layer (auth only), max buffer 0.
	response := make([]byte, 4, 4+len(authzid))
	response[0] = 0x01 // No security layer (authentication only)
	// Bytes 1-3 = 0 (no buffer size needed)

	if authzid != "" {
		response = append(response, []byte(authzid)...)
	}

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
		SndSeqNum: 0,
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

	return tokenBytes, nil
}

// DeleteSecContext implements ldap.GSSAPIClient.
func (g *gssapiClient) DeleteSecContext() error {
	return nil
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

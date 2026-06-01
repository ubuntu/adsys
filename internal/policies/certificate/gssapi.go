package certificate

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/go-ldap/ldap/v3"
	krbclient "github.com/oiweiwei/gokrb5.fork/v9/client"
	"github.com/oiweiwei/gokrb5.fork/v9/crypto"
	"github.com/oiweiwei/gokrb5.fork/v9/gssapi"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/keyusage"
	"github.com/oiweiwei/gokrb5.fork/v9/spnego"
	"github.com/oiweiwei/gokrb5.fork/v9/types"
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
	client      *krbclient.Client
	sessionKey  types.EncryptionKey
	ticketKey   types.EncryptionKey // original key from the service ticket (before subkey extraction)
	established bool
}

// newGSSAPIClient creates a GSSAPIClient adapter from a gokrb5 client.
func newGSSAPIClient(cl *krbclient.Client) ldap.GSSAPIClient {
	return &gssapiClient{client: cl}
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

	krb5Token, err := spnego.NewKRB5TokenAPREQ(g.client, tkt, key, gssFlags, apOptions)
	if err != nil {
		return nil, false, fmt.Errorf("creating AP-REQ token: %w", err)
	}

	tokenBytes, err := krb5Token.Marshal()
	if err != nil {
		return nil, false, fmt.Errorf("marshalling AP-REQ token: %w", err)
	}

	return tokenBytes, true, nil
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
		log.Printf("gssapi: AP-REP subkey extracted (type=%d, len=%d)",
			g.sessionKey.KeyType, len(g.sessionKey.KeyValue))
	} else {
		log.Printf("gssapi: no subkey in AP-REP, using ticket session key (type=%d, len=%d)",
			g.sessionKey.KeyType, len(g.sessionKey.KeyValue))
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
func (g *gssapiClient) NegotiateSaslAuth(token []byte, authzid string) ([]byte, error) {
	payload, err := g.unwrapServerToken(token)
	if err != nil {
		return nil, fmt.Errorf("unwrapping server SASL token: %w", err)
	}

	if len(payload) < 4 {
		return nil, fmt.Errorf("server SASL payload too short: got %d bytes, need at least 4", len(payload))
	}

	// Byte 0: supported security layers bitmask
	//   bit 0 (0x01) = no security layer
	//   bit 1 (0x02) = integrity only
	//   bit 2 (0x04) = confidentiality
	if payload[0]&0x01 == 0 {
		return nil, fmt.Errorf("server does not support auth-only security layer (bitmask: %02x)", payload[0])
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

	log.Printf("gssapi: unwrapServerToken: len=%d flags=0x%02x sealed=%v EC=%d RRC=%d header=%s",
		len(token), token[2], isSealed,
		binary.BigEndian.Uint16(token[4:6]), rrc,
		hex.EncodeToString(token[:gssapi.HdrLen]))

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

	log.Printf("gssapi: unwrapIntegrity: flags=0x%02x EC=%d RRC=%d seqNum=%d payloadLen=%d checksumLen=%d keyType=%d",
		wrapToken.Flags, wrapToken.EC, wrapToken.RRC, wrapToken.SndSeqNum,
		len(wrapToken.Payload), len(wrapToken.CheckSum), g.sessionKey.KeyType)

	// RFC 4121 §2: Wrap tokens always use SEAL key usage, even for integrity-only
	// (conf_flag=FALSE). SIGN key usage is only for MIC tokens.
	if ok, err := wrapToken.Verify(g.sessionKey, keyusage.GSSAPI_ACCEPTOR_SEAL); !ok {
		// Try with the original ticket session key as fallback — some servers
		// may not use the AP-REP subkey for the SASL challenge.
		if !keysEqual(g.ticketKey, g.sessionKey) {
			log.Printf("gssapi: subkey verification failed, trying ticket session key (type=%d)", g.ticketKey.KeyType)
			if ok2, _ := wrapToken.Verify(g.ticketKey, keyusage.GSSAPI_ACCEPTOR_SEAL); ok2 {
				log.Printf("gssapi: ticket session key worked — server is not using AP-REP subkey for SASL")
				g.sessionKey = g.ticketKey
				return wrapToken.Payload, nil
			}
		}
		return nil, fmt.Errorf("integrity token verification failed (tokenHeader=%s, keyType=%d, keyLen=%d): %w",
			hex.EncodeToString(token[:gssapi.HdrLen]), g.sessionKey.KeyType, len(g.sessionKey.KeyValue), err)
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
		EC:        uint16(encType.GetHMACBitLength() / 8),
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

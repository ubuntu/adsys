package certificate

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/go-ldap/ldap/v3"
	asn1 "github.com/jcmturner/gofork/encoding/asn1"
	"github.com/oiweiwei/gokrb5.fork/v9/asn1tools"
	krbclient "github.com/oiweiwei/gokrb5.fork/v9/client"
	krbconfig "github.com/oiweiwei/gokrb5.fork/v9/config"
	"github.com/oiweiwei/gokrb5.fork/v9/credentials"
	"github.com/oiweiwei/gokrb5.fork/v9/crypto"
	"github.com/oiweiwei/gokrb5.fork/v9/gssapi"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/chksumtype"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/etypeID"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/keyusage"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/nametype"
	"github.com/oiweiwei/gokrb5.fork/v9/messages"
	"github.com/oiweiwei/gokrb5.fork/v9/spnego"
	"github.com/oiweiwei/gokrb5.fork/v9/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testKey returns an AES256 encryption key for use in tests.
// The key is 32 bytes (256 bits) as required by AES256-CTS-HMAC-SHA1-96.
func testKey() types.EncryptionKey {
	return types.EncryptionKey{
		KeyType: etypeID.AES256_CTS_HMAC_SHA1_96,
		KeyValue: []byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
			0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
		},
	}
}

// buildIntegrityWrapToken creates a valid integrity-only GSSAPI wrap token
// from the acceptor using the provided key, payload, and key usage.
func buildIntegrityWrapToken(t *testing.T, key types.EncryptionKey, payload []byte, keyUsage uint32) []byte {
	t.Helper()
	return buildIntegrityWrapTokenWithSequence(t, key, payload, keyUsage, 0)
}

func buildIntegrityWrapTokenWithSequence(t *testing.T, key types.EncryptionKey, payload []byte, keyUsage uint32, sequence uint64) []byte {
	t.Helper()

	encType, err := crypto.GetEtype(key.KeyType)
	require.NoError(t, err)

	wt := gssapi.WrapToken{
		Flags:     0x01,                                   // sent by acceptor
		EC:        uint16(encType.GetHMACBitLength() / 8), //nolint:gosec // G115: HMAC byte length is a small constant within uint16
		RRC:       0,
		SndSeqNum: sequence,
		Payload:   payload,
	}

	require.NoError(t, wt.SetCheckSum(key, keyUsage))

	b, err := wt.Marshal()
	require.NoError(t, err)
	return b
}

func buildSealedWrapToken(t *testing.T, key types.EncryptionKey, payload []byte) []byte {
	t.Helper()
	return buildSealedWrapTokenWithSequence(t, key, payload, 0)
}

func buildSealedWrapTokenWithSequence(t *testing.T, key types.EncryptionKey, payload []byte, sequence uint64) []byte {
	t.Helper()
	encType, err := crypto.GetEtype(key.KeyType)
	require.NoError(t, err)
	ec := (encType.GetMessageBlockByteSize() - len(payload)%encType.GetMessageBlockByteSize()) % encType.GetMessageBlockByteSize()
	header := make([]byte, gssapi.HdrLen)
	copy(header, []byte{0x05, 0x04, 0x03, gssapi.FillerByte})
	binary.BigEndian.PutUint16(header[4:6], uint16(ec)) //nolint:gosec // Test EC is bounded by the encryption block size.
	binary.BigEndian.PutUint64(header[8:16], sequence)

	plaintext := append([]byte(nil), payload...)
	for range ec {
		plaintext = append(plaintext, gssapi.FillerByte)
	}
	plaintext = append(plaintext, header...)
	_, ciphertext, err := encType.EncryptMessage(key.KeyValue, plaintext, keyusage.GSSAPI_ACCEPTOR_SEAL)
	require.NoError(t, err)
	return append(header, ciphertext...)
}

func TestNegotiateSaslAuth(t *testing.T) {
	t.Parallel()

	key := testKey()

	// Standard SASL challenge: supports all security layers, 64KB max buffer.
	saslChallenge := []byte{0x07, 0x00, 0xff, 0xff}

	tests := map[string]struct {
		token   func(t *testing.T) []byte
		authzid string

		wantErr bool
	}{
		"Successful negotiation with integrity token": {
			token: func(t *testing.T) []byte {
				t.Helper()
				return buildIntegrityWrapToken(t, key, saslChallenge, keyusage.GSSAPI_ACCEPTOR_SEAL)
			},
		},

		"Successful negotiation with authzid": {
			token: func(t *testing.T) []byte {
				t.Helper()
				return buildIntegrityWrapToken(t, key, saslChallenge, keyusage.GSSAPI_ACCEPTOR_SEAL)
			},
			authzid: "admin@EXAMPLE.COM",
		},

		"Successful negotiation with auth-only layer": {
			token: func(t *testing.T) []byte {
				t.Helper()
				// Only auth-only supported (bit 0)
				payload := []byte{0x01, 0x00, 0x00, 0x00}
				return buildIntegrityWrapToken(t, key, payload, keyusage.GSSAPI_ACCEPTOR_SEAL)
			},
		},

		"Error on token too short": {
			token: func(t *testing.T) []byte {
				t.Helper()
				return []byte{0x05, 0x04, 0x01}
			},
			wantErr: true,
		},

		"Error on wrong token ID": {
			token: func(t *testing.T) []byte {
				t.Helper()
				tok := buildIntegrityWrapToken(t, key, saslChallenge, keyusage.GSSAPI_ACCEPTOR_SEAL)
				tok[0] = 0x04 // corrupt token ID
				return tok
			},
			wantErr: true,
		},

		"Error on checksum mismatch": {
			token: func(t *testing.T) []byte {
				t.Helper()
				tok := buildIntegrityWrapToken(t, key, saslChallenge, keyusage.GSSAPI_ACCEPTOR_SEAL)
				// Corrupt the last byte of the checksum
				tok[len(tok)-1] ^= 0xff
				return tok
			},
			wantErr: true,
		},

		"Error on SASL payload too short": {
			token: func(t *testing.T) []byte {
				t.Helper()
				// 3-byte payload — not enough for the 4-byte SASL structure
				payload := []byte{0x07, 0x00, 0xff}
				return buildIntegrityWrapToken(t, key, payload, keyusage.GSSAPI_ACCEPTOR_SEAL)
			},
			wantErr: true,
		},

		"Error when server does not support any security layer": {
			token: func(t *testing.T) []byte {
				t.Helper()
				// Only integrity (0x02) and confidentiality (0x04) — no auth-only (0x01)
				payload := []byte{0x06, 0x00, 0xff, 0xff}
				return buildIntegrityWrapToken(t, key, payload, keyusage.GSSAPI_ACCEPTOR_SEAL)
			},
			wantErr: true,
		},

		"Error on wrong key usage in server token": {
			token: func(t *testing.T) []byte {
				t.Helper()
				// Server signs with wrong key usage — should fail verification
				return buildIntegrityWrapToken(t, key, saslChallenge, keyusage.GSSAPI_INITIATOR_SEAL)
			},
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			g := &gssapiClient{sessionKey: key, established: true, sequenceReady: true}
			token := tc.token(t)

			result, err := g.NegotiateSaslAuth(token, tc.authzid)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, result, "expected non-empty SASL response token")

			// Verify the response is a valid wrap token that we can parse back
			var respToken gssapi.WrapToken
			err = respToken.Unmarshal(result, false) // false: from initiator
			require.NoError(t, err)

			// Verify the response token's checksum with the correct key usage
			ok, err := respToken.Verify(key, keyusage.GSSAPI_INITIATOR_SEAL)
			require.NoError(t, err)
			assert.True(t, ok, "response token checksum should verify")

			// Verify the response payload structure
			require.GreaterOrEqual(t, len(respToken.Payload), 4)
			assert.Equal(t, byte(0x01), respToken.Payload[0], "should select auth-only layer")
			assert.Equal(t, []byte{0x00, 0x00, 0x00}, respToken.Payload[1:4], "buffer size should be zero")

			// Verify authzid if present
			if tc.authzid != "" {
				assert.Equal(t, tc.authzid, string(respToken.Payload[4:]))
			}
		})
	}
}

func TestProcessAPREPInitializesAcceptorSequence(t *testing.T) {
	t.Parallel()

	key := testKey()
	const acceptorSequence = 4321
	apRep, err := messages.NewAPRep(key, messages.NewEncAPRepPart(acceptorSequence))
	require.NoError(t, err)
	oid, err := asn1.Marshal(gssapi.OIDKRB5.OID())
	require.NoError(t, err)
	apRepBytes, err := apRep.Marshal()
	require.NoError(t, err)
	token := asn1tools.AddASNAppTag(append(append(oid, 0x02, 0x00), apRepBytes...), 0)

	g := &gssapiClient{sessionKey: key, ticketKey: key, sendSeq: 1234}
	_, continueNeeded, err := g.processAPREP(token)
	require.NoError(t, err)
	assert.False(t, continueNeeded)
	assert.True(t, g.sequenceReady)
	assert.Equal(t, uint64(acceptorSequence), g.recvSeq)
	assert.Equal(t, uint64(1234), g.sendSeq)
}

func TestNegotiateSaslAuthBootstrapRequiresConfidentiality(t *testing.T) {
	t.Parallel()

	key := testKey()
	const (
		initiatorSequence = 17
		acceptorSequence  = 23
	)
	challenge := buildIntegrityWrapTokenWithSequence(t, key, []byte{0x07, 0x01, 0x00, 0x00}, keyusage.GSSAPI_ACCEPTOR_SEAL, acceptorSequence)
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = serverConn.Close() })
	transport := newSASLSecurityConn(clientConn)
	t.Cleanup(func() { _ = transport.Close() })
	g := &gssapiClient{
		sessionKey:           key,
		ticketKey:            key,
		established:          true,
		sendSeq:              initiatorSequence,
		recvSeq:              acceptorSequence,
		sequenceReady:        true,
		requireSecurityLayer: true,
		securityTransport:    transport,
	}

	response, err := g.NegotiateSaslAuth(challenge, "")
	require.NoError(t, err)

	var responseToken gssapi.WrapToken
	require.NoError(t, responseToken.Unmarshal(response, false))
	ok, err := responseToken.Verify(key, keyusage.GSSAPI_INITIATOR_SEAL)
	require.NoError(t, err)
	require.True(t, ok)
	require.Len(t, responseToken.Payload, 4)
	assert.Equal(t, uint64(initiatorSequence), responseToken.SndSeqNum)
	assert.Equal(t, byte(0x04), responseToken.Payload[0])
	assert.Equal(t, []byte{0xff, 0xff, 0xff}, responseToken.Payload[1:])

	transport.observeRawBindResponse([]byte{0x30, 0x00})
	require.NoError(t, transport.securityLayerStatus())
	transport.stateMu.Lock()
	layerKey := transport.layer.key.KeyValue
	assert.Equal(t, uint64(initiatorSequence+1), transport.layer.sendSeq)
	assert.Equal(t, uint64(acceptorSequence+1), transport.layer.recvSeq)
	transport.stateMu.Unlock()
	require.NoError(t, transport.Close())
	assert.Equal(t, make([]byte, len(layerKey)), layerKey)
}

func TestNegotiateSaslAuthRejectsReplayAndOutOfOrder(t *testing.T) {
	t.Parallel()

	key := testKey()
	const (
		initiatorSequence = 100
		acceptorSequence  = 200
	)
	challenge := func(sequence uint64) []byte {
		return buildIntegrityWrapTokenWithSequence(t, key, []byte{0x01, 0, 0, 0}, keyusage.GSSAPI_ACCEPTOR_SEAL, sequence)
	}
	g := &gssapiClient{
		sessionKey:    key,
		ticketKey:     key,
		established:   true,
		sendSeq:       initiatorSequence,
		recvSeq:       acceptorSequence,
		sequenceReady: true,
	}

	response, err := g.NegotiateSaslAuth(challenge(acceptorSequence), "")
	require.NoError(t, err)
	var responseToken gssapi.WrapToken
	require.NoError(t, responseToken.Unmarshal(response, false))
	assert.Equal(t, uint64(initiatorSequence), responseToken.SndSeqNum)
	assert.Equal(t, uint64(initiatorSequence+1), g.sendSeq)
	assert.Equal(t, uint64(acceptorSequence+1), g.recvSeq)

	_, err = g.unwrapServerToken(challenge(acceptorSequence))
	require.ErrorContains(t, err, "sequence number")
	_, err = g.unwrapServerToken(challenge(acceptorSequence + 2))
	require.ErrorContains(t, err, "sequence number")
	_, err = g.unwrapServerToken(challenge(acceptorSequence + 1))
	require.NoError(t, err)
}

func TestSASLSecurityLayerSequenceContinuation(t *testing.T) {
	t.Parallel()

	key := testKey()
	layer, err := newSASLSecurityLayer(key, false, 64*1024, 101, 201)
	require.NoError(t, err)
	t.Cleanup(layer.Close)

	inbound := buildSealedWrapTokenWithSequence(t, key, []byte("response"), 201)
	got, err := layer.unwrap(inbound)
	require.NoError(t, err)
	assert.Equal(t, []byte("response"), got)

	_, err = layer.unwrap(inbound)
	require.ErrorContains(t, err, "sequence number")
	_, err = layer.unwrap(buildSealedWrapTokenWithSequence(t, key, []byte("future"), 203))
	require.ErrorContains(t, err, "sequence number")
	_, err = layer.unwrap(buildSealedWrapTokenWithSequence(t, key, []byte("next"), 202))
	require.NoError(t, err)

	first, err := layer.wrap([]byte("request one"))
	require.NoError(t, err)
	second, err := layer.wrap([]byte("request two"))
	require.NoError(t, err)
	assert.Equal(t, uint64(101), binary.BigEndian.Uint64(first[8:16]))
	assert.Equal(t, uint64(102), binary.BigEndian.Uint64(second[8:16]))
}

func TestSASLSecurityLayerNonzeroECSenderInteroperability(t *testing.T) {
	t.Parallel()

	key := types.EncryptionKey{
		KeyType:  etypeID.DES3_CBC_SHA1_KD,
		KeyValue: []byte("0123456789abcdefghijklmn"),
	}
	const sequence = 55
	layer, err := newSASLSecurityLayer(key, false, 64*1024, sequence, 0)
	require.NoError(t, err)
	t.Cleanup(layer.Close)

	want := []byte{0x01, 0x02, 0x03, 0x04}
	token, err := layer.wrap(want)
	require.NoError(t, err)
	require.NotZero(t, binary.BigEndian.Uint16(token[4:6]))
	expectedSequence := uint64(sequence)
	got, err := unwrapSealedToken(token, key, 0, &expectedSequence, keyusage.GSSAPI_INITIATOR_SEAL)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestNegotiateSaslAuth_RRCHandling(t *testing.T) {
	t.Parallel()

	key := testKey()
	saslChallenge := []byte{0x07, 0x00, 0xff, 0xff}

	// Build a valid integrity token then apply RRC rotation.
	tok := buildIntegrityWrapToken(t, key, saslChallenge, keyusage.GSSAPI_ACCEPTOR_SEAL)

	// The data portion is everything after the 16-byte header.
	data := tok[gssapi.HdrLen:]

	// Apply a right-rotation of 4 bytes (RRC=4).
	const rrc = 4
	rotated := make([]byte, len(data))
	copy(rotated, data[len(data)-rrc:])
	copy(rotated[rrc:], data[:len(data)-rrc])
	copy(tok[gssapi.HdrLen:], rotated)

	// Set the RRC field in the header.
	binary.BigEndian.PutUint16(tok[6:8], rrc)

	g := &gssapiClient{sessionKey: key, established: true, sequenceReady: true}
	result, err := g.NegotiateSaslAuth(tok, "")
	require.NoError(t, err)
	require.NotEmpty(t, result)

	// Verify the response is valid
	var respToken gssapi.WrapToken
	require.NoError(t, respToken.Unmarshal(result, false))
	ok, err := respToken.Verify(key, keyusage.GSSAPI_INITIATOR_SEAL)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestUnwrapServerToken_IntegrityOnly(t *testing.T) {
	t.Parallel()

	key := testKey()

	tests := map[string]struct {
		payload []byte
	}{
		"Simple 4-byte payload": {
			payload: []byte{0x07, 0x00, 0xff, 0xff},
		},
		"Single byte payload": {
			payload: []byte{0x42},
		},
		"Larger payload": {
			payload: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tok := buildIntegrityWrapToken(t, key, tc.payload, keyusage.GSSAPI_ACCEPTOR_SEAL)
			g := &gssapiClient{sessionKey: key}

			got, err := g.unwrapServerToken(tok)
			require.NoError(t, err)
			assert.Equal(t, tc.payload, got)
		})
	}
}

func TestUnwrapServerToken_Sealed(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		key              types.EncryptionKey
		requireNonzeroEC bool
	}{
		"AES256": {key: testKey()},
		"DES3 with nonzero EC": {
			key: types.EncryptionKey{
				KeyType:  etypeID.DES3_CBC_SHA1_KD,
				KeyValue: []byte("0123456789abcdefghijklmn"),
			},
			requireNonzeroEC: true,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			want := []byte{0x07, 0x00, 0xff, 0xff}
			token := buildSealedWrapToken(t, tc.key, want)
			if tc.requireNonzeroEC {
				require.NotZero(t, binary.BigEndian.Uint16(token[4:6]))
			}
			const rrc = 3
			ciphertext := token[gssapi.HdrLen:]
			rotated := append([]byte(nil), ciphertext[len(ciphertext)-rrc:]...)
			rotated = append(rotated, ciphertext[:len(ciphertext)-rrc]...)
			copy(ciphertext, rotated)
			binary.BigEndian.PutUint16(token[6:8], rrc)

			got, err := (&gssapiClient{sessionKey: tc.key}).unwrapServerToken(token)
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}
}

func TestUnwrapServerToken_Errors(t *testing.T) {
	t.Parallel()

	key := testKey()

	tests := map[string]struct {
		token []byte
	}{
		"Token shorter than header": {
			token: make([]byte, gssapi.HdrLen-1),
		},
		"Wrong token ID first byte": {
			token: func() []byte {
				tok := make([]byte, gssapi.HdrLen+20)
				tok[0] = 0x04
				tok[1] = 0x04
				return tok
			}(),
		},
		"Wrong token ID second byte": {
			token: func() []byte {
				tok := make([]byte, gssapi.HdrLen+20)
				tok[0] = 0x05
				tok[1] = 0x03
				return tok
			}(),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			g := &gssapiClient{sessionKey: key}
			_, err := g.unwrapServerToken(tc.token)
			require.Error(t, err)
		})
	}
}

func TestUnwrapServerToken_TruncatedSealedTokensNeverPanic(t *testing.T) {
	t.Parallel()

	etypes := []int32{
		etypeID.AES128_CTS_HMAC_SHA1_96,
		etypeID.AES256_CTS_HMAC_SHA1_96,
		etypeID.AES128_CTS_HMAC_SHA256_128,
		etypeID.AES256_CTS_HMAC_SHA384_192,
		etypeID.DES3_CBC_SHA1_KD,
		etypeID.RC4_HMAC,
		etypeID.DES_CBC_MD5,
		etypeID.DES_CBC_CRC,
	}
	for _, keyType := range etypes {
		t.Run(fmt.Sprintf("etype_%d", keyType), func(t *testing.T) {
			t.Parallel()
			encType, err := crypto.GetEtype(keyType)
			require.NoError(t, err)
			minCiphertext := encType.GetConfounderByteSize() + encType.GetHMACBitLength()/8 + gssapi.HdrLen

			for ciphertextLen := 0; ciphertextLen < minCiphertext+encType.GetMessageBlockByteSize(); ciphertextLen++ {
				token := make([]byte, gssapi.HdrLen+ciphertextLen)
				copy(token[:2], []byte{0x05, 0x04})
				token[2] = 0x03
				token[3] = gssapi.FillerByte
				g := &gssapiClient{sessionKey: types.EncryptionKey{KeyType: keyType}}

				var unwrapErr error
				require.NotPanics(t, func() {
					_, unwrapErr = g.unwrapServerToken(token)
				})
				require.Error(t, unwrapErr)
			}
		})
	}
}

func TestWrapSASLResponse(t *testing.T) {
	t.Parallel()

	key := testKey()

	tests := map[string]struct {
		authzid string

		wantPayloadLen int
	}{
		"Without authzid": {
			wantPayloadLen: 4,
		},
		"With authzid": {
			authzid:        "user@REALM",
			wantPayloadLen: 4 + len("user@REALM"),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			g := &gssapiClient{sessionKey: key, ticketKey: key}
			result, err := g.wrapSASLResponse(tc.authzid)
			require.NoError(t, err)
			require.NotEmpty(t, result)

			// Parse the result as a WrapToken
			var wt gssapi.WrapToken
			require.NoError(t, wt.Unmarshal(result, false))

			// Verify checksum
			ok, err := wt.Verify(key, keyusage.GSSAPI_INITIATOR_SEAL)
			require.NoError(t, err)
			assert.True(t, ok)

			// Verify flags: not sealed, not from acceptor
			assert.Equal(t, byte(0x00), wt.Flags)

			// Verify payload
			assert.Len(t, wt.Payload, tc.wantPayloadLen)
			assert.Equal(t, byte(0x01), wt.Payload[0], "should select auth-only")
		})
	}
}

func TestRotateLeft(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		input []byte
		count int
		want  []byte
	}{
		"No rotation":       {input: []byte{1, 2, 3, 4}, count: 0, want: []byte{1, 2, 3, 4}},
		"Rotate by 1":       {input: []byte{1, 2, 3, 4}, count: 1, want: []byte{2, 3, 4, 1}},
		"Rotate by 2":       {input: []byte{1, 2, 3, 4}, count: 2, want: []byte{3, 4, 1, 2}},
		"Rotate full cycle": {input: []byte{1, 2, 3, 4}, count: 4, want: []byte{1, 2, 3, 4}},
		"Rotate wrap":       {input: []byte{1, 2, 3, 4}, count: 5, want: []byte{2, 3, 4, 1}},
		"Empty slice":       {input: []byte{}, count: 3, want: []byte{}},
		"Single element":    {input: []byte{42}, count: 1, want: []byte{42}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			data := make([]byte, len(tc.input))
			copy(data, tc.input)
			rotateLeft(data, tc.count)
			assert.Equal(t, tc.want, data)
		})
	}
}

func TestDeleteSecContext(t *testing.T) {
	t.Parallel()
	g := &gssapiClient{}
	assert.NoError(t, g.DeleteSecContext())
}

func TestBindKerberosClientAlwaysCleansUp(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		bindErr error
	}{
		"successful bind": {},
		"failed bind":     {bindErr: errors.New("bind failed")},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			client := krbclient.NewWithPassword("machine$", "EXAMPLE.COM", "secret", krbconfig.New())
			ownedKey := testKey()
			ownedKeyBytes := ownedKey.KeyValue
			err := bindKerberosClient(context.Background(), client, "dc.example.com", []byte("channel binding"), false, nil,
				func(gssClient ldap.GSSAPIClient, spn string) error {
					assert.Equal(t, "ldap/dc.example.com", spn)
					g, ok := gssClient.(*gssapiClient)
					require.True(t, ok)
					g.sessionKey = ownedKey
					g.ticketKey = types.EncryptionKey{
						KeyType:  ownedKey.KeyType,
						KeyValue: append([]byte(nil), ownedKey.KeyValue...),
					}
					return tc.bindErr
				})
			if tc.bindErr != nil {
				require.ErrorIs(t, err, tc.bindErr)
			} else {
				require.NoError(t, err)
			}
			assert.Empty(t, client.Credentials.UserName())
			assert.Empty(t, client.Credentials.Domain())
			assert.Equal(t, make([]byte, len(ownedKeyBytes)), ownedKeyBytes)
		})
	}
}

func TestGSSAPIBindingChecksum(t *testing.T) {
	t.Parallel()

	flags := []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf, gssapi.ContextFlagMutual, gssapi.ContextFlagSequence}

	repeat := func(b byte) []byte {
		x := make([]byte, 16)
		for i := range x {
			x[i] = b
		}
		return x
	}

	tests := map[string]struct {
		flags          []int
		channelBinding []byte

		wantBnd []byte // expected bytes 4..19
	}{
		"No channel binding (nil)": {
			flags:   flags,
			wantBnd: make([]byte, 16),
		},
		"16-byte channel binding is embedded": {
			flags:          flags,
			channelBinding: repeat(0xAB),
			wantBnd:        repeat(0xAB),
		},
		"Wrong-length channel binding is ignored": {
			flags:          flags,
			channelBinding: []byte{0x01, 0x02, 0x03},
			wantBnd:        make([]byte, 16),
		},
		"No flags": {
			flags:   nil,
			wantBnd: make([]byte, 16),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cksum := gssAPIBindingChecksum(tc.flags, tc.channelBinding)
			require.Len(t, cksum, 24)

			// Lgth field is always 16 (length of the Bnd field).
			assert.Equal(t, uint32(16), binary.LittleEndian.Uint32(cksum[:4]))

			// Bnd field carries the channel binding (or zeros).
			assert.Equal(t, tc.wantBnd, cksum[4:20])

			// Flags field is the OR of all requested flags.
			var wantFlags uint32
			for _, f := range tc.flags {
				wantFlags |= uint32(f) //nolint:gosec // G115: GSS-API context flag values are small constants.
			}
			assert.Equal(t, wantFlags, binary.LittleEndian.Uint32(cksum[20:24]))
		})
	}
}

func TestBuildKRB5APREQToken(t *testing.T) {
	t.Parallel()

	key := testKey()
	cl := &krbclient.Client{Credentials: credentials.New("host$", "EXAMPLE.COM")}

	tkt := messages.Ticket{
		TktVNO: 5,
		Realm:  "EXAMPLE.COM",
		SName: types.PrincipalName{
			NameType:   nametype.KRB_NT_SRV_INST,
			NameString: []string{"ldap", "dc.example.com"},
		},
		EncPart: types.EncryptedData{EType: key.KeyType, KVNO: 1},
	}

	gssFlags := []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf, gssapi.ContextFlagMutual, gssapi.ContextFlagSequence}
	apOptions := []int{2}

	channelBinding := make([]byte, 16)
	for i := range channelBinding {
		channelBinding[i] = byte(i + 1)
	}

	tests := map[string]struct {
		channelBinding []byte

		wantBnd []byte
	}{
		"With channel binding": {
			channelBinding: channelBinding,
			wantBnd:        channelBinding,
		},
		"Without channel binding": {
			channelBinding: nil,
			wantBnd:        make([]byte, 16),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tokenBytes, initialSequence, err := buildKRB5APREQToken(cl, tkt, key, gssFlags, apOptions, tc.channelBinding)
			require.NoError(t, err)
			require.NotEmpty(t, tokenBytes)

			// The produced token must be a parseable KRB5 AP-REQ MechToken.
			var tok spnego.KRB5Token
			require.NoError(t, tok.Unmarshal(tokenBytes))
			require.True(t, tok.IsAPReq())

			// Decrypt the authenticator and inspect its GSS-API checksum.
			apReq := tok.APReq
			require.NoError(t, apReq.DecryptAuthenticator(key))
			assert.Equal(t, uint64(apReq.Authenticator.SeqNumber), initialSequence) //nolint:gosec // Authenticator sequence is non-negative.

			cksum := apReq.Authenticator.Cksum
			assert.Equal(t, chksumtype.GSSAPI, cksum.CksumType)
			require.GreaterOrEqual(t, len(cksum.Checksum), 24)

			// The Bnd field reflects the supplied channel binding.
			assert.Equal(t, tc.wantBnd, cksum.Checksum[4:20])

			// Mutual authentication is requested in the AP options.
			assert.True(t, types.IsFlagSet(&apReq.APOptions, 2))
		})
	}
}

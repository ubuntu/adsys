package certificate

import (
	"encoding/binary"
	"testing"

	"github.com/oiweiwei/gokrb5.fork/v9/crypto"
	"github.com/oiweiwei/gokrb5.fork/v9/gssapi"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/etypeID"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/keyusage"
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

	encType, err := crypto.GetEtype(key.KeyType)
	require.NoError(t, err)

	wt := gssapi.WrapToken{
		Flags:     0x01,                                   // sent by acceptor
		EC:        uint16(encType.GetHMACBitLength() / 8), //nolint:gosec // G115: HMAC byte length is a small constant within uint16
		RRC:       0,
		SndSeqNum: 0,
		Payload:   payload,
	}

	require.NoError(t, wt.SetCheckSum(key, keyUsage))

	b, err := wt.Marshal()
	require.NoError(t, err)
	return b
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

		"Error when server does not support auth-only layer": {
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

			g := &gssapiClient{sessionKey: key, established: true}
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

	g := &gssapiClient{sessionKey: key, established: true}
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

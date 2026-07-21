package certificate

import (
	"encoding/binary"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTemplateAutoEnrollRights(t *testing.T) {
	t.Parallel()

	machineSID := aclSID(5, 21, 1, 2, 3, 1000)
	groupSID := aclSID(5, 21, 1, 2, 3, 2000)
	machine := mustSIDString(t, machineSID)
	group := mustSIDString(t, groupSID)
	token := machineToken{machine: {}, group: {}, "S-1-5-11": {}}
	unrelatedRight := uuid.MustParse("11111111-2222-3333-4444-555555555555")

	tests := map[string]struct {
		descriptor []byte
		token      machineToken
		wantEnroll bool
		wantAuto   bool
		wantErr    bool
	}{
		"Enroll only": {
			descriptor: aclDescriptor(nil, aclObjectACE(accessAllowedObjectACE, enrollExtendedRight, machineSID)),
			token:      token, wantEnroll: true,
		},
		"AutoEnroll only": {
			descriptor: aclDescriptor(nil, aclObjectACE(accessAllowedObjectACE, autoEnrollExtendedRight, machineSID)),
			token:      token, wantAuto: true,
		},
		"Separate object allows": {
			descriptor: aclDescriptor(nil,
				aclObjectACE(accessAllowedObjectACE, enrollExtendedRight, machineSID),
				aclObjectACE(accessAllowedObjectACE, autoEnrollExtendedRight, machineSID)),
			token: token, wantEnroll: true, wantAuto: true,
		},
		"Simple CR allow satisfies both": {
			descriptor: aclDescriptor(nil, aclSimpleACE(accessAllowedACE, 0, rightDSControlAccess, machineSID)),
			token:      token, wantEnroll: true, wantAuto: true,
		},
		"Object ACE without ObjectType satisfies both": {
			descriptor: aclDescriptor(nil, aclObjectACEAll(accessAllowedObjectACE, 0, rightDSControlAccess, machineSID)),
			token:      token, wantEnroll: true, wantAuto: true,
		},
		"Explicit AutoEnroll deny before group allow": {
			descriptor: aclDescriptor(nil,
				aclObjectACE(accessDeniedObjectACE, autoEnrollExtendedRight, machineSID),
				aclSimpleACE(accessAllowedACE, 0, rightDSControlAccess, groupSID)),
			token: token, wantEnroll: true,
		},
		"Explicit allow before inherited deny wins": {
			descriptor: aclDescriptor(nil,
				aclSimpleACE(accessAllowedACE, 0, rightDSControlAccess, machineSID),
				aclSimpleACE(accessDeniedACE, 0x10, rightDSControlAccess, machineSID)),
			token: token, wantEnroll: true, wantAuto: true,
		},
		"Effective inherited allow": {
			descriptor: aclDescriptor(nil, aclSimpleACE(accessAllowedACE, 0x10, rightDSControlAccess, groupSID)),
			token:      token, wantEnroll: true, wantAuto: true,
		},
		"Inherit-only allow ignored": {
			descriptor: aclDescriptor(nil, aclSimpleACE(accessAllowedACE, aceInheritOnly, rightDSControlAccess, machineSID)),
			token:      token,
		},
		"Nested token group": {
			descriptor: aclDescriptor(nil, aclSimpleACE(accessAllowedACE, 0, rightDSControlAccess, groupSID)),
			token:      token, wantEnroll: true, wantAuto: true,
		},
		"Authenticated Users": {
			descriptor: aclDescriptor(nil, aclSimpleACE(accessAllowedACE, 0, rightDSControlAccess, aclSID(5, 11))),
			token:      token, wantEnroll: true, wantAuto: true,
		},
		"Everyone": {
			descriptor: aclDescriptor(nil, aclSimpleACE(accessAllowedACE, 0, rightDSControlAccess, aclSID(1, 0))),
			token: machineToken{
				"S-1-1-0": {},
			},
			wantEnroll: true, wantAuto: true,
		},
		"Network": {
			descriptor: aclDescriptor(nil, aclSimpleACE(accessAllowedACE, 0, rightDSControlAccess, aclSID(5, 2))),
			token: machineToken{
				"S-1-5-2": {},
			},
			wantEnroll: true, wantAuto: true,
		},
		"PRINCIPAL_SELF excluded": {
			descriptor: aclDescriptor(nil, aclSimpleACE(accessAllowedACE, 0, rightDSControlAccess, aclSID(5, 10))),
			token:      token,
		},
		"Owner alone grants nothing": {
			descriptor: aclDescriptor(machineSID),
			token:      token,
		},
		"GenericAll is not CR": {
			descriptor: aclDescriptor(nil, aclSimpleACE(accessAllowedACE, 0, 0x10000000, machineSID)),
			token:      token,
		},
		"Unrelated object GUID ignored": {
			descriptor: aclDescriptor(nil, aclObjectACE(accessAllowedObjectACE, unrelatedRight, machineSID)),
			token:      token,
		},
		"Empty DACL denies": {
			descriptor: aclDescriptor(nil),
			token:      token,
		},
		"NULL DACL grants": {
			descriptor: aclNullDACL(),
			token:      token, wantEnroll: true, wantAuto: true,
		},
		"Absent DACL grants": {
			descriptor: aclAbsentDACL(),
			token:      token, wantEnroll: true, wantAuto: true,
		},
		"Applicable callback fails closed": {
			descriptor: aclDescriptor(nil, aclCallbackACE(accessAllowedCallbackACE, rightDSControlAccess, machineSID)),
			token:      token, wantErr: true,
		},
		"Nonmatching callback is ignored": {
			descriptor: aclDescriptor(nil,
				aclCallbackACE(accessAllowedCallbackACE, rightDSControlAccess, aclSID(5, 21, 9, 9, 9, 9)),
				aclSimpleACE(accessAllowedACE, 0, rightDSControlAccess, groupSID)),
			token: token, wantEnroll: true, wantAuto: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			enroll, autoEnroll, err := templateAutoEnrollRights(tc.descriptor, tc.token)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantEnroll, enroll)
			assert.Equal(t, tc.wantAuto, autoEnroll)
		})
	}
}

func TestMachineTokenIncludesRequiredSIDs(t *testing.T) {
	t.Parallel()

	machine := aclSID(5, 21, 10, 20, 30, 1000)
	nested := aclSID(5, 21, 10, 20, 30, 2300)
	history := aclSID(5, 21, 90, 80, 70, 1000)
	token, err := newMachineToken(machine, [][]byte{nested, nested}, "515", [][]byte{history})
	require.NoError(t, err)

	for _, sid := range []string{
		"S-1-5-21-10-20-30-1000",
		"S-1-5-21-10-20-30-2300",
		"S-1-5-21-10-20-30-515",
		"S-1-5-21-90-80-70-1000",
		"S-1-1-0",
		"S-1-5-11",
		"S-1-5-2",
	} {
		assert.Contains(t, token, sid)
	}
	assert.NotContains(t, token, "S-1-5-10")

	domainComputers := aclDescriptor(nil, aclSimpleACE(accessAllowedACE, 0, rightDSControlAccess, aclSID(5, 21, 10, 20, 30, 515)))
	enroll, autoEnroll, err := templateAutoEnrollRights(domainComputers, token)
	require.NoError(t, err)
	assert.True(t, enroll)
	assert.True(t, autoEnroll)
}

func TestSecurityDescriptorMalformedNeverPanics(t *testing.T) {
	t.Parallel()

	valid := aclDescriptor(nil, aclSimpleACE(accessAllowedACE, 0, rightDSControlAccess, aclSID(5, 11)))
	vectors := [][]byte{
		nil,
		make([]byte, 19),
		append([]byte(nil), valid[:20]...),
		func() []byte {
			value := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint32(value[16:20], uint32(len(value)+1)) //nolint:gosec // The test descriptor is a fixed, tiny buffer.
			return value
		}(),
		func() []byte {
			value := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint16(value[22:24], 0xffff)
			return value
		}(),
		func() []byte {
			value := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint16(value[24:26], 2)
			return value
		}(),
		func() []byte {
			value := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint16(value[30:32], 0xffff)
			return value
		}(),
		func() []byte {
			value := append([]byte(nil), valid...)
			value[len(value)-len(aclSID(5, 11))+1] = 16
			return value
		}(),
	}

	token := machineToken{"S-1-5-11": {}}
	for i, vector := range vectors {
		assert.NotPanics(t, func() {
			_, _, err := templateAutoEnrollRights(vector, token)
			assert.Error(t, err, "vector %d", i)
		})
	}
}

func aclSID(authority uint64, subAuthorities ...uint32) []byte {
	value := make([]byte, 8+len(subAuthorities)*4)
	value[0] = 1
	value[1] = byte(len(subAuthorities)) //nolint:gosec // Test SIDs have far fewer than the protocol maximum of 15 sub-authorities.
	for i := 0; i < 6; i++ {
		value[7-i] = byte(authority)
		authority >>= 8
	}
	for i, subAuthority := range subAuthorities {
		binary.LittleEndian.PutUint32(value[8+i*4:], subAuthority)
	}
	return value
}

func mustSIDString(t *testing.T, raw []byte) string {
	t.Helper()
	sid, err := parseLDAPSID(raw)
	require.NoError(t, err)
	return sid.String()
}

func aclSimpleACE(aceType, flags byte, mask uint32, sid []byte) []byte {
	ace := make([]byte, 8+len(sid))
	ace[0] = aceType
	ace[1] = flags
	binary.LittleEndian.PutUint16(ace[2:4], uint16(len(ace))) //nolint:gosec // Test ACEs are bounded to a SID and fixed header.
	binary.LittleEndian.PutUint32(ace[4:8], mask)
	copy(ace[8:], sid)
	return ace
}

func aclObjectACE(aceType byte, objectType uuid.UUID, sid []byte) []byte {
	ace := make([]byte, 12+16+len(sid))
	ace[0] = aceType
	binary.LittleEndian.PutUint16(ace[2:4], uint16(len(ace))) //nolint:gosec // Test ACEs are bounded to a SID, GUID and fixed header.
	binary.LittleEndian.PutUint32(ace[4:8], rightDSControlAccess)
	binary.LittleEndian.PutUint32(ace[8:12], aceObjectTypePresent)
	copy(ace[12:28], uuidToMicrosoftBytes(objectType))
	copy(ace[28:], sid)
	return ace
}

func aclObjectACEAll(aceType, flags byte, mask uint32, sid []byte) []byte {
	ace := make([]byte, 12+len(sid))
	ace[0] = aceType
	ace[1] = flags
	binary.LittleEndian.PutUint16(ace[2:4], uint16(len(ace))) //nolint:gosec // Test ACEs are bounded to a SID and fixed header.
	binary.LittleEndian.PutUint32(ace[4:8], mask)
	copy(ace[12:], sid)
	return ace
}

func aclCallbackACE(aceType byte, mask uint32, sid []byte) []byte {
	ace := aclSimpleACE(aceType, 0, mask, sid)
	ace = append(ace, 1, 2, 3, 4)
	binary.LittleEndian.PutUint16(ace[2:4], uint16(len(ace))) //nolint:gosec // Test ACEs are bounded to a SID and fixed callback payload.
	return ace
}

func uuidToMicrosoftBytes(value uuid.UUID) []byte {
	return []byte{
		value[3], value[2], value[1], value[0],
		value[5], value[4],
		value[7], value[6],
		value[8], value[9], value[10], value[11], value[12], value[13], value[14], value[15],
	}
}

func aclDescriptor(owner []byte, aces ...[]byte) []byte {
	aclSize := 8
	for _, ace := range aces {
		aclSize += len(ace)
	}
	daclOffset := 20
	ownerOffset := 0
	if len(owner) > 0 {
		ownerOffset = daclOffset + aclSize
	}
	descriptor := make([]byte, 20+aclSize+len(owner))
	descriptor[0] = 1
	binary.LittleEndian.PutUint16(descriptor[2:4], securityDescriptorSelfRelative|securityDescriptorDACLPresent)
	if ownerOffset != 0 {
		binary.LittleEndian.PutUint32(descriptor[4:8], uint32(ownerOffset))
	}
	binary.LittleEndian.PutUint32(descriptor[16:20], uint32(daclOffset))
	descriptor[daclOffset] = 4
	binary.LittleEndian.PutUint16(descriptor[daclOffset+2:daclOffset+4], uint16(aclSize))
	binary.LittleEndian.PutUint16(descriptor[daclOffset+4:daclOffset+6], uint16(len(aces))) //nolint:gosec // Test descriptors contain only a handful of ACEs.
	position := daclOffset + 8
	for _, ace := range aces {
		copy(descriptor[position:], ace)
		position += len(ace)
	}
	copy(descriptor[ownerOffset:], owner)
	return descriptor
}

func aclNullDACL() []byte {
	descriptor := make([]byte, 20)
	descriptor[0] = 1
	binary.LittleEndian.PutUint16(descriptor[2:4], securityDescriptorSelfRelative|securityDescriptorDACLPresent)
	return descriptor
}

func aclAbsentDACL() []byte {
	descriptor := make([]byte, 20)
	descriptor[0] = 1
	binary.LittleEndian.PutUint16(descriptor[2:4], securityDescriptorSelfRelative)
	return descriptor
}

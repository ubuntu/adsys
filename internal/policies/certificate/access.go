package certificate

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

const (
	rightDSControlAccess uint32 = 0x00000100

	securityDescriptorDACLPresent  uint16 = 0x0004
	securityDescriptorSACLPresent  uint16 = 0x0010
	securityDescriptorSelfRelative uint16 = 0x8000

	accessAllowedACE               byte = 0x00
	accessDeniedACE                byte = 0x01
	systemAuditACE                 byte = 0x02
	systemAlarmACE                 byte = 0x03
	accessAllowedObjectACE         byte = 0x05
	accessDeniedObjectACE          byte = 0x06
	systemAuditObjectACE           byte = 0x07
	systemAlarmObjectACE           byte = 0x08
	accessAllowedCallbackACE       byte = 0x09
	accessDeniedCallbackACE        byte = 0x0a
	accessAllowedCallbackObjectACE byte = 0x0b
	accessDeniedCallbackObjectACE  byte = 0x0c
	systemAuditCallbackACE         byte = 0x0d
	systemAlarmCallbackACE         byte = 0x0e
	systemAuditCallbackObjectACE   byte = 0x0f
	systemAlarmCallbackObjectACE   byte = 0x10
	systemMandatoryLabelACE        byte = 0x11
	systemResourceAttributeACE     byte = 0x12
	systemScopedPolicyIDACE        byte = 0x13

	aceObjectTypePresent          uint32 = 0x00000001
	aceInheritedObjectTypePresent uint32 = 0x00000002
	aceInheritOnly                byte   = 0x08
)

var (
	enrollExtendedRight     = uuid.MustParse("0e10c968-78fb-11d2-90d4-00c04f79dc55")
	autoEnrollExtendedRight = uuid.MustParse("a05b8cc2-17bc-4802-a710-e7c15ab866a2")
)

type windowsSID struct {
	revision  byte
	authority uint64
	subAuth   []uint32
}

func (s windowsSID) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "S-%d-%d", s.revision, s.authority)
	for _, value := range s.subAuth {
		fmt.Fprintf(&b, "-%d", value)
	}
	return b.String()
}

func parseLDAPSID(raw []byte) (windowsSID, error) {
	sid, consumed, err := parseSIDAt(raw, 0, len(raw))
	if err != nil {
		return windowsSID{}, err
	}
	if consumed != len(raw) {
		return windowsSID{}, fmt.Errorf("SID has %d trailing bytes", len(raw)-consumed)
	}
	return sid, nil
}

func parseSIDAt(data []byte, offset, limit int) (windowsSID, int, error) {
	if offset < 0 || limit < offset || limit > len(data) || limit-offset < 8 {
		return windowsSID{}, 0, fmt.Errorf("SID offset %d is out of bounds", offset)
	}
	revision := data[offset]
	if revision != 1 {
		return windowsSID{}, 0, fmt.Errorf("unsupported SID revision %d", revision)
	}
	count := int(data[offset+1])
	if count > 15 {
		return windowsSID{}, 0, fmt.Errorf("SID has invalid sub-authority count %d", count)
	}
	size := 8 + count*4
	if size > limit-offset {
		return windowsSID{}, 0, fmt.Errorf("SID size %d exceeds enclosing structure", size)
	}
	var authority uint64
	for _, value := range data[offset+2 : offset+8] {
		authority = authority<<8 | uint64(value)
	}
	sid := windowsSID{revision: revision, authority: authority, subAuth: make([]uint32, count)}
	for i := range sid.subAuth {
		sid.subAuth[i] = binary.LittleEndian.Uint32(data[offset+8+i*4:])
	}
	return sid, size, nil
}

func primaryGroupSID(machine windowsSID, primaryGroupID uint32) (windowsSID, error) {
	if machine.authority != 5 || len(machine.subAuth) < 2 || machine.subAuth[0] != 21 {
		return windowsSID{}, fmt.Errorf("machine objectSid is not a domain account SID")
	}
	group := windowsSID{
		revision:  machine.revision,
		authority: machine.authority,
		subAuth:   append([]uint32(nil), machine.subAuth...),
	}
	group.subAuth[len(group.subAuth)-1] = primaryGroupID
	return group, nil
}

type machineToken map[string]struct{}

func newMachineToken(machineSID []byte, tokenGroups [][]byte, primaryGroupID string, sidHistory [][]byte) (machineToken, error) {
	machine, err := parseLDAPSID(machineSID)
	if err != nil {
		return nil, fmt.Errorf("invalid machine objectSid: %w", err)
	}
	primaryRID, err := strconv.ParseUint(strings.TrimSpace(primaryGroupID), 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid primaryGroupID %q: %w", primaryGroupID, err)
	}
	primary, err := primaryGroupSID(machine, uint32(primaryRID))
	if err != nil {
		return nil, err
	}

	token := machineToken{}
	add := func(sid windowsSID) {
		token[strings.ToUpper(sid.String())] = struct{}{}
	}
	add(machine)
	add(primary)
	for i, raw := range tokenGroups {
		sid, err := parseLDAPSID(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid tokenGroups SID %d: %w", i, err)
		}
		add(sid)
	}
	for i, raw := range sidHistory {
		sid, err := parseLDAPSID(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid sIDHistory SID %d: %w", i, err)
		}
		add(sid)
	}
	for _, builtIn := range []string{"S-1-1-0", "S-1-5-11", "S-1-5-2"} {
		token[builtIn] = struct{}{}
	}
	return token, nil
}

type parsedACE struct {
	aceType     byte
	flags       byte
	mask        uint32
	sid         string
	objectType  *uuid.UUID
	unsupported bool
}

type parsedSecurityDescriptor struct {
	daclPresent bool
	nullDACL    bool
	dacl        []parsedACE
}

func parseSecurityDescriptor(data []byte) (parsedSecurityDescriptor, error) {
	if len(data) < 20 {
		return parsedSecurityDescriptor{}, fmt.Errorf("security descriptor is shorter than its 20-byte header")
	}
	if data[0] != 1 {
		return parsedSecurityDescriptor{}, fmt.Errorf("unsupported security descriptor revision %d", data[0])
	}
	control := binary.LittleEndian.Uint16(data[2:4])
	if control&securityDescriptorSelfRelative == 0 {
		return parsedSecurityDescriptor{}, fmt.Errorf("security descriptor is not self-relative")
	}
	ownerOffset := binary.LittleEndian.Uint32(data[4:8])
	groupOffset := binary.LittleEndian.Uint32(data[8:12])
	saclOffset := binary.LittleEndian.Uint32(data[12:16])
	daclOffset := binary.LittleEndian.Uint32(data[16:20])

	for name, offset := range map[string]uint32{"owner": ownerOffset, "group": groupOffset} {
		if offset == 0 {
			continue
		}
		if offset < 20 || uint64(offset) >= uint64(len(data)) {
			return parsedSecurityDescriptor{}, fmt.Errorf("%s SID offset %d is out of bounds", name, offset)
		}
		if _, _, err := parseSIDAt(data, int(offset), len(data)); err != nil {
			return parsedSecurityDescriptor{}, fmt.Errorf("invalid %s SID: %w", name, err)
		}
	}

	if control&securityDescriptorSACLPresent == 0 {
		if saclOffset != 0 {
			return parsedSecurityDescriptor{}, fmt.Errorf("SACL offset is set while SACL_PRESENT is clear")
		}
	} else if saclOffset != 0 {
		if _, err := parseACL(data, int(saclOffset), false); err != nil {
			return parsedSecurityDescriptor{}, fmt.Errorf("invalid SACL: %w", err)
		}
	}

	if control&securityDescriptorDACLPresent == 0 {
		if daclOffset != 0 {
			return parsedSecurityDescriptor{}, fmt.Errorf("DACL offset is set while DACL_PRESENT is clear")
		}
		return parsedSecurityDescriptor{daclPresent: false}, nil
	}
	if daclOffset == 0 {
		return parsedSecurityDescriptor{daclPresent: true, nullDACL: true}, nil
	}
	aces, err := parseACL(data, int(daclOffset), true)
	if err != nil {
		return parsedSecurityDescriptor{}, fmt.Errorf("invalid DACL: %w", err)
	}
	return parsedSecurityDescriptor{daclPresent: true, dacl: aces}, nil
}

func parseACL(data []byte, offset int, parseAccess bool) ([]parsedACE, error) {
	if offset < 20 || offset > len(data)-8 {
		return nil, fmt.Errorf("ACL offset %d is out of bounds", offset)
	}
	revision := data[offset]
	if revision != 2 && revision != 4 {
		return nil, fmt.Errorf("unsupported ACL revision %d", revision)
	}
	size := int(binary.LittleEndian.Uint16(data[offset+2 : offset+4]))
	if size < 8 || size > len(data)-offset {
		return nil, fmt.Errorf("ACL size %d is out of bounds", size)
	}
	aceCount := int(binary.LittleEndian.Uint16(data[offset+4 : offset+6]))
	end := offset + size
	position := offset + 8
	aces := make([]parsedACE, 0, aceCount)
	for i := 0; i < aceCount; i++ {
		if position > end-4 {
			return nil, fmt.Errorf("ACE count %d exceeds ACL size", aceCount)
		}
		aceSize := int(binary.LittleEndian.Uint16(data[position+2 : position+4]))
		if aceSize < 4 || aceSize > end-position {
			return nil, fmt.Errorf("ACE %d size %d is out of bounds", i, aceSize)
		}
		ace, err := parseAccessACE(data[position : position+aceSize])
		if err != nil {
			return nil, fmt.Errorf("ACE %d: %w", i, err)
		}
		if parseAccess {
			aces = append(aces, ace)
		}
		position += aceSize
	}
	if position != end {
		return nil, fmt.Errorf("ACL size leaves %d unaccounted bytes after %d ACEs", end-position, aceCount)
	}
	return aces, nil
}

func parseAccessACE(data []byte) (parsedACE, error) {
	ace := parsedACE{aceType: data[0], flags: data[1]}
	switch ace.aceType {
	case accessAllowedACE, accessDeniedACE:
		return parseSimpleACE(data, false, false)

	case systemAuditACE, systemAlarmACE, systemMandatoryLabelACE, systemScopedPolicyIDACE:
		return parseSimpleACE(data, false, true)

	case accessAllowedObjectACE, accessDeniedObjectACE:
		return parseObjectACE(data, false)

	case systemAuditObjectACE, systemAlarmObjectACE:
		ace, err := parseObjectACE(data, false)
		ace.unsupported = true
		return ace, err

	case accessAllowedCallbackACE, accessDeniedCallbackACE, systemAuditCallbackACE, systemAlarmCallbackACE, systemResourceAttributeACE:
		return parseSimpleACE(data, true, true)

	case accessAllowedCallbackObjectACE, accessDeniedCallbackObjectACE:
		return parseObjectACE(data, true)

	case systemAuditCallbackObjectACE, systemAlarmCallbackObjectACE:
		ace, err := parseObjectACE(data, true)
		ace.unsupported = true
		return ace, err

	default:
		ace.unsupported = true
		return ace, nil
	}
}

func parseSimpleACE(data []byte, trailingData, unsupported bool) (parsedACE, error) {
	if len(data) < 16 {
		return parsedACE{}, fmt.Errorf("simple access ACE is too short")
	}
	ace := parsedACE{
		aceType:     data[0],
		flags:       data[1],
		mask:        binary.LittleEndian.Uint32(data[4:8]),
		unsupported: unsupported,
	}
	sid, consumed, err := parseSIDAt(data, 8, len(data))
	if err != nil {
		return parsedACE{}, err
	}
	if !trailingData && 8+consumed != len(data) {
		return parsedACE{}, fmt.Errorf("simple access ACE has trailing data")
	}
	ace.sid = strings.ToUpper(sid.String())
	return ace, nil
}

func parseObjectACE(data []byte, callback bool) (parsedACE, error) {
	if len(data) < 20 {
		return parsedACE{}, fmt.Errorf("object ACE is too short")
	}
	ace := parsedACE{
		aceType:     data[0],
		flags:       data[1],
		mask:        binary.LittleEndian.Uint32(data[4:8]),
		unsupported: callback,
	}
	objectFlags := binary.LittleEndian.Uint32(data[8:12])
	if objectFlags & ^(aceObjectTypePresent|aceInheritedObjectTypePresent) != 0 {
		return parsedACE{}, fmt.Errorf("object ACE has unsupported flags 0x%x", objectFlags)
	}
	position := 12
	if objectFlags&aceObjectTypePresent != 0 {
		if position > len(data)-16 {
			return parsedACE{}, fmt.Errorf("object ACE ObjectType is truncated")
		}
		value, err := uuidFromMicrosoftBytes(data[position : position+16])
		if err != nil {
			return parsedACE{}, err
		}
		ace.objectType = &value
		position += 16
	}
	if objectFlags&aceInheritedObjectTypePresent != 0 {
		if position > len(data)-16 {
			return parsedACE{}, fmt.Errorf("object ACE InheritedObjectType is truncated")
		}
		position += 16
	}
	sid, consumed, err := parseSIDAt(data, position, len(data))
	if err != nil {
		return parsedACE{}, err
	}
	if !callback && position+consumed != len(data) {
		return parsedACE{}, fmt.Errorf("object ACE has trailing data")
	}
	ace.sid = strings.ToUpper(sid.String())
	return ace, nil
}

func uuidFromMicrosoftBytes(raw []byte) (uuid.UUID, error) {
	if len(raw) != 16 {
		return uuid.Nil, fmt.Errorf("GUID has length %d, want 16", len(raw))
	}
	network := []byte{
		raw[3], raw[2], raw[1], raw[0],
		raw[5], raw[4],
		raw[7], raw[6],
		raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
	}
	return uuid.FromBytes(network)
}

func templateAutoEnrollRights(descriptor []byte, token machineToken) (enroll, autoEnroll bool, err error) {
	sd, err := parseSecurityDescriptor(descriptor)
	if err != nil {
		return false, false, err
	}
	if !sd.daclPresent || sd.nullDACL {
		return true, true, nil
	}
	enroll, err = checkControlAccess(sd.dacl, token, enrollExtendedRight)
	if err != nil {
		return false, false, fmt.Errorf("checking Enroll right: %w", err)
	}
	autoEnroll, err = checkControlAccess(sd.dacl, token, autoEnrollExtendedRight)
	if err != nil {
		return false, false, fmt.Errorf("checking AutoEnroll right: %w", err)
	}
	return enroll, autoEnroll, nil
}

func checkControlAccess(aces []parsedACE, token machineToken, right uuid.UUID) (bool, error) {
	for i, ace := range aces {
		if ace.flags&aceInheritOnly != 0 {
			continue
		}
		if ace.unsupported && ace.sid == "" {
			return false, fmt.Errorf("unsupported effective ACE type 0x%02x at index %d", ace.aceType, i)
		}
		if _, matches := token[ace.sid]; !matches {
			continue
		}
		if ace.mask&rightDSControlAccess == 0 {
			continue
		}
		if ace.objectType != nil && *ace.objectType != right {
			continue
		}
		if ace.unsupported {
			return false, fmt.Errorf("unsupported applicable ACE type 0x%02x at index %d", ace.aceType, i)
		}
		switch ace.aceType {
		case accessAllowedACE, accessAllowedObjectACE:
			return true, nil
		case accessDeniedACE, accessDeniedObjectACE:
			return false, nil
		default:
			return false, fmt.Errorf("unsupported applicable ACE type 0x%02x at index %d", ace.aceType, i)
		}
	}
	return false, nil
}

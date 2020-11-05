package registry

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf16"
)

type dataType uint8

/* From winNT.h */
const (
	regNone              dataType = 0  /* no type */
	regSz                dataType = 1  /* string type (ASCII) */
	regExpandSz          dataType = 2  /* string, includes %ENVVAR% (expanded by caller) (ASCII) */
	regBinary            dataType = 3  /* binary format, callerspecific */
	regDwordLittleEndian dataType = 4  /* DWORD in little endian format */
	regDword             dataType = 4  /* DWORD in little endian format */
	regDwordBigEndian    dataType = 5  /* DWORD in big endian format  */
	regLink              dataType = 6  /* symbolic link (UNICODE) */
	regMultiSz           dataType = 7  /* multiple strings, delimited by \0, terminated by \0\0 (ASCII) */
	regQword             dataType = 11 /* QWORD in little endian format */
	regQwordLittleEndian dataType = 11 /* QWORD in little endian format */
)

// PolicyEntry represents an entry of a policy file
type PolicyEntry struct {
	Key   string // Absolute path to setting. Ex: Sofware/Ubuntu/User/dconf/wallpaper
	Value string
}

// DecodePolicy parses a policy stream in registry file format and returns a slice of entries.
func DecodePolicy(r io.Reader) (entries []PolicyEntry, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("couldn't decode policy: %v", err)
		}
	}()

	ent, err := readPolicy(r)
	if err != nil {
		return nil, err
	}

	// translate to strings based on type
	for _, e := range ent {
		var res string
		switch t := e.dType; t {
		case regSz:
			res, err = decodeUtf16(e.data)
			if err != nil {
				return nil, err
			}
		case regDword:
			var resInt uint32
			buf := bytes.NewReader(e.data)
			if err := binary.Read(buf, binary.LittleEndian, &resInt); err != nil {
				return nil, err
			}
			res = strconv.FormatUint(uint64(resInt), 10)
		default:
			return nil, fmt.Errorf("%d type is not supported set for key %s", t, e.key)
		}
		e.path = strings.ReplaceAll(e.path, `\`, `/`)
		entries = append(entries, PolicyEntry{
			Key:      filepath.Join(e.path, e.key),
			Value:    res,
		})
	}

	return entries, nil
}

type policyRawEntry struct {
	path  string
	key   string
	dType dataType
	data  []byte
}

type policyFileHeader struct {
	Signature int32
	Version   int32
}

func readPolicy(r io.Reader) (entries []policyRawEntry, err error) {
	validPolicyFileHeader := policyFileHeader{
		Signature: 0x67655250,
		Version:   1,
	}

	header := policyFileHeader{}
	err = binary.Read(r, binary.LittleEndian, &header)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("invalid policy file (empty)")
		}
		return nil, err
	}

	if header != validPolicyFileHeader {
		return nil, fmt.Errorf("invalid policy file header: %x%x", header.Signature, header.Version)
	}

	sectionStart := []byte{'[', 0}     // [ in UTF-16 (little endian)
	sectionEnd := []byte{0, 0, ']', 0} // \0] in UTF-16 (little endian)
	dataOffset := len(sectionStart)
	sectionEndWidth := len(sectionEnd)

	// [key;value;type;size;data]
	scanEntries := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		// Skip leading sectionStart.
		start := 0
		for ; start+dataOffset-1 < len(data); start++ {
			if bytes.Compare(data[start:start+dataOffset], sectionStart) == 0 {
				break
			}
		}

		// Scan until sectionEnd, marking end of word.
		for i := start + dataOffset; i+sectionEndWidth-1 < len(data); i++ {
			if bytes.Compare(data[i:i+sectionEndWidth], sectionEnd) == 0 {
				return i + sectionEndWidth, data[start+dataOffset : i+2], nil
			}
		}

		// If we're at EOF, we have a final, non-empty, non-terminated word. Return an error.
		if atEOF && len(data) > start {
			return 0, nil, fmt.Errorf("item does not end with ']'")
		}
		// Request more data.
		return start, nil, nil
	}

	s := bufio.NewScanner(r)
	s.Split(scanEntries)
	delimiter := []byte{0, 0, ';', 0} // \0; in little endian (UTF-16)
	for s.Scan() {
		elems := bytes.SplitN(s.Bytes(), delimiter, 5)
		if len(elems) < 5 {
			return nil, fmt.Errorf("item should contains at least 5 ';' separator: %s", s.Text())
		}

		keyPrefix, err := decodeUtf16(elems[0])
		if err != nil {
			return nil, err
		}
		keySuffix, err := decodeUtf16(elems[1])
		if err != nil {
			return nil, err
		}

		if keyPrefix == "" {
			return nil, fmt.Errorf("empty key in %s", s.Text())
		}
		if keySuffix == "" {
			return nil, fmt.Errorf("empty value in %s", s.Text())
		}

		entries = append(entries, policyRawEntry{
			path:  keyPrefix,
			key:   keySuffix,
			dType: dataType(elems[2][0]),
			data:  elems[4], // TODO: if admx support binary data, then also return size
		})
	}

	if err := s.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

func decodeUtf16(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", fmt.Errorf("%x is not a valid UTF-16 string", b)
	}
	ints := make([]uint16, len(b)/2)
	if err := binary.Read(bytes.NewReader(b), binary.LittleEndian, &ints); err != nil {
		return "", err
	}
	// remove trailing \0
	if len(ints) >= 1 && ints[len(ints)-1] == 0 {
		ints = ints[:len(ints)-1]
	}
	return string(utf16.Decode(ints)), nil
}

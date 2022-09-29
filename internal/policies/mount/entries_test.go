package mount

import (
	"fmt"

	"github.com/ubuntu/adsys/internal/policies/entry"
)

// EntriesForTests is a map with multiple []entries combinations to be used in tests.
var EntriesForTests = map[string][]entry.Entry{
	"one entry with one value": {{Value: "protocol://domain.com/mountpath"}},

	"multiple entries with one value": {
		{Value: "protocol://domain.com/mountpath2"},
		{Value: "smb://otherdomain.com/mount/path"},
		{Value: "nfs://yetanotherdomain.com/mount-path/mount/path"},
	},

	"one entry with multiple values": {{Value: "protocol://domain.com/mountpath2\nsmb://otherdomain.com/mount/path\nnfs://yetanotherdomain.com/mount-path/mount/path"}},

	"multiple entries with multiple values": {
		{Value: "protocol://domain.com/mountpath\nsmb://dmn.com/mount\nnfs://d.com/mnt/pth"},
		{Value: "protocol://otherdomain.com/mount/path\nsmb://otherdomain.com/mount-path\nnfs://otherdomain.com/mount-path"},
		{Value: "nfs://yetanotherdomain.com/mount-path/mount/path\nsmb://yetanotherdomain.com/mount-path\nprotocol://yetanotherdomain.com/mount"},
	},

	"one entry with repeatead values": {{Value: "rpt://repeated.com/repeatedmount\nsmb://single.com/mnt\nrpt://repeated.com/repeatedmount\nnfs://anotherone.com/mnt\n"}},

	"multiple entries with the same value": {
		{Value: "rpt://repeated.com/repeatedmount"},
		{Value: "nfs://not-repeated.com/mount"},
		{Value: "rpt://repeated.com/repeatedmount"},
	},

	"multiple entries with repeated values": {
		{Value: "rpt://repeated.com/repeatedmount\nnfs://not-repeated/mount\nsmb://something.com/some-mount"},
		{Value: "nfs://otherdomain.com/other-mount\nrpt://repeated.com/repeatedmount\nnfs://domain.com/mountpath"},
		{Value: "smb://testing.com/test/mount\nnfs://chaos.com/none/mount\nrpt://repeated.com/repeatedmount"},
	},

	"errored entries": {
		{Value: "protocol://domain.com/mountpath"},
		{Value: "smb://errored.com/error/ed", Err: fmt.Errorf("some error")},
		{Value: "nfs://yetanotherdomain.com/mount-path/mount/path"},
	},

	"one entry with no value": {
		{},
	},

	"multiple entries with no value": {
		{},
		{},
		{},
	},

	"no entries": {},
}

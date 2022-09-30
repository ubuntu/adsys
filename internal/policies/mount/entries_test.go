package mount

import (
	"fmt"

	"github.com/ubuntu/adsys/internal/policies/entry"
)

// EntriesForTests is a map with multiple []entries combinations to be used in tests.
var EntriesForTests = map[string][]entry.Entry{
	"one entry with one value": {
		{Value: "protocol://domain.com/mountpath"},
	},

	"multiple entries with one value": {
		{Value: "protocol://domain.com/mountpath2"},
		{Value: "smb://otherdomain.com/mount/path"},
		{Value: "nfs://yetanotherdomain.com/mount-path/mount/path"},
	},

	"one entry with multiple values": {
		{Value: `
protocol://domain.com/mountpath2
smb://otherdomain.com/mount/path
nfs://yetanotherdomain.com/mount-path/mount/path`,
		},
	},

	"multiple entries with multiple values": {
		{Value: `
protocol://domain.com/mountpath
smb://dmn.com/mount
nfs://d.com/mnt/pth`,
		},
		{Value: `
protocol://otherdomain.com/mount/path
smb://otherdomain.com/mount-path
nfs://otherdomain.com/mount-path`,
		},
		{Value: `
nfs://yetanotherdomain.com/mount-path/mount/path
smb://yetanotherdomain.com/mount-path
protocol://yetanotherdomain.com/mount`,
		},
	},

	"one entry with repeatead values": {
		{Value: `
rpt://repeated.com/repeatedmount
smb://single.com/mnt
rpt://repeated.com/repeatedmount
nfs://anotherone.com/mnt
		`},
	},

	"multiple entries with the same value": {
		{Value: "rpt://repeated.com/repeatedmount"},
		{Value: "nfs://not-repeated.com/mount"},
		{Value: "rpt://repeated.com/repeatedmount"},
	},

	"multiple entries with repeated values": {
		{Value: `
rpt://repeated.com/repeatedmount
nfs://not-repeated/mount
smb://something.com/some-mount
		`},
		{Value: `
nfs://otherdomain.com/other-mount
rpt://repeated.com/repeatedmount
nfs://domain.com/mountpath
		`},
		{Value: `
smb://testing.com/test/mount
nfs://chaos.com/none/mount
rpt://repeated.com/repeatedmount
		`},
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

	"entry with multiple linebreaks": {
		{Value: `
protocol://domain.com/mounpath





smb://otherdomain.com/mount/path
		`},
	},

	"entry with linebreaks and spaces": {
		{Value: `
			protocol://domain.com/mountpath
		  
smb://otherdomain.com/mount/path
		      
	nfs://yetanotherdomain.com/path/mount

		`},
	},

	"entry with anonymous tags": {
		{Value: `
[anonymous]smb://shady.com/shady/mount
[anonymous]nfs://stealthydomain.com/mount/stealthy
protocol://domain.com/mountpath
		`},
	},
}

package mount

import (
	"fmt"

	"github.com/ubuntu/adsys/internal/policies/entry"
)

// EntriesForTests is a map with multiple entries combinations to be used in tests.
var EntriesForTests = map[string]entry.Entry{
	"entry with one value": {Value: "protocol://domain.com/mountpath"},

	"entry with one good value and one bad": {Value: `
protocol://domain.com/mountpath
protocol//bad.com/badpath
`,
	},

	"entry with one anonymous value": {Value: "[anonymous]protocol://anon.com/anon/mount"},

	"entry with multiple values": {Value: `
protocol://domain.com/mountpath2
smb://otherdomain.com/mount/path
nfs://yetanotherdomain.com/mount-path/mount/path
`,
	},

	"entry with multiple slightly different values": {Value: `
smb://otherdomain.com/mount/path
smb://otherdomain.com/mount-path
nfs://yetanotherdomain.com/mount-path/mount/path
nfs://yetanotherdomain.com/mount/path/mount-path
`,
	},

	"entry with different values": {Value: `
protocol://otherdomain.com/mountpath2
smb://otherdomain.com/mount/path
nfs://domain.com/mount-path
`,
	},

	"entry with repeatead values": {Value: `
rpt://repeated.com/repeatedmount
smb://single.com/mnt
rpt://repeated.com/repeatedmount
nfs://anotherone.com/mnt
`,
	},

	"entry with no value": {},

	"entry with multiple linebreaks": {Value: `
protocol://domain.com/mounpath





smb://otherdomain.com/mount/path
`,
	},

	"entry with spaces": {Value: `
			protocol://domain.com/mountpath
smb://otherdomain.com/mount/path
	nfs://yetanotherdomain.com/path/mount
`,
	},

	"entry with kerberos auth tags": {Value: `
[krb5]smb://authenticated.com/authenticated/mount
[krb5]nfs://krb_domain.com/mount/krb_path
protocol://domain.com/mountpath
`,
	},

	"errored entry": {Value: "protocol://domain.com/mountpath", Err: fmt.Errorf("some error")},

	"entry with bad value": {Value: "protocol//domain.com/mountpath"},

	"entry with correct and bad values": {Value: `
	bad//format.com/value
	correct://format.com/value
	bad\\format.com\othere\value
`,
	},
}

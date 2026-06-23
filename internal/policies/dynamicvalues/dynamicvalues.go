// Package dynamicvalues expands ${VAR} placeholders in policy entry values at
// apply time.
//
// Administrators can template GPO values against the principal a policy is being
// applied to, e.g. a per-user network share "smb://server/homes/${USER}". The
// supported variables are an explicit, fixed allow-list (see the package
// constants); anything else is rejected so that typos surface loudly instead of
// silently applying a broken value.
//
// Only the ${VAR} syntax (braces required) is recognized. A lone "$" or a bare
// "$VAR" without braces is passed through literally. The Windows-style %VAR%
// form is intentionally not supported as it collides with URL percent-encoding
// (e.g. %20) used in mount values.
package dynamicvalues

import (
	"errors"
	"strings"

	"github.com/leonelquinteros/gotext"
)

// Variable names recognized by the engine. Lookup is case-insensitive.
const (
	// VarUser is the login name without the domain (sAMAccountName), e.g. "bob".
	VarUser = "USER"
	// VarFQDNUser is the fully-qualified user, e.g. "bob@dom.com".
	VarFQDNUser = "FQDN_USER"
	// VarHostname is the short machine hostname, e.g. "workstation01".
	VarHostname = "HOSTNAME"
	// VarFQDNHostname is the fully-qualified machine name, e.g. "workstation01.dom.com".
	VarFQDNHostname = "FQDN_HOSTNAME"
	// VarDomain is the AD DNS domain, e.g. "dom.com".
	VarDomain = "DOMAIN"
)

// userOnlyVars are variables that only make sense in a user policy. Using them
// in a machine policy is an error.
var userOnlyVars = map[string]bool{
	VarUser:     true,
	VarFQDNUser: true,
}

// Context carries the resolved values for one ApplyPolicies invocation.
type Context struct {
	User         string // "" for computer policies
	FQDNUser     string // "" for computer policies
	Hostname     string
	FQDNHostname string // always built from the machine domain, even in user policies
	Domain       string // user domain for users, machine domain for computers
	IsComputer   bool
}

// Expand replaces ${VAR} placeholders in value according to ctx.
//
// It returns an error if value contains an unknown variable, a malformed
// placeholder (unterminated or empty), or a user-only variable while
// ctx.IsComputer is true. A value without any "${" marker is returned unchanged.
func Expand(value string, ctx Context) (string, error) {
	// Fast path: nothing to expand.
	if !strings.Contains(value, "${") {
		return value, nil
	}

	values := map[string]string{
		VarUser:         ctx.User,
		VarFQDNUser:     ctx.FQDNUser,
		VarHostname:     ctx.Hostname,
		VarFQDNHostname: ctx.FQDNHostname,
		VarDomain:       ctx.Domain,
	}

	var b strings.Builder
	b.Grow(len(value))

	for i := 0; i < len(value); {
		// Copy everything that is not the start of a "${" placeholder verbatim.
		if value[i] != '$' || i+1 >= len(value) || value[i+1] != '{' {
			b.WriteByte(value[i])
			i++
			continue
		}

		// We are at a "${": find the matching closing brace.
		rel := strings.IndexByte(value[i+2:], '}')
		if rel == -1 {
			return "", errors.New(gotext.Get("unterminated dynamic value placeholder in %q", value))
		}
		name := value[i+2 : i+2+rel]
		token := "${" + name + "}"

		if name == "" {
			return "", errors.New(gotext.Get("empty dynamic value placeholder in %q", value))
		}

		canonical := strings.ToUpper(name)
		resolved, ok := values[canonical]
		if !ok {
			return "", errors.New(gotext.Get("unknown dynamic value %q in %q", token, value))
		}
		if ctx.IsComputer && userOnlyVars[canonical] {
			return "", errors.New(gotext.Get("dynamic value %q is only available in user policies but was used in a machine policy in %q", token, value))
		}

		b.WriteString(resolved)
		i += 2 + rel + 1
	}

	return b.String(), nil
}

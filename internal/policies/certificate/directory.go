package certificate

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

type directoryNamingContexts struct {
	configuration string
	defaultDomain string
}

type machineDirectoryIdentity struct {
	shortName      string
	samAccountName string
	dnsName        string
}

func normalizeDomainIdentity(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

func normalizeMachineIdentity(identity string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(identity), "."))
}

func deriveMachineDirectoryIdentity(objectName, domain, localHostname string) (machineDirectoryIdentity, error) {
	name := strings.TrimSpace(objectName)
	if name == "" {
		name = strings.TrimSpace(localHostname)
	}
	if strings.HasPrefix(strings.ToLower(name), "host/") {
		name = name[len("host/"):]
	}
	if at := strings.IndexByte(name, '@'); at >= 0 {
		name = name[:at]
	}
	name = strings.TrimSuffix(strings.TrimSuffix(name, "."), "$")
	name = normalizeMachineIdentity(name)
	domain = normalizeDomainIdentity(domain)
	if name == "" || domain == "" {
		return machineDirectoryIdentity{}, fmt.Errorf("machine name and domain must be known")
	}

	shortName := name
	if dot := strings.IndexByte(shortName, '.'); dot >= 0 {
		shortName = shortName[:dot]
	}
	if shortName == "" || strings.ContainsAny(shortName, `/\`) {
		return machineDirectoryIdentity{}, fmt.Errorf("invalid machine name %q", name)
	}
	dnsName := name
	if !strings.ContainsRune(dnsName, '.') {
		dnsName += "." + domain
	}
	return machineDirectoryIdentity{
		shortName:      shortName,
		samAccountName: shortName + "$",
		dnsName:        dnsName,
	}, nil
}

func enrollmentMachineIdentity(objectName, domain string) (machineDirectoryIdentity, error) {
	localHostname := ""
	if objectName == "" {
		var err error
		localHostname, err = os.Hostname()
		if err != nil {
			return machineDirectoryIdentity{}, fmt.Errorf("determining local hostname: %w", err)
		}
	}
	return deriveMachineDirectoryIdentity(objectName, domain, localHostname)
}

func fetchNamingContextsContext(ctx context.Context, conn LDAPClient) (directoryNamingContexts, error) {
	searchReq := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"configurationNamingContext", "defaultNamingContext"},
		nil,
	)
	result, err := ldapSearchContext(ctx, conn, searchReq)
	if err != nil {
		return directoryNamingContexts{}, fmt.Errorf("failed to query root DSE: %w", err)
	}
	if len(result.Entries) != 1 {
		return directoryNamingContexts{}, fmt.Errorf("root DSE returned %d entries, want exactly one", len(result.Entries))
	}
	contexts := directoryNamingContexts{
		configuration: result.Entries[0].GetAttributeValue("configurationNamingContext"),
		defaultDomain: result.Entries[0].GetAttributeValue("defaultNamingContext"),
	}
	if contexts.configuration == "" {
		return directoryNamingContexts{}, fmt.Errorf("configurationNamingContext not found in root DSE")
	}
	if contexts.defaultDomain == "" {
		return directoryNamingContexts{}, fmt.Errorf("defaultNamingContext not found in root DSE")
	}
	return contexts, nil
}

func fetchMachineTokenContext(ctx context.Context, conn LDAPClient, defaultDN string, identity machineDirectoryIdentity) (machineToken, error) {
	filter := fmt.Sprintf(
		"(&(objectClass=computer)(|(sAMAccountName=%s)(dNSHostName=%s)))",
		ldap.EscapeFilter(identity.samAccountName),
		ldap.EscapeFilter(identity.dnsName),
	)
	searchReq := ldap.NewSearchRequest(
		defaultDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		2, 0, false,
		filter,
		[]string{"sAMAccountName", "dNSHostName", "objectSid", "tokenGroups", "primaryGroupID", "sIDHistory"},
		nil,
	)
	result, err := ldapSearchContext(ctx, conn, searchReq)
	if err != nil {
		return nil, fmt.Errorf("LDAP search for current computer object failed: %w", err)
	}
	if len(result.Entries) != 1 {
		return nil, fmt.Errorf("current computer identity resolved to %d directory objects, want exactly one", len(result.Entries))
	}
	entry := result.Entries[0]
	samMatches := strings.EqualFold(entry.GetAttributeValue("sAMAccountName"), identity.samAccountName)
	dnsMatches := normalizeMachineIdentity(entry.GetAttributeValue("dNSHostName")) == identity.dnsName
	if !samMatches && !dnsMatches {
		return nil, fmt.Errorf("resolved computer object does not match machine identity %q", identity.dnsName)
	}

	objectSIDValues := entry.GetRawAttributeValues("objectSid")
	if len(objectSIDValues) != 1 || len(objectSIDValues[0]) == 0 {
		return nil, fmt.Errorf("computer object must have exactly one binary objectSid")
	}
	primaryGroupIDs := entry.GetAttributeValues("primaryGroupID")
	if len(primaryGroupIDs) != 1 {
		return nil, fmt.Errorf("computer object must have exactly one primaryGroupID")
	}
	return newMachineToken(
		objectSIDValues[0],
		entry.GetRawAttributeValues("tokenGroups"),
		primaryGroupIDs[0],
		entry.GetRawAttributeValues("sIDHistory"),
	)
}

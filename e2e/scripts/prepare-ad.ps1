# Description: Prepare the domain controller for E2E testing
#
# The script takes a single argument, the hostname of the Linux client to be tested.
# It creates the following OU structure, together with GPOs and users:
#  OU=e2e,DC=warthogs,DC=biz
#  └── $hostname
#      ├── users <──────── linked to $hostname-users-gpo
#      │   ├── admins <─── linked to $hostname-admins-gpo
#      │   │   └── 👤 $hostname-adm
#      │   └── 👤 $hostname-usr
#      ├── computers <──── linked to $hostname-computers-gpo
#      │   └── 💻 $hostname
#      └── out-of-tree
#
# The script assumes the GPO data is stored in the same directory - this is the
# case when ran via the ./cmd/run_tests/02_provision_ad command.
#
# The script is not idempotent, it will fail if any resources already exist.
param (
    [string]$hostname
)

# Uncomment to dry run the script
# $WhatIfPreference = $true

# Stop on first error
$ErrorActionPreference = "Stop"

# Create parent OU
$parentOUPath = "OU=e2e,DC=warthogs,DC=biz"
New-ADOrganizationalUnit -Name $hostname -Path $parentOUPath -ProtectedFromAccidentalDeletion $false

$organizationalUnits = @{
    'users' = "OU=${hostname},${parentOUPath}"
    'computers' = "OU=${hostname},${parentOUPath}"
    'admins' = "OU=users,OU=${hostname},${parentOUPath}"
    'out-of-tree' = "OU=${hostname},${parentOUPath}"
}

# Create child OUs
foreach ($ou in $organizationalUnits.GetEnumerator()) {
    New-ADOrganizationalUnit -Name $ou.Key -Path $ou.Value -ProtectedFromAccidentalDeletion $false
}

# Prepare GPOs
# POL files are stored in the same directory as this script
$gpoPaths = 'users', 'users-admins', 'computers'
foreach ($gpoPath in $gpoPaths) {
    $targetOU = $gpoPath.split('-')[-1]
    $targetOUPath = $organizationalUnits[$targetOU]

    $gpoName = "e2e-$hostname-$targetOU-gpo"
    $gpo = New-GPO -Name $gpoName -Comment $hostname

    # Copy path to SYSVOL
    $sourceDir = Join-Path -Path $PSScriptRoot -ChildPath $gpoPath
    $destinationDir = "\\warthogs.biz\SYSVOL\warthogs.biz\Policies\{$($gpo.Id)}"
    Copy-Item -Path "$sourceDir\*" -Destination $destinationDir -Recurse -Force

    # Link GPO to OU
    New-GPLink -Name $gpoName -Target "OU=${targetOU},${targetOUPath}" -LinkEnabled Yes
}

# Create users
$password = ConvertTo-SecureString -String 'supersecretpassword' -AsPlainText -Force
New-ADUser -Name "${hostname}-usr" -Path "OU=users,$($organizationalUnits['users'])" -AccountPassword $password -Enabled $true
New-ADUser -Name "${hostname}-adm" -Path "OU=admins,$($organizationalUnits['admins'])" -AccountPassword $password -Enabled $true

# Move machine to computers OU and ensure its dNSHostName matches the
# expected FQDN. The native LDAP enrollment backend verifies that the
# certificate issued by AD CS contains the machine's FQDN in its DNS SAN.
# The v1 Machine template builds the SAN from the computer object's
# dNSHostName attribute, which realm join may leave unset or set to the
# short hostname only.
$identity = Get-ADComputer -Identity $hostname
Move-ADObject -Identity $identity -TargetPath "OU=computers,$($organizationalUnits['computers'])"
Set-ADComputer -Identity $hostname -DNSHostName "$hostname.warthogs.biz"

# Grant the AutoEnroll extended right on the Machine certificate template to
# Domain Computers. The native LDAP enrollment backend checks the template's
# security descriptor for the AutoEnroll right (GUID a05b8cc2-17bc-4802-a710-
# e7c15ab866a2) before enrolling. The default AD CS Machine template grants
# Enroll but not AutoEnroll to Domain Computers, which the legacy CEPCES
# backend never checked. This is idempotent: if the right is already granted
# the existing ACE is left in place.
$machineTemplateDN = "CN=Machine,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=warthogs,DC=biz"
$entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$machineTemplateDN")
$acl = $entry.ObjectSecurity
$domainComputers = New-Object System.Security.Principal.NTAccount("WARTHOGS\Domain Computers")
$autoEnrollGuid = [guid]"a05b8cc2-17bc-4802-a710-e7c15ab866a2"

$alreadyGranted = $false
foreach ($ace in $acl.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])) {
    if ($ace.IdentityReference -eq $domainComputers -and
        $ace.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
        $ace.ObjectType -eq $autoEnrollGuid) {
        $alreadyGranted = $true
        break
    }
}
if (-not $alreadyGranted) {
    $rule = New-Object System.DirectoryServices.ExtendedRightAccessRule(
        $domainComputers,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $autoEnrollGuid)
    $acl.AddAccessRule($rule)
    $entry.ObjectSecurity = $acl
    $entry.CommitChanges()
}

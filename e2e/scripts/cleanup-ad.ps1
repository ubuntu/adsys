# Description: Clean up stale data from the AD Server
#
# The script takes a single argument, the hostname of the Linux client being tested.
# It deletes all resources pertaining to it (GPOS, OUs, user accounts), and any
# other stale E2E resources older than 7 days.
# If no argument is provided, only stale resources are deleted.
param (
    [string]$hostname
)

# Uncomment to dry run the script
# $WhatIfPreference = $true

# Stop on first error
$ErrorActionPreference = "Stop"

$parentOUPath = "OU=e2e,DC=warthogs,DC=biz"
$cutoffDate = (Get-Date).AddDays(-7)

# If hostname is provided, delete its GPOs and OUs
if ($hostname) {
    # Recursively delete OU (and users)
    try {
        Remove-ADOrganizationalUnit -Identity "OU=${hostname},${parentOUPath}" -Recursive -Confirm:$false
    } catch {
        Write-Host "OU for ${hostname} not found"
    }

    # Delete GPOs
    $gpoPaths = 'users', 'admins', 'computers'
    foreach ($gpoPath in $gpoPaths) {
        $gpoName = "e2e-$hostname-$gpoPath-gpo"
        try {
            Remove-GPO -Name $gpoName -Confirm:$false
        } catch {
            Write-Host "GPO for ${hostname} not found"
        }
    }
}

# Remove stale OUs
$ous = Get-ADOrganizationalUnit -SearchBase $parentOUPath -Filter * -Properties whenCreated -SearchScope OneLevel
foreach ($ou in $ous) {
    if ($ou.whenCreated -lt $cutoffDate) {
        Remove-ADOrganizationalUnit -Identity $ou.DistinguishedName -Recursive -Confirm:$false
    }
}

# Remove stale GPOs
$gpos = Get-GPO -All
foreach ($gpo in $gpos) {
    $gpoName = $gpo.DisplayName
    if ($gpoName -match "e2e-.*-gpo") {
        if ($gpo.CreationTime -lt $cutoffDate) {
            Remove-GPO -Name $gpoName -Confirm:$false
        }
    }
}

# Remove stale users
$users = Get-ADUser -Filter * -Properties whenCreated
foreach ($user in $users) {
    $userName = $user.Name
    if ($userName -match ".*-usr" -or $userName -match ".*-adm") {
        if ($user.whenCreated -lt $cutoffDate) {
            Remove-ADUser -Identity $userName -Confirm:$false
        }
    }
}

# Description: Prepare the domain controller for E2E testing
#
# The script takes a single argument, the hostname of the Linux client to be tested.
# It creates the following OU structure, together with GPOs and users:
#  DC=warthogs,DC=biz
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
# case when ran via the ./cmd/provision_resources/02_provision_ad command.
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
$parentOUPath = "DC=warthogs,DC=biz"
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

    $gpoName = "$hostname-$targetOU-gpo"
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

# Move machine to computers OU
$identity = Get-ADComputer -Identity $hostname
Move-ADObject -Identity $identity -TargetPath "OU=computers,$($organizationalUnits['computers'])"

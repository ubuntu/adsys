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

# Renew the DC's CEP/IIS HTTPS certificate if it has expired. The legacy
# CEPCES enrollment backend connects to the CEP endpoint over HTTPS
# (https://adc.warthogs.biz:443/ADPolicyProvider_CEP_Kerberos/service.svc/CEP)
# and verifies the server certificate. The AD base image is built
# periodically and the DC's HTTPS certificate may lapse between rebuilds.
# Request a new certificate from AD CS and bind it to the IIS HTTPS
# endpoint so CEPCES enrollment works.
$validCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    ($_.Subject -match "adc\.warthogs\.biz" -or $_.DnsNameList -match "adc\.warthogs\.biz") -and
    $_.NotAfter -gt (Get-Date)
} | Sort-Object NotAfter -Descending | Select-Object -First 1

if (-not $validCert) {
    # Request a new certificate from the DomainController template.
    # Use -config to specify the CA explicitly and -q -f to suppress any
    # interactive prompts and force file overwrites so the command runs
    # non-interactively without hanging the remote session.
    $caConfig = "adc.warthogs.biz\warthogs-CA"
    $infContent = @"
[Version]
Signature = "`$Windows NT`$"
[NewRequest]
Subject = "CN=adc.warthogs.biz"
KeySpec = 1
KeyLength = 2048
Exportable = false
MachineKeySet = true
ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider"
RequestType = PKCS10
[EnhancedKeyUsageExtension]
OID = 1.3.6.1.5.5.7.3.1
[Extensions]
2.5.29.17 = "{text}DNS=adc.warthogs.biz&DNS=adc"
"@

    $suffix = [System.IO.Path]::GetRandomFileName()
    $infPath = Join-Path $env:TEMP "cep_renewal_${hostname}_${suffix}.inf"
    $reqPath = Join-Path $env:TEMP "cep_renewal_${hostname}_${suffix}.req"
    $crtPath = Join-Path $env:TEMP "cep_renewal_${hostname}_${suffix}.crt"
    Set-Content -Path $infPath -Value $infContent -Encoding ASCII

    certreq -q -f -new $infPath $reqPath
    certreq -q -f -submit -config $caConfig -attrib "CertificateTemplate:DomainController" $reqPath $crtPath
    certreq -q -f -accept $crtPath
    Remove-Item $infPath, $reqPath, $crtPath -ErrorAction SilentlyContinue

    $validCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
        ($_.Subject -match "adc\.warthogs\.biz" -or $_.DnsNameList -match "adc\.warthogs\.biz") -and
        $_.NotAfter -gt (Get-Date)
    } | Sort-Object NotBefore -Descending | Select-Object -First 1
}

# Ensure the valid certificate is bound to the HTTPS endpoint in HTTP.sys and IIS
if ($validCert) {
    $thumbprint = $validCert.Thumbprint

    # Update HTTP.sys SSL binding for 0.0.0.0:443
    & netsh http delete sslcert ipport=0.0.0.0:443 2>&1 | Out-Null
    & netsh http add sslcert ipport=0.0.0.0:443 certhash=$thumbprint appid='{4dc3e181-e14b-4a21-b022-59fc669b0914}' certstorename=MY 2>&1 | Out-Null

    # Update IIS binding if WebAdministration is available
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    $bindings = Get-WebBinding -Protocol "https" -ErrorAction SilentlyContinue
    foreach ($b in $bindings) {
        try {
            $b.RebindSslCertificate($thumbprint, "My")
        } catch {
            try {
                $b.AddSslCertificate($thumbprint, "My")
            } catch {}
        }
    }

    # Restart IIS so the new certificate is picked up immediately
    & iisreset /restart 2>&1 | Out-Null

    # Warm up the CEP endpoint so subsequent client requests don't hit cold-start timeouts
    try {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        $wc = New-Object System.Net.WebClient
        $wc.DownloadString("https://127.0.0.1/ADPolicyProvider_CEP_Kerberos/service.svc/CEP") | Out-Null
    } catch {}
    try {
        $wc.DownloadString("https://adc.warthogs.biz/ADPolicyProvider_CEP_Kerberos/service.svc/CEP") | Out-Null
    } catch {}
}

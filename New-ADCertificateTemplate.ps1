#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Creates an RSA, ECDSA or ECDH certificate template from a version 1/2 RSA source.
.DESCRIPTION
Version 1.2.0. Creates a new OID registration and template, copies the source
DACL and its inheritance setting, and applies the selected settings. Never overwrites an existing template. With -Publish, publishes on the LOCAL
enterprise CA after successful creation and verification.

Requires an elevated Windows PowerShell 5.1 session, domain connectivity, and delegated
permissions to create OID/template objects and write the template DACL.
Missing ActiveDirectory management tools are installed automatically using
RSAT-AD-PowerShell on Server or RSAT capability on Windows clients.
With -Publish, certutil.exe publishes and verifies the template on the local
enterprise CA. ADCSAdministration is no longer required for publication.
No CA role is installed and no automatic reboot is performed.
Windows servicing may require access to an approved component source.
Local administrator membership does not grant AD or CA permissions.
RSA-validated sources: WebServer, User and KerberosAuthentication. Other sources
require separate lab validation.
Algorithms: RSA (default), plus ECDSA and ECDH on P-256/P-384/P-521. ECC
requires KSP. ECDSA uses Signature purpose and Digital Signature key usage;
ECDH uses Encryption purpose and Key Agreement usage, not Key Encipherment.
Curve size is automatic unless explicitly supplied. EKUs/policies are retained;
application interoperability must be validated separately.
Provider names are not checked against the local machine: the enrollment
client, not this management machine, must have the provider installed.

Defaults: CA 2012 R2, recipient Windows 10/Server 2016, KSP, RSA 3072,
SHA256, any provider, one year (365 days), subject supplied in request,
approval off, key export off. Source renewal period and policies are retained
unless overridden. Source private-key/enrollment flags otherwise remain intact.
No new enrollment ACEs are added unless EnrollmentGroup is supplied.

ApplicationPolicy adds OIDs to both source policy lists; it does not replace
them. The source's owner and audit ACL are not copied. Inherited permissions
come from the destination container, which is also the source container.

CACompatibility and RecipientCompatibility specify minimum versions, not
the actual OS versions. CEP/CES can filter templates with Windows 10/2016
compatibility; use 2012 R2 / Windows 8.1 when that limitation applies.

WhatIf performs discovery and reads/validation, but writes nothing. If AD tools
are missing, it reports planned installation and stops: AD validation cannot run.
Publication needs certutil.exe, which is checked before template creation.
On creation/verification failure, the script attempts to delete only objects
created by this run. Publication is separate: publication failure retains the
verified AD template and reports PublicationStatus Failed; it does not roll back
the template or retry publication. Inspect it, allow replication, then retry
publication separately with certutil. Existing template names remain protected.
AD operations are not transactional: cleanup failure is reported explicitly.
DACL verification tolerates ordering/merging of equivalent allow
ACEs in canonical allow-only DACLs. Deny/callback/noncanonical DACLs retain
strict comparison. Unexpected differences log both SDDL values before rollback.
Publication uses certutil with forced AD template discovery, exit-code and
issuance-list checks. Patch 1.0.1 added certutil -f -ADTemplate before
publication and requires the expected template name in its output.
Version 1.1.0 derives the OID object CN from the final OID arc and the MD5
hash of its UTF-16LE bytes, without a terminator. Existing OID objects are
not repaired automatically. Export/import tools are included separately.
Release 1.0.0 preserved the implementation validated in 0.2.2. The ten lab
scenarios and two additional multi-SAN cases were reported successful.
Actual subject reuse on renewal and the hash in the original CSR were not
independently verified. The template name eventually resolved on the client;
this release does not force an OID cache refresh.

.PARAMETER Name
Unique internal template name (letters, digits, underscore, hyphen).
.PARAMETER DisplayName
Friendly template name displayed in the Certificate Templates console.
.PARAMETER SourceTemplate
Internal name of a version 1/2 RSA source template. Default: WebServer.
Tab suggests the three lab-tested baselines, not an inventory of AD templates.
.PARAMETER CACompatibility
Certification Authority choice from the Compatibility tab.
.PARAMETER RecipientCompatibility
Certificate recipient choice from the Compatibility tab.
.PARAMETER ProviderCategory
Legacy Cryptographic Service Provider or Key Storage Provider.
.PARAMETER ProviderSelection
AnyAvailable permits any provider in the selected category. SelectedProviders
requires Provider and writes the ordered provider list with priorities 1, 2, ...
.PARAMETER Provider
Exact provider names, in preference order. Only with SelectedProviders.
Tab completion lists local providers for the selected category. Names on remote
enrollment clients can still be entered manually; suggestions are not validation.
Fallback examples are labeled when local provider discovery is unavailable.
.PARAMETER Algorithm
RSA (default); ECDSA_P256/P384/P521 for signing; ECDH_P256/P384/P521 for
key agreement. ECC requires KSP. Family-specific purpose and key usage are set
automatically. Source EKUs are retained, not converted to a new application.
.PARAMETER MinimumKeySize
RSA: 1024, 2048, 3072, 4096, 8192 or 16384 bits; default 3072.
ECC: omit for automatic 256/384/521 selection, or specify exactly the curve size.
.PARAMETER RequestHash
KSP request hash, distinct from the CA certificate signature and ECDH KDF.
Defaults: SHA256 (RSA/P-256), SHA384 (P-384), SHA512 (P-521). ECC accepts
SHA256, SHA384 or SHA512; SHA1 is rejected. Omit for legacy CSP.
.PARAMETER ValidityYears
Validity in years of 365 days. Default: 1.
.PARAMETER RenewalWeeks
Optional renewal period in weeks; otherwise the source period is retained.
.PARAMETER SubjectNameMode
SupplyInRequest or ActiveDirectory.
.PARAMETER ReuseSubjectOnRenewal
Use subject information from existing certificates for autoenrollment renewal.
Only valid with SupplyInRequest; does not grant Autoenroll rights.
.PARAMETER SubjectNameFormat
AD subject format: None, Common name, Fully distinguished name, DNS name,
or E-mail name. Omit with SupplyInRequest.
.PARAMETER SubjectAlternativeName
AD SAN selections: DNS name, Domain DNS name, E-mail name, UPN, SPN, Directory GUID.
Omit with SupplyInRequest. DNS-based enrollment requires a computer identity
with dNSHostName and its own enrollment permissions. Domain DNS name sets
CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS; for a DC profile, combine it with
DNS name. The CA obtains DNS-domain and NetBIOS-domain information from the
requesting computer. The CA must be able to contact that computer for this lookup.
.PARAMETER RequireManagerApproval
CA certificate manager approval. Default false.
.PARAMETER AllowPrivateKeyExport
Allow private key to be exported for newly generated keys. Default false.
.PARAMETER ApplicationPolicy
Tab suggests the known friendly names; custom numeric OIDs remain accepted.
Additional application policy OIDs or names: Client Authentication,
Server Authentication, Code Signing, Secure Email, Time Stamping, OCSP Signing.
.PARAMETER EnrollmentGroup
AD groups to receive Read + Enroll, and optionally Autoenroll.
.PARAMETER EnrollmentPermission
Enroll or EnrollAndAutoenroll. Default Enroll. Source ACEs are retained.
.PARAMETER Publish
Publish the newly created template on the local enterprise CA. Run on that CA.
Publication in this script is restricted to the local enterprise CA.
.PARAMETER Server
Optional DC override; a writable DC is discovered automatically when omitted.
.EXAMPLE
.\New-ADCertificateTemplate.ps1 -Name MWWebServer02 -DisplayName 'MW Web Server 02' -WhatIf
.EXAMPLE
$settings = @{
    Name = 'MWWebServer02'
    DisplayName = 'MW Web Server 02'
    ProviderSelection = 'SelectedProviders'
    Provider = 'Microsoft Software Key Storage Provider'
    SubjectNameMode = 'ActiveDirectory'
    SubjectNameFormat = 'DNS name'
    SubjectAlternativeName = 'DNS name'
    RequireManagerApproval = $true
    AllowPrivateKeyExport = $true
    ApplicationPolicy = 'Client Authentication'
    EnrollmentGroup = 'GG-T0-Admins'
}
.\New-ADCertificateTemplate.ps1 @settings -Verbose
.EXAMPLE
.\New-ADCertificateTemplate.ps1 -Name MWLegacy01 -DisplayName 'MW Legacy 01' -ProviderCategory 'Legacy Cryptographic Service Provider' -ReuseSubjectOnRenewal $true
.EXAMPLE
.\New-ADCertificateTemplate.ps1 -Name MWMultiSANUser01 -DisplayName 'MW Multi SAN User 01' -SourceTemplate User -SubjectNameMode ActiveDirectory -SubjectNameFormat 'Common name' -SubjectAlternativeName UPN,'E-mail name' -EnrollmentGroup 'GG-T0-Admins' -Publish
.NOTES
Version: 1.2.0
Use Get-Help -Full for parameters and examples. Without -Publish: creation only.
Direct AD changes: validate resulting UI settings and enroll in a lab before production.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z][A-Za-z0-9_-]{0,63}$')]
    [string]$Name,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$DisplayName,
    [ArgumentCompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $prefix = ([string]$wordToComplete).Trim([char[]]@([char]39,[char]34))
        foreach ($value in @('WebServer','User','KerberosAuthentication')) {
            if ($value.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) {
                $quoted = "'" + $value.Replace("'", "''") + "'"
                [System.Management.Automation.CompletionResult]::new(
                    $quoted,$value,[System.Management.Automation.CompletionResultType]::ParameterValue,
                    'Lab-tested RSA baseline; other version 1/2 source names can still be supplied.')
            }
        }
    })]
    [ValidatePattern('^[A-Za-z][A-Za-z0-9_-]{0,63}$')][string]$SourceTemplate = 'WebServer',
    [ValidateSet('Windows Server 2003','Windows Server 2008','Windows Server 2008 R2',
        'Windows Server 2012','Windows Server 2012 R2','Windows Server 2016')]
    [string]$CACompatibility = 'Windows Server 2012 R2',
    [ValidateSet('Windows XP / Windows Server 2003','Windows Vista / Windows Server 2008',
        'Windows 7 / Windows Server 2008 R2','Windows 8 / Windows Server 2012',
        'Windows 8.1 / Windows Server 2012 R2','Windows 10 / Windows Server 2016')]
    [string]$RecipientCompatibility = 'Windows 10 / Windows Server 2016',
    [ValidateSet('Legacy Cryptographic Service Provider','Key Storage Provider')]
    [string]$ProviderCategory = 'Key Storage Provider',
    [ValidateSet('AnyAvailable','SelectedProviders')][string]$ProviderSelection = 'AnyAvailable',
    [ArgumentCompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        # Completion is read-only and self-contained: the generator body is not run.
        $category = 'Key Storage Provider'
        if ($null -ne $fakeBoundParameters -and $fakeBoundParameters.ContainsKey('ProviderCategory') -and
            $fakeBoundParameters['ProviderCategory'] -in 'Key Storage Provider','Legacy Cryptographic Service Provider') {
            $category = [string]$fakeBoundParameters['ProviderCategory']
        }
        $wantLegacy = $category -eq 'Legacy Cryptographic Service Provider'
        $names = [System.Collections.Generic.List[string]]::new()
        $collection = $null
        try {
            $collection = New-Object -ComObject X509Enrollment.CCspInformations -ErrorAction Stop
            $null = $collection.AddAvailableCsps()
            for ($index = 0; $index -lt $collection.Count; $index++) {
                $provider = $null
                try {
                    $provider = $collection.ItemByIndex($index)
                    if ([bool]$provider.LegacyCsp -eq $wantLegacy -and
                        -not [string]::IsNullOrWhiteSpace([string]$provider.Name)) {
                        $names.Add([string]$provider.Name)
                    }
                }
                catch { } # A provider with unreadable metadata is omitted.
                finally {
                    if ($null -ne $provider -and [Runtime.InteropServices.Marshal]::IsComObject($provider)) {
                        try { $null = [Runtime.InteropServices.Marshal]::ReleaseComObject($provider) } catch { }
                    }
                }
            }
        }
        catch { } # Completion must not interrupt input when COM discovery is unavailable.
        finally {
            if ($null -ne $collection -and [Runtime.InteropServices.Marshal]::IsComObject($collection)) {
                try { $null = [Runtime.InteropServices.Marshal]::ReleaseComObject($collection) } catch { }
            }
        }
        $origin = 'Locally installed'
        if ($names.Count -eq 0) {
            $origin = 'Common Windows example; local discovery unavailable'
            if ($wantLegacy) {
                $names.Add('Microsoft Enhanced RSA and AES Cryptographic Provider')
                $names.Add('Microsoft Enhanced Cryptographic Provider v1.0')
                $names.Add('Microsoft Strong Cryptographic Provider')
                $names.Add('Microsoft Base Cryptographic Provider v1.0')
            }
            else { $names.Add('Microsoft Software Key Storage Provider') }
        }
        $prefix = ([string]$wordToComplete).Trim([char[]]@([char]39,[char]34))
        $kind = if ($wantLegacy) { 'Legacy CSP' } else { 'KSP' }
        foreach ($name in @($names | Sort-Object -Unique)) {
            if ($name.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) {
                $quoted = "'" + $name.Replace("'", "''") + "'"
                $tip = "$origin $kind. Use SelectedProviders; verify availability and algorithm support on enrollment clients."
                [System.Management.Automation.CompletionResult]::new(
                    $quoted,$name,[System.Management.Automation.CompletionResultType]::ParameterValue,$tip)
            }
        }
    })]
    [ValidateNotNullOrEmpty()][string[]]$Provider,
    [ValidateSet('RSA','ECDSA_P256','ECDSA_P384','ECDSA_P521','ECDH_P256','ECDH_P384','ECDH_P521')][string]$Algorithm = 'RSA',
    [ValidateSet(256,384,521,1024,2048,3072,4096,8192,16384)][int]$MinimumKeySize = 3072,
    [ValidateSet('SHA1','SHA256','SHA384','SHA512')][string]$RequestHash = 'SHA256',
    [ValidateRange(1,100)][int]$ValidityYears = 1,
    [ValidateRange(1,5200)][int]$RenewalWeeks,
    [ValidateSet('SupplyInRequest','ActiveDirectory')][string]$SubjectNameMode = 'SupplyInRequest',
    [bool]$ReuseSubjectOnRenewal = $false,
    [ValidateSet('None','Common name','Fully distinguished name','DNS name','E-mail name')]
    [string]$SubjectNameFormat,
    [ValidateSet('DNS name','Domain DNS name','E-mail name','UPN','SPN','Directory GUID')]
    [string[]]$SubjectAlternativeName,
    [bool]$RequireManagerApproval = $false,
    [bool]$AllowPrivateKeyExport = $false,
    [ArgumentCompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $prefix = ([string]$wordToComplete).Trim([char[]]@([char]39,[char]34))
        foreach ($value in @('Client Authentication','Server Authentication','Code Signing','Secure Email','Time Stamping','OCSP Signing')) {
            if ($value.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) {
                $quoted = "'" + $value.Replace("'", "''") + "'"
                [System.Management.Automation.CompletionResult]::new(
                    $quoted,$value,[System.Management.Automation.CompletionResultType]::ParameterValue,
                    'Adds this purpose to the source policies. A valid numeric OID can also be entered.')
            }
        }
    })]
    [ValidateNotNullOrEmpty()][string[]]$ApplicationPolicy,
    [ValidateNotNullOrEmpty()][string[]]$EnrollmentGroup,
    [ValidateSet('Enroll','EnrollAndAutoenroll')][string]$EnrollmentPermission = 'Enroll',
    [ValidateNotNullOrEmpty()][string]$Server,
    [switch]$Publish
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-AttributeValue {
    param($Object, [string]$Attribute)
    $property = $Object.PSObject.Properties[$Attribute]
    if ($null -ne $property) { return ,($property.Value) }
    return $null
}

function Get-StringValues {
    param($Value)
    foreach ($item in $Value) {
        if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace([string]$item)) {
            [string]$item
        }
    }
}

function Get-AllowDaclFingerprint {
    param([System.DirectoryServices.ActiveDirectorySecurity]$Security)
    # Only allow-only canonical DACLs can safely ignore ordering here.
    # Any deny/callback/unsupported ACE uses strict comparison instead.
    if (-not $Security.AreAccessRulesCanonical) { return $null }
    $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new(
        $Security.GetSecurityDescriptorBinaryForm(), 0)
    if ($null -eq $raw.DiscretionaryAcl) { return $null }
    $masks = @{}
    foreach ($ace in $raw.DiscretionaryAcl) {
        if ($ace -isnot [System.Security.AccessControl.QualifiedAce]) { return $null }
        if ($ace.AceQualifier -ne [System.Security.AccessControl.AceQualifier]::AccessAllowed -or
            $ace.IsCallback) { return $null }
        if ($ace -isnot [System.Security.AccessControl.CommonAce] -and
            $ace -isnot [System.Security.AccessControl.ObjectAce]) { return $null }

        # Preserve ACE type, flags, SID, object GUIDs and every other byte.
        # Normalize only the access mask and the order of equivalent allow ACEs.
        $bytes = [byte[]]::new($ace.BinaryLength)
        $ace.GetBinaryForm($bytes, 0)
        for ($index = 4; $index -lt 8; $index++) { $bytes[$index] = 0 }
        $key = [Convert]::ToBase64String($bytes)
        if (-not $masks.ContainsKey($key)) { $masks[$key] = [int]0 }
        $masks[$key] = [int]$masks[$key] -bor [int]$ace.AccessMask
    }
    $parts = @("Protected=$($Security.AreAccessRulesProtected)")
    foreach ($key in @($masks.Keys | Sort-Object)) {
        $parts += "$key=$($masks[$key])"
    }
    return ($parts -join '|')
}

function Test-TemplateDacl {
    param([System.DirectoryServices.ActiveDirectorySecurity]$Expected,
          [System.DirectoryServices.ActiveDirectorySecurity]$Actual)
    $section = [System.Security.AccessControl.AccessControlSections]::Access
    $expectedSddl = $Expected.GetSecurityDescriptorSddlForm($section)
    $actualSddl = $Actual.GetSecurityDescriptorSddlForm($section)
    if ($expectedSddl -ceq $actualSddl) { return $true }
    $expectedFingerprint = Get-AllowDaclFingerprint $Expected
    $actualFingerprint = Get-AllowDaclFingerprint $Actual
    if ($null -ne $expectedFingerprint -and $null -ne $actualFingerprint -and
        $expectedFingerprint -ceq $actualFingerprint) {
        Write-Verbose 'DACL verified: identical allow ACEs and inheritance protection; only representation/order differs.'
        return $true
    }
    Write-Verbose "Expected DACL: $expectedSddl"
    Write-Verbose "Saved DACL:    $actualSddl"
    return $false
}

function Open-TemplateEntry {
    param([string]$DistinguishedName)
    $entry = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$DC/$DistinguishedName")
    try {
        $entry.PSBase.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
        $entry.PSBase.RefreshCache(@('ntSecurityDescriptor'))
        return ,$entry
    }
    catch { $entry.PSBase.Dispose(); throw }
}

# This release uses native Windows PowerShell RSAT/ServerManager modules.
if ($PSVersionTable.PSEdition -ne 'Desktop') {
    throw 'Run this version in elevated Windows PowerShell 5.1 (powershell.exe).'
}

# Pass the script cmdlet explicitly so installation also honors -WhatIf/-Confirm.
function Ensure-ManagementModule {
    param([string]$ModuleName, [string]$ServerFeature,
          [string]$ClientCapability, $CallingCmdlet)
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        if (-not $CallingCmdlet.ShouldProcess($env:COMPUTERNAME, "Install management tools for $ModuleName")) {
            return $false
        }
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ([int]$os.ProductType -eq 1) {
            if ([string]::IsNullOrWhiteSpace($ClientCapability)) {
                throw "$ModuleName automatic installation is supported only on Windows Server in this version."
            }
            Import-Module Dism -ErrorAction Stop -Verbose:$false
            $installation = Add-WindowsCapability -Online -Name $ClientCapability -ErrorAction Stop
            if ($installation.RestartNeeded) {
                throw 'Management tools require a restart. Restart manually and rerun the script.'
            }
        }
        else {
            Import-Module ServerManager -ErrorAction Stop -Verbose:$false
            $installation = Install-WindowsFeature -Name $ServerFeature -ErrorAction Stop
            if (-not $installation.Success) { throw "Installation of $ServerFeature failed." }
            if ([string]$installation.RestartNeeded -eq 'Yes') {
                throw 'Management tools require a restart. Restart manually and rerun the script.'
            }
        }
        if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
            throw "$ModuleName is still unavailable after installing the management tools. No template was created."
        }
    }
    # Use global scope because import occurs inside this helper function.
    Import-Module $ModuleName -Global -ErrorAction Stop -Verbose:$false
    return $true
}

$caVersions = @('Windows Server 2003','Windows Server 2008','Windows Server 2008 R2',
    'Windows Server 2012','Windows Server 2012 R2','Windows Server 2016')
$clientVersions = @('Windows XP / Windows Server 2003','Windows Vista / Windows Server 2008',
    'Windows 7 / Windows Server 2008 R2','Windows 8 / Windows Server 2012',
    'Windows 8.1 / Windows Server 2012 R2','Windows 10 / Windows Server 2016')
$caCode = [array]::IndexOf($caVersions, $CACompatibility) + 1
$clientCode = [array]::IndexOf($clientVersions, $RecipientCompatibility) + 1
$isKsp = $ProviderCategory -eq 'Key Storage Provider'
$Algorithm = $Algorithm.ToUpperInvariant()
$isEcc = $Algorithm -ne 'RSA'
$isEcdsa = $Algorithm -like 'ECDSA_*'
$isEcdh = $Algorithm -like 'ECDH_*'
if ($isEcc) {
    if (-not $isKsp) { throw 'ECC requires ProviderCategory Key Storage Provider.' }
    $curveSize = [int]($Algorithm.Split('_')[1].Substring(1))
    if ($PSBoundParameters.ContainsKey('MinimumKeySize') -and $MinimumKeySize -ne $curveSize) {
        throw "Algorithm $Algorithm requires MinimumKeySize $curveSize (or omit MinimumKeySize)."
    }
    $MinimumKeySize = $curveSize
    if (-not $PSBoundParameters.ContainsKey('RequestHash')) {
        $RequestHash = @{256='SHA256';384='SHA384';521='SHA512'}[$curveSize]
    }
    if ($RequestHash -eq 'SHA1') { throw 'ECC profiles in this release require a SHA2 request hash.' }
}
elseif ($MinimumKeySize -notin 1024,2048,3072,4096,8192,16384) {
    throw 'RSA MinimumKeySize must be 1024, 2048, 3072, 4096, 8192 or 16384.'
}

if ($isKsp -and ($caCode -lt 2 -or $clientCode -lt 2)) {
    throw 'Key Storage Provider requires at least CA Windows Server 2008 and recipient Windows Vista.'
}
if (-not $isKsp -and $PSBoundParameters.ContainsKey('RequestHash')) {
    throw 'With legacy CSP, omit RequestHash: the UI uses Determined by CSP.'
}
if ($ProviderSelection -eq 'SelectedProviders' -and -not $Provider) {
    throw 'SelectedProviders requires at least one Provider name.'
}
if ($ProviderSelection -eq 'AnyAvailable' -and $Provider) {
    throw 'Provider is only valid with ProviderSelection SelectedProviders.'
}
if ($Provider) {
    foreach ($providerName in $Provider) {
        if ([string]::IsNullOrWhiteSpace($providerName) -or $providerName -match '[,\r\n]') {
            throw 'Provider names must be nonempty and contain no commas or newlines.'
        }
    }
    if (@($Provider | Sort-Object -Unique).Count -ne $Provider.Count) {
        throw 'Provider names must be unique.'
    }
}
if ($SubjectNameMode -eq 'SupplyInRequest' -and
    ($PSBoundParameters.ContainsKey('SubjectNameFormat') -or $SubjectAlternativeName)) {
    throw 'SubjectNameFormat and SubjectAlternativeName apply only to ActiveDirectory mode.'
}
if ($SubjectNameMode -eq 'ActiveDirectory' -and $ReuseSubjectOnRenewal) {
    throw 'ReuseSubjectOnRenewal applies only to SupplyInRequest mode.'
}
if ($SubjectNameMode -eq 'ActiveDirectory' -and -not $SubjectNameFormat) {
    throw 'ActiveDirectory mode requires SubjectNameFormat (use None for an empty subject).'
}
if (-not $EnrollmentGroup -and $PSBoundParameters.ContainsKey('EnrollmentPermission')) {
    throw 'EnrollmentPermission requires EnrollmentGroup.'
}

# Check local publication prerequisites before installing tools or creating objects.
$localCAName = $null
$certutilPath = Join-Path $env:SystemRoot 'System32\certutil.exe'
if ($Publish) {
    if (-not (Test-Path -LiteralPath $certutilPath -PathType Leaf)) {
        throw 'certutil.exe is required for publication. No template was created.'
    }
    $caService = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
    if ($null -eq $caService -or $caService.Status -ne 'Running') {
        throw '-Publish requires a running local CA (CertSvc). Run on the issuing CA or omit -Publish.'
    }
    $caRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
    $localCAName = [string](Get-ItemProperty -LiteralPath $caRoot -Name Active -ErrorAction Stop).Active
    if ([string]::IsNullOrWhiteSpace($localCAName)) { throw 'No active local CA configuration found.' }
    $caSettings = Get-ItemProperty -LiteralPath "$caRoot\$localCAName" -Name CAType -ErrorAction Stop
    if ([int]$caSettings.CAType -notin 0,1) { throw '-Publish requires an enterprise CA.' }
}

$adReady = Ensure-ManagementModule -ModuleName ActiveDirectory `
    -ServerFeature RSAT-AD-PowerShell `
    -ClientCapability 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0' -CallingCmdlet $PSCmdlet
if (-not $adReady) {
    Write-Warning 'ActiveDirectory tools are missing. Installation was not performed; AD validation and creation were skipped.'
    return
}

if ($Server) { $DC = $Server }
else {
    $discoveredDC = Get-ADDomainController -Discover -Writable -ErrorAction Stop
    $DC = [string]($discoveredDC.HostName | Select-Object -First 1)
}
if ([string]::IsNullOrWhiteSpace($DC)) { throw 'Domain controller discovery returned no hostname.' }
$dcInfo = Get-ADDomainController -Identity $DC -Server $DC -ErrorAction Stop
if ($dcInfo.IsReadOnly) { throw 'The selected domain controller is read-only.' }
$root = Get-ADRootDSE -Server $DC -ErrorAction Stop
$configNC = [string]$root.configurationNamingContext
$templateContainer = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
$oidContainer = "CN=OID,CN=Public Key Services,CN=Services,$configNC"
$targetDN = "CN=$Name,$templateContainer"
Write-Verbose "Using domain controller: $DC"

if (Get-ADObject -Server $DC -SearchBase $templateContainer -SearchScope OneLevel -LDAPFilter "(cn=$Name)") {
    throw "Template '$Name' already exists. No changes were made."
}
$source = Get-ADObject -Server $DC -Identity "CN=$SourceTemplate,$templateContainer" -Properties *
$sourceVersion = [int](Get-AttributeValue $source 'msPKI-Template-Schema-Version')
if ($sourceVersion -notin 1,2) {
    throw 'The creator supports version 1/2 RSA source templates only (baseline: WebServer). Use export/import for custom KSP sources.'
}
$forestOidObject = Get-ADObject -Server $DC -Identity $oidContainer -Properties 'msPKI-Cert-Template-OID'
$forestOid = [string]$forestOidObject.'msPKI-Cert-Template-OID'
if ([string]::IsNullOrWhiteSpace($forestOid)) { throw 'No forest OID base was found.' }

# Resolve every group before any writes. Same-domain names or explicit DNs/SIDs.
$groupSids = @(
    foreach ($groupName in $EnrollmentGroup) {
        (Get-ADGroup -Server $DC -Identity $groupName -ErrorAction Stop).SID.Value
    }
) | Sort-Object -Unique

$copyAttributes = @('flags','pKIDefaultKeySpec','pKIKeyUsage','pKIMaxIssuingDepth',
    'pKICriticalExtensions','pKIExtendedKeyUsage','pKIExpirationPeriod','pKIOverlapPeriod',
    'msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag','msPKI-Private-Key-Flag',
    'msPKI-RA-Signature','msPKI-RA-Policies','msPKI-RA-Application-Policies',
    'msPKI-Certificate-Policy','msPKI-Certificate-Application-Policy')
$attributes = @{}
foreach ($attribute in $copyAttributes) {
    $value = Get-AttributeValue $source $attribute
    if ($null -eq $value) { continue }
    if ($value -is [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]) {
        if ($value.Count -eq 0) { continue }
        if ($value.Count -eq 1) { $value = $value[0] }
        else { $value = @($value) }
    }
    $attributes[$attribute] = $value
}
if ($attributes.ContainsKey('flags')) {
    $attributes['flags'] = [int]$attributes['flags'] -band (-bnot 0x00010000)
}

# Use version 4 for 2012+ settings, version 3 for KSP, otherwise version 2.
$schemaVersion = 2
if ($caCode -ge 4 -or $clientCode -ge 4) { $schemaVersion = 4 }
elseif ($isKsp) { $schemaVersion = 3 }
if ($schemaVersion -eq 4 -and ($caCode -lt 4 -or $clientCode -lt 4)) {
    throw 'Version 4 requires both CA and recipient compatibility of Windows Server 2012 / Windows 8 or later.'
}

$privateFlags = [int]$attributes['msPKI-Private-Key-Flag']
if ($isEcc) {
    if (($privateFlags -band 1) -ne 0) {
        throw 'ECC profiles requiring private-key archival are outside this release scope.'
    }
    $attributes['pKIDefaultKeySpec'] = if ($isEcdh) { 1 } else { 2 }
    # ECDH is key agreement, not RSA-style key encipherment.
    if ($isEcdh) { $attributes['pKIKeyUsage'] = [byte[]]@(0x08,0x00) }
    else { $attributes['pKIKeyUsage'] = [byte[]]@(0x80,0x00) }
}
$privateFlags = ($privateFlags -band (-bnot (0x000F0000 -bor 0x0F000000))) -bor
    ($caCode -shl 16) -bor ($clientCode -shl 24)
if ($AllowPrivateKeyExport) { $privateFlags = $privateFlags -bor 0x10 }
else { $privateFlags = $privateFlags -band (-bnot 0x10) }
if ($isKsp) {
    $privateFlags = $privateFlags -band (-bnot 0x100)
    # Convert the source's RA policies to the KSP property-triplet syntax.
    $raPolicies = @(Get-StringValues (Get-AttributeValue $source 'msPKI-RA-Application-Policies'))
    # Match certtmpl.msc for ECDH: restricting CNG to agreement-only caused
    # NTE_PERM during enrollment in the lab. Certificate usage stays Key Agreement.
    $cngKeyUsage = if ($isEcdh) { 0x00FFFFFF } elseif ($isEcdsa) { 2 } else { 3 }
    $crypto = 'msPKI-Asymmetric-Algorithm`PZPWSTR`' + $Algorithm + '`' +
        'msPKI-Hash-Algorithm`PZPWSTR`' + $RequestHash + '`' +
        'msPKI-Key-Usage`DWORD`' + $cngKeyUsage + '`'
    if ($raPolicies.Count -gt 0) {
        $crypto += 'msPKI-RA-Application-Policies`PZPWSTR`' + ($raPolicies -join ',') + '`'
    }
    $attributes['msPKI-RA-Application-Policies'] = $crypto
}
else { $privateFlags = $privateFlags -bor 0x100 }
$attributes['msPKI-Private-Key-Flag'] = [int]$privateFlags
$attributes['msPKI-Minimal-Key-Size'] = $MinimumKeySize
if ($ProviderSelection -eq 'SelectedProviders') {
    $providerList = @()
    for ($i = 0; $i -lt $Provider.Count; $i++) { $providerList += "$($i + 1),$($Provider[$i])" }
    $attributes['pKIDefaultCSPs'] = [string[]]$providerList
}

$validity = [TimeSpan]::FromDays(365 * $ValidityYears)
$attributes['pKIExpirationPeriod'] = [BitConverter]::GetBytes([long](-$validity.Ticks))
if ($PSBoundParameters.ContainsKey('RenewalWeeks')) {
    $renewal = [TimeSpan]::FromDays(7 * $RenewalWeeks)
    $attributes['pKIOverlapPeriod'] = [BitConverter]::GetBytes([long](-$renewal.Ticks))
}
elseif ($attributes.ContainsKey('pKIOverlapPeriod')) {
    $renewalTicks = [BitConverter]::ToInt64([byte[]]$attributes['pKIOverlapPeriod'], 0)
    $renewal = [TimeSpan]::FromTicks(-$renewalTicks)
}
else { throw 'Source has no renewal period. Specify RenewalWeeks.' }
if ($renewal.Ticks -le 0 -or $renewal -ge $validity) {
    throw 'Renewal period must be positive and shorter than the validity period.'
}
if ($renewal.TotalHours -le 8 -or $renewal.TotalDays -ge ($validity.TotalDays * 0.2)) {
    Write-Warning 'Renewal period is outside the recommended >8 hours and <20% of validity range.'
}

$nameFlags = 0
if ($SubjectNameMode -eq 'SupplyInRequest') {
    $nameFlags = 1
    if ($ReuseSubjectOnRenewal) { $nameFlags = $nameFlags -bor 8 }
}
else {
    $formatFlags = @{'None'=0; 'Common name'=0x40000000;
        'Fully distinguished name'=-2147483648; 'DNS name'=0x10000000; 'E-mail name'=0x20000000}
    $sanFlags = @{'DNS name'=0x08000000; 'Domain DNS name'=0x00400000; 'E-mail name'=0x04000000;
        'UPN'=0x02000000; 'SPN'=0x00800000; 'Directory GUID'=0x01000000}
    $nameFlags = [int]$formatFlags[$SubjectNameFormat]
    foreach ($san in $SubjectAlternativeName) { $nameFlags = $nameFlags -bor $sanFlags[$san] }
    if ($nameFlags -eq 0) { throw 'An empty AD subject requires at least one SAN selection.' }
}
$attributes['msPKI-Certificate-Name-Flag'] = [int]$nameFlags
$enrollmentFlags = [int]$attributes['msPKI-Enrollment-Flag']
if ($RequireManagerApproval) { $enrollmentFlags = $enrollmentFlags -bor 2 }
else { $enrollmentFlags = $enrollmentFlags -band (-bnot 2) }
$attributes['msPKI-Enrollment-Flag'] = [int]$enrollmentFlags

$policyNames = @{'Client Authentication'='1.3.6.1.5.5.7.3.2';
    'Server Authentication'='1.3.6.1.5.5.7.3.1'; 'Code Signing'='1.3.6.1.5.5.7.3.3';
    'Secure Email'='1.3.6.1.5.5.7.3.4'; 'Time Stamping'='1.3.6.1.5.5.7.3.8';
    'OCSP Signing'='1.3.6.1.5.5.7.3.9'}
$extraOids = @(
    foreach ($policy in $ApplicationPolicy) {
        if ($policyNames.ContainsKey($policy)) { $policyNames[$policy] }
        elseif ($policy -match '^[0-2](\.[0-9]+)+$') {
            # Validate ASN.1 first/second arcs as well as the dotted format.
            $arcs = $policy.Split('.')
            if ([int]$arcs[0] -lt 2 -and [decimal]$arcs[1] -gt 39) { throw "Invalid OID: $policy" }
            $policy
        }
        else { throw "Unknown application policy name or invalid OID: $policy" }
    }
)
if ($extraOids.Count -gt 0) {
    foreach ($attribute in @('pKIExtendedKeyUsage','msPKI-Certificate-Application-Policy')) {
        $existing = @(Get-StringValues (Get-AttributeValue $source $attribute))
        # Populate missing application policies from EKU for a version 1 source.
        if ($attribute -eq 'msPKI-Certificate-Application-Policy' -and $existing.Count -eq 0) {
            $existing = @(Get-StringValues (Get-AttributeValue $source 'pKIExtendedKeyUsage'))
        }
        $attributes[$attribute] = [string[]]@(($existing + $extraOids) | Sort-Object -Unique)
    }
}
elseif (-not $attributes.ContainsKey('msPKI-Certificate-Application-Policy')) {
    $sourceEku = @(Get-StringValues (Get-AttributeValue $source 'pKIExtendedKeyUsage'))
    if ($sourceEku.Count -gt 0) { $attributes['msPKI-Certificate-Application-Policy'] = [string[]]$sourceEku }
}

# Capture the source DACL and construct the final permissions before creating objects.
$sourceEntry = Open-TemplateEntry $source.DistinguishedName
try {
    $sourceSecurity = $sourceEntry.PSBase.ObjectSecurity
    $accessSection = [System.Security.AccessControl.AccessControlSections]::Access
    if ($sourceSecurity.Access.Count -eq 0) { throw 'Source DACL is empty; refusing to copy it.' }
    $sourceSddl = $sourceSecurity.GetSecurityDescriptorSddlForm($accessSection)
    $finalSecurity = [System.DirectoryServices.ActiveDirectorySecurity]::new()
    $finalSecurity.SetSecurityDescriptorSddlForm($sourceSddl, $accessSection)
    foreach ($sidText in $groupSids) {
        $sid = [System.Security.Principal.SecurityIdentifier]::new($sidText)
        $allow = [System.Security.AccessControl.AccessControlType]::Allow
        $finalSecurity.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new(
            $sid, [System.DirectoryServices.ActiveDirectoryRights]::GenericRead, $allow))
        $rights = @([guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55')
        if ($EnrollmentPermission -eq 'EnrollAndAutoenroll') {
            $rights += [guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
        }
        foreach ($right in $rights) {
            $finalSecurity.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new(
                $sid, [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight, $allow, $right))
        }
    }
    $finalSddl = $finalSecurity.GetSecurityDescriptorSddlForm($accessSection)
}
finally { $sourceEntry.PSBase.Dispose() }

function Get-CTOIDObjectName {
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[0-2](\.[0-9]+)+$')]
        [string]$OID
    )
    # Verified against a custom template created through certtmpl.msc.
    # UTF-16LE without a BOM or terminating NUL; MD5 is for object naming only.
    $md5 = [System.Security.Cryptography.MD5]::Create()
    try {
        $oidBytes = [System.Text.Encoding]::Unicode.GetBytes($OID)
        $hashBytes = $md5.ComputeHash($oidBytes)
        $hashHex = ($hashBytes | ForEach-Object {
            $_.ToString('X2')
        }) -join ''
        return ('{0}.{1}' -f $OID.Split('.')[-1], $hashHex)
    }
    finally {
        $md5.Dispose()
    }
}

do {
    $part1 = Get-Random -Minimum 10000000 -Maximum 99999999
    $part2 = Get-Random -Minimum 10000000 -Maximum 99999999
    $newOid = "$forestOid.$part1.$part2"
    $existingOid = Get-ADObject -Server $DC -SearchBase $oidContainer -LDAPFilter "(msPKI-Cert-Template-OID=$newOid)"
} while ($existingOid)
$oidName = Get-CTOIDObjectName -OID $newOid
$attributes['msPKI-Cert-Template-OID'] = $newOid
$attributes['msPKI-Template-Schema-Version'] = $schemaVersion
$attributes['msPKI-Template-Minor-Revision'] = 0
$attributes['revision'] = 1

Write-Verbose "Prepared $Name; schema $schemaVersion; $ProviderCategory; $Algorithm $MinimumKeySize; validity $($validity.TotalDays) days."
$createApproved = $PSCmdlet.ShouldProcess($targetDN, 'Create OID and certificate template, apply settings and source permissions')
if (-not $createApproved) {
    if ($Publish -and $WhatIfPreference) {
        $null = $PSCmdlet.ShouldProcess("$env:COMPUTERNAME\$localCAName", "Publish template $Name after successful creation")
    }
    return
}

$createdOid = $null
$createdTemplate = $null
try {
    $createdOid = New-ADObject -Server $DC -Name $oidName -Path $oidContainer `
        -Type 'msPKI-Enterprise-Oid' -DisplayName $DisplayName `
        -OtherAttributes @{'msPKI-Cert-Template-OID'=$newOid; 'flags'=1} -PassThru -Confirm:$false
    $createdTemplate = New-ADObject -Server $DC -Name $Name -Path $templateContainer `
        -Type 'pKICertificateTemplate' -DisplayName $DisplayName `
        -OtherAttributes $attributes -PassThru -Confirm:$false

    $targetEntry = Open-TemplateEntry $targetDN
    try {
        $targetSecurity = $targetEntry.PSBase.ObjectSecurity
        $targetSecurity.SetSecurityDescriptorSddlForm($finalSddl, $accessSection)
        $targetEntry.PSBase.ObjectSecurity = $targetSecurity
        $targetEntry.PSBase.CommitChanges()
        $targetEntry.PSBase.RefreshCache(@('ntSecurityDescriptor'))
        $savedSecurity = $targetEntry.PSBase.ObjectSecurity
        $savedSddl = $savedSecurity.GetSecurityDescriptorSddlForm($accessSection)
        if (-not (Test-TemplateDacl -Expected $finalSecurity -Actual $savedSecurity)) {
            throw 'Saved DACL differs from the prepared permissions. See Expected DACL and Saved DACL in verbose output.'
        }
    }
    finally { $targetEntry.PSBase.Dispose() }

    $saved = Get-ADObject -Server $DC -Identity $createdTemplate.ObjectGUID -Properties *
    # Check all settings written, comparing binary values and unordered multi-values.
    foreach ($attribute in $attributes.Keys) {
        $expected = $attributes[$attribute]
        $actual = Get-AttributeValue $saved $attribute
        if ($expected -is [byte[]]) {
            $matches = [Convert]::ToBase64String($expected) -ceq [Convert]::ToBase64String([byte[]]$actual)
        }
        else {
            $expectedStrings = @(Get-StringValues $expected | Sort-Object)
            $actualStrings = @(Get-StringValues $actual | Sort-Object)
            $matches = ($expectedStrings.Count -eq $actualStrings.Count) -and
                (($expectedStrings -join [char]0) -ceq ($actualStrings -join [char]0))
        }
        if (-not $matches) { throw "Read-back verification failed for $attribute." }
    }
    if ($saved.DisplayName -cne $DisplayName) { throw 'Display name read-back verification failed.' }
    $result = [PSCustomObject]@{
        ScriptVersion = '1.2.0'
        Name = $saved.Name
        DisplayName = $saved.DisplayName
        DistinguishedName = $saved.DistinguishedName
        DomainController = $DC
        TemplateOID = $newOid
        SchemaVersion = $schemaVersion
        CACompatibility = $CACompatibility
        RecipientCompatibility = $RecipientCompatibility
        ProviderCategory = $ProviderCategory
        ProviderSelection = $ProviderSelection
        Providers = @(Get-StringValues $Provider)
        Algorithm = $Algorithm
        KeyPurpose = $(if ($isEcdh) { 'Encryption (key agreement)' } elseif ($isEcdsa) { 'Signature' } else { 'Source settings' })
        MinimumKeySize = $MinimumKeySize
        RequestHash = $(if ($isKsp) { $RequestHash } else { 'Determined by CSP' })
        ValidityDays = $validity.TotalDays
        RenewalDays = $renewal.TotalDays
        SubjectNameMode = $SubjectNameMode
        ReuseSubjectOnRenewal = $ReuseSubjectOnRenewal
        SubjectNameFormat = $SubjectNameFormat
        SubjectAlternativeName = @(Get-StringValues $SubjectAlternativeName)
        RequireManagerApproval = $RequireManagerApproval
        AllowPrivateKeyExport = $AllowPrivateKeyExport
        ApplicationPolicies = @(Get-StringValues (Get-AttributeValue $saved 'msPKI-Certificate-Application-Policy'))
        EnrollmentGroups = @(Get-StringValues $EnrollmentGroup)
        EnrollmentPermission = $EnrollmentPermission
        InheritanceBlocked = $savedSecurity.AreAccessRulesProtected
        Verified = $true
        Published = $false
        PublicationStatus = 'NotRequested'
        PublicationError = $null
        PublicationCA = $null
    }
}
catch {
    $failure = $_
    # These object references were returned by this run's successful creates.
    if ($null -ne $createdTemplate) {
        try { Remove-ADObject -Server $DC -Identity $createdTemplate.ObjectGUID -Confirm:$false -ErrorAction Stop }
        catch { Write-Warning "Template cleanup failed: $($_.Exception.Message). Inspect $targetDN." }
    }
    if ($null -ne $createdOid) {
        try { Remove-ADObject -Server $DC -Identity $createdOid.ObjectGUID -Confirm:$false -ErrorAction Stop }
        catch { Write-Warning "OID cleanup failed: $($_.Exception.Message). Inspect $($createdOid.DistinguishedName)." }
    }
    throw $failure
}

# Publication is deliberately outside the creation/rollback block.
# A valid AD template remains available if CA publication fails or is declined.
if ($Publish) {
    $result.PublicationCA = "$env:COMPUTERNAME\$localCAName"
    $result.PublicationStatus = 'Skipped'
    if ($PSCmdlet.ShouldProcess($result.PublicationCA, "Refresh template discovery and publish certificate template $Name")) {
        try {
            # A successful exit alone is insufficient: unforced ADTemplate may
            # return zero with no matching template. Refresh discovery and require
            # a matching name before adding the template to the CA issuance list.
            $namePattern = '(?im)^\s*' + [regex]::Escape($Name) + ':\s'
            Write-Verbose "Refreshing AD template discovery for $Name."
            $discoveryOutput = @(& $certutilPath -f -ADTemplate $Name 2>&1)
            $discoveryExitCode = $LASTEXITCODE
            $discoveryText = $discoveryOutput -join [Environment]::NewLine
            Write-Verbose $discoveryText
            if ($discoveryExitCode -ne 0 -or $discoveryText -notmatch $namePattern) {
                throw "Forced AD template discovery did not confirm '$Name' (exit $discoveryExitCode): $discoveryText"
            }

            # Pass arguments directly; never build a shell command from user input.
            $publishOutput = @(& $certutilPath -config $result.PublicationCA -SetCATemplates "+$Name" 2>&1)
            $publishExitCode = $LASTEXITCODE
            Write-Verbose ($publishOutput -join [Environment]::NewLine)
            if ($publishExitCode -ne 0) {
                throw "certutil -SetCATemplates failed (exit $publishExitCode): $($publishOutput -join ' ')"
            }
            $verifyOutput = @(& $certutilPath -config $result.PublicationCA -CATemplates $Name 2>&1)
            $verifyExitCode = $LASTEXITCODE
            $verifyText = $verifyOutput -join [Environment]::NewLine
            Write-Verbose $verifyText
            # Match the internal name, not localized success messages. An Auto-Enroll
            # Access is denied annotation does not mean publication has failed.
            if ($verifyExitCode -ne 0 -or $verifyText -notmatch $namePattern) {
                throw "Publication could not be confirmed by certutil -CATemplates (exit $verifyExitCode): $verifyText"
            }
            $result.Published = $true
            $result.PublicationStatus = 'Succeeded'
        }
        catch {
            $result.PublicationStatus = 'Failed'
            $result.PublicationError = $_.Exception.Message
            Write-Warning "Template '$Name' was created and verified in AD, but publication failed or could not be confirmed: $($_.Exception.Message). The template and OID were retained. Check CA state and AD replication before retrying publication."
        }
    }
}
$result

#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Imports an exported JSON configuration as a NEW AD certificate template.
.DESCRIPTION
Version 1.1.0. Requires the companion .psm1 in the same directory and Windows
PowerShell 5.1. Never overwrites templates; always creates a new OID registration.
Raw configuration values (including binary durations and crypto settings) are
retained. Identity, AD system fields, revision, minor revision and publication
state are not restored. This is a clone/import tool, NOT disaster recovery.

Default permissions come from a destination template, WebServer by default.
Preserve mode is explicit and restricted to the original forest identity.
Owner and SACL are never imported. New enrollment groups are optional/additive.
Superseded-template references are omitted unless explicitly requested.
Custom policy OIDs must already be registered in the destination; their OID
registrations and semantics are not automatically migrated.

On creation/read-back failure, attempts to delete objects created by this run.
Publication happens afterwards and failure retains the verified AD objects.
Publication errors return a warning and PublicationStatus Failed; callers must
check that field. No automatic retry. WhatIf never creates/publishes/installs.
.PARAMETER Path
Input JSON exported by Export-ADCertificateTemplate (maximum 1 MiB).
.PARAMETER Name
New unique internal template name, required even when importing to another forest.
.PARAMETER DisplayName
Optional new display name. Default: exported display name plus ' (Imported)'.
.PARAMETER PermissionMode
TargetBaseline (default): destination baseline DACL. Preserve: exported DACL,
only when source/destination Configuration object GUIDs match.
.PARAMETER PermissionTemplate
Destination baseline template, used only with TargetBaseline. Default WebServer.
.PARAMETER EnrollmentGroup
Destination AD groups to receive Read + Enroll (and optional Autoenroll).
.PARAMETER EnrollmentPermission
Enroll (default) or EnrollAndAutoenroll. Requires EnrollmentGroup if specified.
.PARAMETER IncludeSupersededTemplates
Retain exported supersedence references after verifying destination names exist.
.PARAMETER Server
Optional destination writable DC; otherwise automatically discovered.
.PARAMETER Publish
Publish on the local enterprise CA using forced certutil discovery and verification.
.EXAMPLE
.\Import-ADCertificateTemplate.ps1 -Path .\WebServer.json -Name MWWebImported -WhatIf
.EXAMPLE
.\Import-ADCertificateTemplate.ps1 -Path .\WebServer.json -Name MWWebImported -PermissionMode Preserve -Publish
.EXAMPLE
.\Import-ADCertificateTemplate.ps1 -Path .\WebServer.json -Name ProdWeb -PermissionTemplate WebServer -EnrollmentGroup GG-PKI-WebServer-Enroll
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z][A-Za-z0-9_-]{0,63}$')][string]$Name,
    [ValidateNotNullOrEmpty()][string]$DisplayName,
    [ValidateSet('TargetBaseline','Preserve')][string]$PermissionMode = 'TargetBaseline',
    [ValidateNotNullOrEmpty()][string]$PermissionTemplate = 'WebServer',
    [ValidateNotNullOrEmpty()][string[]]$EnrollmentGroup,
    [ValidateSet('Enroll','EnrollAndAutoenroll')][string]$EnrollmentPermission = 'Enroll',
    [switch]$IncludeSupersededTemplates,
    [string]$Server,
    [switch]$Publish
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ADCertificateTemplate.Portability.psm1') -Force -ErrorAction Stop -Verbose:$false
$fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
if (-not [IO.File]::Exists($fullPath)) { throw "Input file not found: $fullPath" }
if ((Get-Item -LiteralPath $fullPath).Length -gt 1048576) { throw 'Input JSON exceeds the 1 MiB limit.' }
$inputBytes = [IO.File]::ReadAllBytes($fullPath)
$sha256 = [Security.Cryptography.SHA256]::Create()
try { $inputHash = [BitConverter]::ToString($sha256.ComputeHash($inputBytes)).Replace('-','') }
finally { $sha256.Dispose() }
$jsonText = [Text.Encoding]::UTF8.GetString($inputBytes).TrimStart([char]0xFEFF)
$configuration = ConvertFrom-Json $jsonText
if ((Get-CTProperty $configuration 'Format') -cne 'ADCertificateTemplate.Configuration' -or
    (Get-CTProperty $configuration 'FormatVersion') -cne '1.0') { throw 'Unsupported configuration format/version.' }
$attributes = ConvertFrom-CTAttributes (Get-CTProperty $configuration 'Attributes')
$source = Get-CTProperty $configuration 'Source'
if ($null -eq $source) { throw 'Source metadata is missing.' }
$sourceForest = [guid](Get-CTProperty $source 'ForestIdentity')
if ($sourceForest -eq [guid]::Empty) { throw 'Source forest identity is missing/empty.' }
if (-not $DisplayName) {
    $sourceDisplayName = [string](Get-CTProperty $source 'DisplayName')
    if ([string]::IsNullOrWhiteSpace($sourceDisplayName)) { throw 'Specify DisplayName; source display name is missing.' }
    $DisplayName = "$sourceDisplayName (Imported)"
}
if (-not $EnrollmentGroup -and $PSBoundParameters.ContainsKey('EnrollmentPermission')) {
    throw 'EnrollmentPermission requires EnrollmentGroup.'
}
if ($PermissionMode -eq 'Preserve' -and $PSBoundParameters.ContainsKey('PermissionTemplate')) {
    throw 'PermissionTemplate only applies to TargetBaseline mode.'
}
$ca = $null
if ($Publish) { $ca = Get-CTLocalCA }
$context = Initialize-CTDirectory -Server $Server -CallingCmdlet $PSCmdlet
if ($null -eq $context) { return }
if (Get-CTTemplate -Context $context -Name $Name -Optional) { throw "Template '$Name' already exists. No objects were created." }

if ($PermissionMode -eq 'Preserve') {
    if ($sourceForest -ne [guid]$context.ForestIdentity) {
        throw 'Preserve permissions is limited to the same forest. Use TargetBaseline and destination enrollment groups for another forest.'
    }
    $permissions = Get-CTProperty $configuration 'Permissions'
    $encodedDacl = Get-CTProperty $permissions 'DaclDescriptorBase64'
    if ($encodedDacl -isnot [string] -or [string]::IsNullOrWhiteSpace($encodedDacl)) { throw 'Exported DACL descriptor is missing.' }
    $security = [System.DirectoryServices.ActiveDirectorySecurity]::new()
    $security.SetSecurityDescriptorBinaryForm([Convert]::FromBase64String($encodedDacl),
        [System.Security.AccessControl.AccessControlSections]::Access)
    if ($security.Access.Count -eq 0) { throw 'Exported DACL is empty; refusing import.' }
}
else {
    $baseline = Get-CTTemplate -Context $context -Name $PermissionTemplate
    $security = Get-CTSecurity -Context $context -DistinguishedName $baseline.DistinguishedName
    if ($security.Access.Count -eq 0) { throw 'Destination baseline DACL is empty.' }
}
Add-CTEnrollmentRules -Context $context -Security $security -Group $EnrollmentGroup -Permission $EnrollmentPermission

$superseded = @()
if ($attributes.ContainsKey('msPKI-Supersede-Templates')) {
    if ($IncludeSupersededTemplates) {
        $superseded = @($attributes['msPKI-Supersede-Templates'])
        foreach ($dependency in $superseded) {
            if ($dependency -ieq $Name) { throw 'A template cannot supersede itself.' }
            $null = Get-CTTemplate -Context $context -Name $dependency
        }
    }
    else {
        Write-Warning 'Exported superseded-template references were omitted. Use IncludeSupersededTemplates after reviewing destination references.'
        $attributes.Remove('msPKI-Supersede-Templates')
    }
}
Assert-CTPolicyDependencies -Context $context -Attributes $attributes
$identity = New-CTIdentity $context
# Never reuse the original template identity or revision counters.
$attributes['flags'] = [int]$attributes['flags'] -band (-bnot 0x00010000)
$attributes['msPKI-Cert-Template-OID'] = $identity.OID
$attributes['revision'] = 1
$attributes['msPKI-Template-Minor-Revision'] = 0
$targetDN = "CN=$Name,$($context.TemplateContainer)"
Write-Verbose "Prepared import '$Name'; permission mode $PermissionMode; a fresh template OID will be assigned."
if (-not $PSCmdlet.ShouldProcess($targetDN,'Import configuration as a new template and OID; apply and verify permissions')) {
    if ($Publish -and $WhatIfPreference) { $null = $PSCmdlet.ShouldProcess($ca.Config,"Publish imported template $Name") }
    return
}
$createdOID = $null
$createdTemplate = $null
try {
    $createdOID = New-ADObject -Server $context.DC -Name $identity.ObjectName -Path $context.OIDContainer `
        -Type 'msPKI-Enterprise-Oid' -DisplayName $DisplayName `
        -OtherAttributes @{'msPKI-Cert-Template-OID'=$identity.OID; 'flags'=1} -PassThru -Confirm:$false -ErrorAction Stop
    $createdTemplate = New-ADObject -Server $context.DC -Name $Name -Path $context.TemplateContainer `
        -Type pKICertificateTemplate -DisplayName $DisplayName -OtherAttributes $attributes `
        -PassThru -Confirm:$false -ErrorAction Stop
    $entry = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$($context.DC)/$targetDN")
    try {
        $entry.PSBase.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
        $entry.PSBase.RefreshCache(@('ntSecurityDescriptor'))
        $targetSecurity = $entry.PSBase.ObjectSecurity
        $targetSecurity.SetSecurityDescriptorBinaryForm($security.GetSecurityDescriptorBinaryForm(),
            [System.Security.AccessControl.AccessControlSections]::Access)
        $entry.PSBase.ObjectSecurity = $targetSecurity
        $entry.PSBase.CommitChanges()
    }
    finally { $entry.PSBase.Dispose() }
    $savedSecurity = Get-CTSecurity -Context $context -DistinguishedName $targetDN
    if (-not (Test-CTDacl -Expected $security -Actual $savedSecurity)) { throw 'Imported DACL verification failed. See verbose output.' }
    $saved = Get-CTTemplate -Context $context -Name $Name
    foreach ($attribute in $attributes.Keys) {
        if (-not (Test-CTAttribute -Expected $attributes[$attribute] -Actual (Get-CTProperty $saved $attribute))) {
            throw "Read-back verification failed for $attribute."
        }
    }
    if ($saved.DisplayName -cne $DisplayName) { throw 'Display name verification failed.' }
    $result = [PSCustomObject]@{
        ImporterVersion = '1.1.0'
        Name = $saved.Name
        DisplayName = $saved.DisplayName
        DomainController = $context.DC
        SourceTemplate = Get-CTProperty $source 'Name'
        SourceTemplateOID = Get-CTProperty $source 'TemplateOID'
        TemplateOID = $identity.OID
        ConfigurationSHA256 = $inputHash
        PermissionMode = $PermissionMode
        PermissionTemplate = $(if ($PermissionMode -eq 'TargetBaseline') { $PermissionTemplate } else { $null })
        EnrollmentGroups = @(Get-CTStrings $EnrollmentGroup)
        SupersededTemplates = $superseded
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
    if ($null -ne $createdTemplate) {
        try { Remove-ADObject -Server $context.DC -Identity $createdTemplate.ObjectGUID -Confirm:$false -ErrorAction Stop }
        catch { Write-Warning "Template cleanup failed: $targetDN. $($_.Exception.Message)" }
    }
    if ($null -ne $createdOID) {
        try { Remove-ADObject -Server $context.DC -Identity $createdOID.ObjectGUID -Confirm:$false -ErrorAction Stop }
        catch { Write-Warning "OID cleanup failed: $($createdOID.DistinguishedName). $($_.Exception.Message)" }
    }
    throw $failure
}
if ($Publish) {
    $result.PublicationCA = $ca.Config
    $result.PublicationStatus = 'Skipped'
    if ($PSCmdlet.ShouldProcess($ca.Config,"Refresh discovery and publish imported template $Name")) {
        try {
            Publish-CTTemplate -CA $ca -Name $Name
            $result.Published = $true
            $result.PublicationStatus = 'Succeeded'
        }
        catch {
            $result.PublicationStatus = 'Failed'
            $result.PublicationError = $_.Exception.Message
            Write-Warning "Import verified, but publication failed: $($_.Exception.Message). AD objects were retained."
        }
    }
}
$result

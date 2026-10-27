#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Exports a custom AD CS certificate template to a typed, reviewable JSON file.
.DESCRIPTION
Version 1.2.0. Initial scope: custom schema 2/3/4 RSA and schema 3/4 ECDSA/ECDH P-256/P-384/P-521 templates, including those
created with New-ADCertificateTemplate. Exports configuration and a DACL snapshot;
no certificates/private keys and no CA publication state. Source identity/OID
and revisions are metadata only. Unknown populated PKI attributes cause a stop.
The companion .psm1 must be in the same directory. Use Windows PowerShell 5.1.
Missing AD tools can be installed automatically. WhatIf never installs/writes.
.PARAMETER TemplateName
Internal template name in AD, not its display name.
.PARAMETER Path
Output JSON path. Parent directory must exist. Existing files require Force.
.PARAMETER Server
Optional writable DC override; otherwise automatically discovered.
.PARAMETER Force
Allow overwriting the specified output JSON file.
.EXAMPLE
.\Export-ADCertificateTemplate.ps1 -TemplateName MWWebServerProd -Path .\WebServer.json
.EXAMPLE
.\Export-ADCertificateTemplate.ps1 -TemplateName MWWebServerProd -Path .\WebServer.json -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$TemplateName,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path,
    [string]$Server,
    [switch]$Force
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ADCertificateTemplate.Portability.psm1') -Force -ErrorAction Stop -Verbose:$false
$fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
if ([IO.Path]::GetExtension($fullPath) -ine '.json') { throw 'Use a .json output file.' }
if (-not [IO.Directory]::Exists([IO.Path]::GetDirectoryName($fullPath))) { throw 'Output parent directory does not exist.' }
if ([IO.File]::Exists($fullPath) -and -not $Force) { throw "File already exists: $fullPath. Use -Force to replace it." }
$context = Initialize-CTDirectory -Server $Server -CallingCmdlet $PSCmdlet
if ($null -eq $context) { return }
$template = Get-CTTemplate -Context $context -Name $TemplateName
$encoded = ConvertTo-CTAttributes $template
# Validate the same schema that import uses before offering an export.
$attributeObject = ConvertFrom-Json (ConvertTo-Json -InputObject $encoded -Depth 8)
$decoded = ConvertFrom-CTAttributes $attributeObject
$security = Get-CTSecurity -Context $context -DistinguishedName $template.DistinguishedName
$permissions = ConvertTo-CTPermissionRecord $security
$validityTicks = [BitConverter]::ToInt64([byte[]]$decoded['pKIExpirationPeriod'],0)
$renewalTicks = [BitConverter]::ToInt64([byte[]]$decoded['pKIOverlapPeriod'],0)
$schema = [int]$decoded['msPKI-Template-Schema-Version']
$privateFlags = [int]$decoded['msPKI-Private-Key-Flag']
$legacy = ($schema -eq 2) -or (($privateFlags -band 0x100) -ne 0)
$crypto = Get-CTCryptography -Attributes $decoded
$configuration = [ordered]@{
    Format = 'ADCertificateTemplate.Configuration'
    FormatVersion = '1.0'
    ExporterVersion = '1.2.0'
    ExportedAtUtc = [datetime]::UtcNow.ToString('o')
    Source = [ordered]@{
        Name = $template.Name
        DisplayName = [string]$template.DisplayName
        ForestIdentity = $context.ForestIdentity
        ConfigurationDN = $context.ConfigurationDN
        DomainController = $context.DC
        ObjectGUID = ([guid]$template.ObjectGUID).ToString('D')
        TemplateOID = [string](Get-CTProperty $template 'msPKI-Cert-Template-OID')
        Revision = Get-CTProperty $template 'revision'
        MinorRevision = Get-CTProperty $template 'msPKI-Template-Minor-Revision'
    }
    # Informational only; Attributes is the authoritative configuration on import.
    SummaryForReview = [ordered]@{
        SchemaVersion = $schema
        ProviderCategory = $(if ($legacy) { 'Legacy Cryptographic Service Provider' } else { 'Key Storage Provider' })
        Algorithm = $crypto.Algorithm
        RequestHash = $crypto.RequestHash
        MinimumKeySize = [int]$decoded['msPKI-Minimal-Key-Size']
        ValidityDays = [TimeSpan]::FromTicks(-$validityTicks).TotalDays
        RenewalDays = [TimeSpan]::FromTicks(-$renewalTicks).TotalDays
        Providers = @(Get-CTStrings $decoded['pKIDefaultCSPs'])
        ApplicationPolicies = @(Get-CTStrings $decoded['msPKI-Certificate-Application-Policy'])
    }
    Attributes = $encoded
    Permissions = $permissions
}
$json = ConvertTo-Json -InputObject $configuration -Depth 12
if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 1048574) { throw 'Export would exceed the import format size limit.' }
if (-not $PSCmdlet.ShouldProcess($fullPath,"Export template '$TemplateName' configuration and DACL snapshot")) { return }
$mode = [IO.FileMode]::CreateNew
if ($Force) { $mode = [IO.FileMode]::Create }
$stream = [IO.File]::Open($fullPath,$mode,[IO.FileAccess]::Write,[IO.FileShare]::None)
try {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + [Environment]::NewLine)
    $stream.Write($bytes,0,$bytes.Length)
}
finally { $stream.Dispose() }
[PSCustomObject]@{
    ExporterVersion = '1.2.0'
    Template = $template.Name
    Path = $fullPath
    SHA256 = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash
    SchemaVersion = $schema
    ExportedAttributes = $encoded.Count
    IncludesDaclSnapshot = $true
    IncludesPrivateKeys = $false
}

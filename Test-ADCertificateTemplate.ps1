#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Runs ONE of ten lab scenarios for New-ADCertificateTemplate v1.1.0.
.DESCRIPTION
Release 1.1.0. Default is a dry run (-WhatIf). Add -Create for actual creation. Names must be
unique: use a fresh RunId when repeating a successful scenario. Publication
occurs only in scenario 10 with -Create, on the local enterprise CA.
No CA role is installed and existing templates are never deleted by this runner.
.EXAMPLE
.\Test-ADCertificateTemplate.ps1 -TestNumber 1
.EXAMPLE
.\Test-ADCertificateTemplate.ps1 -TestNumber 1 -Create
.EXAMPLE
.\Test-ADCertificateTemplate.ps1 -TestNumber 7 -ComputerEnrollmentGroup 'GG-Lab-Certificate-Computers' -Create
.EXAMPLE
.\Test-ADCertificateTemplate.ps1 -TestNumber 2 -RunId R02 -Create
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateRange(1,10)][int]$TestNumber,
    [ValidatePattern('^[A-Za-z0-9_-]{1,20}$')][string]$RunId = 'R01',
    [ValidateNotNullOrEmpty()][string]$EnrollmentGroup = 'GG-T0-Admins',
    [string]$ComputerEnrollmentGroup,
    [string]$ScriptPath = (Join-Path $PSScriptRoot 'New-ADCertificateTemplate.ps1'),
    [switch]$Create
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) { throw "Script not found: $ScriptPath" }
$number = '{0:D2}' -f $TestNumber
$settings = @{
    Name = "MWT${number}_$RunId"
    DisplayName = "MW Test $number $RunId"
    EnrollmentGroup = $EnrollmentGroup
}
$expected = ''
switch ($TestNumber) {
    1 {
        $expected = 'Defaults: schema 4; CA 2012 R2; Windows 10; KSP/any; RSA3072/SHA256; 365 days; supply; approval/export/reuse off; Server Authentication.'
    }
    2 {
        $settings.ProviderSelection = 'SelectedProviders'
        $settings.Provider = 'Microsoft Software Key Storage Provider'
        $settings.ApplicationPolicy = 'Client Authentication'
        $expected = 'KSP; only Software KSP; RSA3072/SHA256; Server + Client Authentication; supply in request.'
    }
    3 {
        $settings.ProviderCategory = 'Legacy Cryptographic Service Provider'
        $expected = 'Legacy CSP; any available provider; request hash Determined by CSP; schema 4; compatibility retained.'
    }
    4 {
        $settings.ProviderCategory = 'Legacy Cryptographic Service Provider'
        $settings.ProviderSelection = 'SelectedProviders'
        $settings.Provider = 'Microsoft Enhanced RSA and AES Cryptographic Provider'
        $settings.CACompatibility = 'Windows Server 2003'
        $settings.RecipientCompatibility = 'Windows XP / Windows Server 2003'
        $settings.MinimumKeySize = 2048
        $expected = 'Schema 2; CA2003/XP; selected Enhanced RSA and AES CSP; RSA2048; Determined by CSP.'
    }
    5 {
        $settings.CACompatibility = 'Windows Server 2008'
        $settings.RecipientCompatibility = 'Windows Vista / Windows Server 2008'
        $settings.ProviderSelection = 'SelectedProviders'
        $settings.Provider = 'Microsoft Software Key Storage Provider'
        $settings.MinimumKeySize = 2048
        $expected = 'Schema 3; CA2008/Vista; Software KSP; RSA2048/SHA256.'
    }
    6 {
        $settings.ProviderSelection = 'SelectedProviders'
        $settings.Provider = 'Microsoft Software Key Storage Provider'
        $settings.MinimumKeySize = 4096
        $settings.RequestHash = 'SHA384'
        $settings.ValidityYears = 2
        $settings.RenewalWeeks = 8
        $settings.ReuseSubjectOnRenewal = $true
        $settings.RequireManagerApproval = $true
        $settings.AllowPrivateKeyExport = $true
        $expected = 'Supply + reuse on renewal; RSA4096/SHA384; 730 days; renewal 56 days; approval/export on. New request must pend.'
    }
    7 {
        if ([string]::IsNullOrWhiteSpace($ComputerEnrollmentGroup)) {
            throw 'Scenario 7 requires -ComputerEnrollmentGroup containing the test COMPUTER account.'
        }
        $settings.EnrollmentGroup = $ComputerEnrollmentGroup
        $settings.EnrollmentPermission = 'EnrollAndAutoenroll'
        $settings.SubjectNameMode = 'ActiveDirectory'
        $settings.SubjectNameFormat = 'DNS name'
        $settings.SubjectAlternativeName = 'DNS name'
        $settings.ProviderSelection = 'SelectedProviders'
        $settings.Provider = 'Microsoft Software Key Storage Provider'
        $settings.ApplicationPolicy = 'Client Authentication'
        $settings.RenewalWeeks = 6
        $expected = 'Computer: AD DNS subject + DNS SAN; Read/Enroll/Autoenroll for computer group; Server + Client Authentication. Autoenrollment also requires GPO.'
    }
    8 {
        $settings.SourceTemplate = 'User'
        $settings.SubjectNameMode = 'ActiveDirectory'
        $settings.SubjectNameFormat = 'Common name'
        $settings.SubjectAlternativeName = 'UPN'
        $settings.ApplicationPolicy = 'Client Authentication'
        $expected = 'Source User: AD Common name subject + UPN SAN; original User EKUs retained; Client Authentication present once. Enroll in current-user context with a user that has UPN.'
    }
    9 {
        $settings.CACompatibility = 'Windows Server 2012'
        $settings.RecipientCompatibility = 'Windows 8 / Windows Server 2012'
        $settings.MinimumKeySize = 4096
        $settings.RequestHash = 'SHA512'
        $settings.ValidityYears = 3
        $settings.RenewalWeeks = 8
        $settings.ApplicationPolicy = @('Client Authentication','1.3.6.1.5.5.7.3.2','Code Signing')
        $expected = 'Schema 4; CA2012/Windows8; RSA4096/SHA512; 1095 days; renewal56; Server + Client + Code Signing, no duplicate Client OID. Mixed-purpose lab test only.'
    }
    10 {
        $settings.ProviderSelection = 'SelectedProviders'
        $settings.Provider = 'Microsoft Software Key Storage Provider'
        $settings.ApplicationPolicy = 'Client Authentication'
        $settings.Publish = $true
        $expected = 'Run on local issuing enterprise CA: missing tools installed if needed; AD template verified; PublicationStatus Succeeded; Published True; visible on CA.'
    }
}
Write-Host "Scenario $number; template $($settings.Name)" -ForegroundColor Cyan
Write-Host "Expected: $expected"
if ($Create) {
    & $ScriptPath @settings -Verbose
}
else {
    & $ScriptPath @settings -WhatIf -Verbose
}

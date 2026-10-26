#Requires -Version 5.1
<#
.SYNOPSIS
Local format/DACL regression checks. No AD access, installs or template writes.
.DESCRIPTION
Run in Windows PowerShell 5.1. These tests do NOT establish live AD import,
cross-forest or certificate-enrollment correctness. A failed assertion terminates.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -ne 'Desktop') { throw 'Run in Windows PowerShell 5.1.' }
Import-Module (Join-Path $PSScriptRoot 'ADCertificateTemplate.Portability.psm1') -Force -ErrorAction Stop -Verbose:$false
$script:passed = 0
function Assert-Test {
    param([bool]$Condition,[string]$Name)
    if (-not $Condition) { throw "FAILED: $Name" }
    $script:passed++
    Write-Host "PASS: $Name" -ForegroundColor Green
}
function Assert-Throws {
    param([scriptblock]$Action,[string]$Name)
    $caught = $false
    try { & $Action | Out-Null } catch { $caught = $true }
    Assert-Test $caught $Name
}
function Copy-JsonObject {
    param($Value)
    ConvertFrom-Json (ConvertTo-Json -InputObject $Value -Depth 12)
}
# Known value captured from a custom template created through certtmpl.msc.
$knownOID = '1.3.6.1.4.1.311.21.8.11065154.9939449.10308263.13356538.12837965.3.5086035.6190214'
$expectedOIDName = '6190214.3DB1FB8636D8C77B77AB439D9EF9FC4F'
Assert-Test ((Get-CTOIDObjectName -OID $knownOID) -ceq $expectedOIDName) 'OID CN matches the UI-created template (UTF-16LE, no terminator)'
Assert-Throws { Get-CTOIDObjectName -OID 'not-an-oid' } 'Invalid OID rejected before naming'

$fixture = [PSCustomObject]@{
    Name = 'ExampleOnly'
    'flags' = 577
    'msPKI-Template-Schema-Version' = 4
    'msPKI-Template-Minor-Revision' = 12
    'msPKI-Cert-Template-OID' = '1.3.6.1.4.1.311.21.8.1.2.3'
    'msPKI-Minimal-Key-Size' = 3072
    'msPKI-Private-Key-Flag' = 0x06050010
    'msPKI-Enrollment-Flag' = 2
    'msPKI-Certificate-Name-Flag' = -2147483648
    'pKIKeyUsage' = [byte[]]@(160,0)
    'pKIExpirationPeriod' = [BitConverter]::GetBytes([long](-[TimeSpan]::FromDays(365).Ticks))
    'pKIOverlapPeriod' = [BitConverter]::GetBytes([long](-[TimeSpan]::FromDays(42).Ticks))
    'pKIDefaultCSPs' = @('1,Microsoft Software Key Storage Provider')
    'pKIExtendedKeyUsage' = @('1.3.6.1.5.5.7.3.1','1.3.6.1.5.5.7.3.2')
    'msPKI-Certificate-Application-Policy' = @('1.3.6.1.5.5.7.3.1','1.3.6.1.5.5.7.3.2')
    'msPKI-RA-Application-Policies' = @('msPKI-Asymmetric-Algorithm`PZPWSTR`RSA`msPKI-Hash-Algorithm`PZPWSTR`SHA256`msPKI-Key-Usage`DWORD`3`')
}
$wrappedBinary = ,([byte[]]@(160,0))
Assert-Test (Test-CTAttribute -Expected ([byte[]]@(160,0)) -Actual $wrappedBinary) 'Wrapped binary attribute handled without changing bytes'
$encoded = ConvertTo-CTAttributes $fixture
$json = Copy-JsonObject $encoded
$decoded = ConvertFrom-CTAttributes $json
foreach ($name in $decoded.Keys) {
    Assert-Test (Test-CTAttribute -Expected (Get-CTProperty $fixture $name) -Actual $decoded[$name]) "Typed round-trip: $name"
}
Assert-Test (-not $encoded.Contains('msPKI-Cert-Template-OID')) 'Source OID cannot become an imported attribute'
Assert-Test (-not $encoded.Contains('msPKI-Template-Minor-Revision')) 'Source revision counter is metadata only'
Assert-Test ($decoded['msPKI-Certificate-Name-Flag'] -eq [int]::MinValue) 'Signed flag high bit preserved'
Assert-Test ($decoded['pKIDefaultCSPs'] -is [string[]] -and $decoded['pKIDefaultCSPs'].Count -eq 1) 'Single provider remains a string array'
Assert-Test (Test-CTAttribute -Expected @('b','a') -Actual @('a','b')) 'Unordered policy comparison'
Assert-Test (-not (Test-CTAttribute -Expected @('a','b') -Actual @('a'))) 'Missing policy is detected'
Assert-Test (-not (Test-CTAttribute -Expected ([byte[]]@(160,0)) -Actual ([byte[]]@(128,0)))) 'Changed key usage is detected'

$bad = Copy-JsonObject $json
$bad | Add-Member -NotePropertyName nTSecurityDescriptor -NotePropertyValue ([PSCustomObject]@{Type='Binary';Value='AA=='})
Assert-Throws { ConvertFrom-CTAttributes $bad } 'Arbitrary security attribute rejected'
$bad = Copy-JsonObject $json
$bad.'pKIExpirationPeriod'.Value = '!invalid!'
Assert-Throws { ConvertFrom-CTAttributes $bad } 'Invalid Base64 rejected'
$bad = Copy-JsonObject $json
$bad.'pKIExpirationPeriod'.Value = 'AA=='
Assert-Throws { ConvertFrom-CTAttributes $bad } 'Truncated validity interval rejected'
$bad = Copy-JsonObject $json
$bad.'pKIOverlapPeriod'.Value = $bad.'pKIExpirationPeriod'.Value
Assert-Throws { ConvertFrom-CTAttributes $bad } 'Renewal >= validity rejected'
$bad = Copy-JsonObject $json
$bad.'msPKI-Template-Schema-Version'.Value = 1
Assert-Throws { ConvertFrom-CTAttributes $bad } 'Built-in schema 1 import rejected'
$bad = Copy-JsonObject $json
$bad.'msPKI-Private-Key-Flag'.Type = 'StringArray'
Assert-Throws { ConvertFrom-CTAttributes $bad } 'Type substitution rejected'
$bad = Copy-JsonObject $json
$bad.'msPKI-Minimal-Key-Size'.Value = '3072'
Assert-Throws { ConvertFrom-CTAttributes $bad } 'Numeric string rejected'
$bad = Copy-JsonObject $json
$bad.'pKIExtendedKeyUsage'.Value = @('1.2.3','1.2.3')
Assert-Throws { ConvertFrom-CTAttributes $bad } 'Duplicate values rejected'
$bad = Copy-JsonObject $json
$bad.'msPKI-RA-Application-Policies'.Value = @('msPKI-Asymmetric-Algorithm`PZPWSTR`ECDSA_P256`')
Assert-Throws { ConvertFrom-CTAttributes $bad } 'ECC configuration outside initial scope rejected'
$unsupported = Copy-JsonObject $fixture
$unsupported | Add-Member -NotePropertyName 'msPKI-Unhandled-Setting' -NotePropertyValue 1
Assert-Throws { ConvertTo-CTAttributes $unsupported } 'Unknown populated PKI field cannot be silently dropped'

$acl1 = [System.DirectoryServices.ActiveDirectorySecurity]::new()
$acl2 = [System.DirectoryServices.ActiveDirectorySecurity]::new()
$acl1.SetSecurityDescriptorSddlForm('D:P(A;;GR;;;AU)(A;;GA;;;SY)')
$acl2.SetSecurityDescriptorSddlForm('D:P(A;;GA;;;SY)(A;;GR;;;AU)')
Assert-Test (Test-CTDacl -Expected $acl1 -Actual $acl2) 'Allow ACE order does not cause false mismatch'
$acl2.SetSecurityDescriptorSddlForm('D:P(A;;GW;;;AU)(A;;GA;;;SY)')
Assert-Test (-not (Test-CTDacl -Expected $acl1 -Actual $acl2)) 'Changed ACL rights detected'
$acl2.SetSecurityDescriptorSddlForm('D:(A;;GR;;;AU)(A;;GA;;;SY)')
Assert-Test (-not (Test-CTDacl -Expected $acl1 -Actual $acl2)) 'Changed inheritance protection detected'

[PSCustomObject]@{ Passed = $script:passed; Failed = 0; LiveADTestsPerformed = $false }

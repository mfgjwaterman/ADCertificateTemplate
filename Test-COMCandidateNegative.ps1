#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Checks integrated COM 0.2.0 validation and collision guards with no Commit requested.
.DESCRIPTION
Place beside the COM 0.2.0 commands/module. Reads a known-good RSA KSP source and
exports it to a private temporary directory. Every import uses WhatIf; expected
exceptions must match the intended validation message. Compares template and
OID GUID/USN snapshots, and CA publication lists, before/after. No AD cleanup
or mutation is attempted. Does not test denied Commit or partial Commit.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Server,
    [string]$SourceTemplate='COMRC1RSA_R03'
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$importer=Join-Path $PSScriptRoot 'Import-ADCertificateTemplate.ps1'
$exporter=Join-Path $PSScriptRoot 'Export-ADCertificateTemplate.ps1'
foreach ($file in @($importer,$exporter)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {throw "Missing command: $file"}
    if ((Get-Content -LiteralPath $file -Raw) -notmatch '0\.2\.0-COM') {throw "Use the COM 0.2.0 package: $file"}
}
Import-Module ActiveDirectory -ErrorAction Stop
$root=Get-ADRootDSE -Server $Server
$pki="CN=Public Key Services,CN=Services,$($root.configurationNamingContext)"
$templateBase="CN=Certificate Templates,$pki"
$oidBase="CN=OID,$pki"
$caBase="CN=Enrollment Services,$pki"
$source=Get-ADObject -Server $Server -Identity "CN=$SourceTemplate,$templateBase" -Properties displayName
$tag=[guid]::NewGuid().ToString('N').Substring(0,12)
$name="COMNegative_$tag"
$display="COM Negative $tag"
$work=Join-Path ([IO.Path]::GetTempPath()) "COMNegative-$tag"
$null=[IO.Directory]::CreateDirectory($work)
$sourcePath=Join-Path $work 'Source.json'
$casePath=Join-Path $work 'Case.json'
$rows=[Collections.Generic.List[object]]::new()

function Get-NegativeSnapshot {
    param([string]$Base,[switch]$Publication)
    $properties=@('uSNChanged')
    if ($Publication) {$properties+= 'certificateTemplates'}
    $items=@(Get-ADObject -Server $Server -SearchBase $Base -SearchScope OneLevel -Filter * -Properties $properties)
    [string[]]$lines=@(foreach ($item in $items) {
        $line=([string]$item.ObjectGUID)+'|'+([string]$item.uSNChanged)
        if ($Publication) {$line+='|'+(@($item.certificateTemplates | Sort-Object) -join ';')}
        $line
    })
    return (($lines | Sort-Object) -join "`n")
}
function Add-NegativeResult {
    param([string]$Test,[bool]$Passed,[string]$Detail)
    $rows.Add([pscustomobject]@{Test=$Test;Passed=$Passed;Detail=$Detail})
}

$beforeTemplates=Get-NegativeSnapshot $templateBase
$beforeOids=Get-NegativeSnapshot $oidBase
$beforePublication=Get-NegativeSnapshot $caBase -Publication
try {
    & $exporter -Server $Server -TemplateName $SourceTemplate -Path $sourcePath -WhatIf:$false -Confirm:$false | Out-Null
    $original=Get-Content -LiteralPath $sourcePath -Raw
    $baseArgs=@{Server=$Server;Path=$sourcePath;Name=$name;DisplayName=$display;PermissionMode='Preserve'}
    # A valid control must prepare successfully before rejection tests are meaningful.
    & $importer @baseArgs -WhatIf -ErrorAction Stop | Out-Null
    Add-NegativeResult 'Valid source prepares (control)' $true 'WhatIf completed without exception.'

    $cases=@(
        @{Label='Unsupported format';Pattern='Unsupported configuration format/version';Mutate={param($d) $d.Format='Invalid'}},
        @{Label='Unsupported format version';Pattern='Unsupported configuration format/version';Mutate={param($d) $d.FormatVersion='99.0'}},
        @{Label='Unknown attribute';Pattern="Attribute 'UnsupportedAttribute' is not permitted";Mutate={param($d) $d.Attributes | Add-Member NoteProperty UnsupportedAttribute ([pscustomobject]@{Type='Int32';Value=1})}},
        @{Label='Missing required key size';Pattern='Required configuration attribute missing: msPKI-Minimal-Key-Size';Mutate={param($d) $d.Attributes.PSObject.Properties.Remove('msPKI-Minimal-Key-Size')}},
        @{Label='Numeric string';Pattern='msPKI-Minimal-Key-Size must be an integer JSON number';Mutate={param($d) $d.Attributes.'msPKI-Minimal-Key-Size'.Value='3072'}},
        @{Label='Wrong integer type declaration';Pattern='Unexpected type declaration for msPKI-Minimal-Key-Size';Mutate={param($d) $d.Attributes.'msPKI-Minimal-Key-Size'.Type='StringArray'}},
        @{Label='Provider scalar';Pattern='pKIDefaultCSPs must contain a nonempty JSON array';Mutate={param($d) $d.Attributes.pKIDefaultCSPs.Value='1,Microsoft Software Key Storage Provider'}},
        @{Label='Duplicate EKU';Pattern='pKIExtendedKeyUsage contains duplicate values';Mutate={param($d) $v=[string]$d.Attributes.pKIExtendedKeyUsage.Value[0];$d.Attributes.pKIExtendedKeyUsage.Value=@($v,$v)}},
        @{Label='Invalid Base64';Pattern='Invalid Base64 in pKIExpirationPeriod';Mutate={param($d) $d.Attributes.pKIExpirationPeriod.Value='!invalid!'}},
        @{Label='Truncated validity';Pattern='pKIExpirationPeriod must contain exactly eight bytes';Mutate={param($d) $d.Attributes.pKIExpirationPeriod.Value='AA=='}},
        @{Label='Renewal equals validity';Pattern='Renewal period must be shorter than validity';Mutate={param($d) $d.Attributes.pKIOverlapPeriod.Value=$d.Attributes.pKIExpirationPeriod.Value}},
        @{Label='Schema 4 blocked';Pattern='Schema 4 is blocked';Mutate={param($d) $d.Attributes.'msPKI-Template-Schema-Version'.Value=4}},
        @{Label='Policy lists differ';Pattern='requires explicit, matching nonempty EKU and Application Policies';Mutate={param($d) $d.Attributes.'msPKI-Certificate-Application-Policy'.Value=@('1.3.6.1.5.5.7.3.2')}},
        @{Label='Autoenroll ACE without flag';Pattern='Autoenroll ACE present but template autoenrollment flag 0x20 is absent';Auto=$true;Mutate={param($d) $d.Attributes.'msPKI-Enrollment-Flag'.Value=([int]$d.Attributes.'msPKI-Enrollment-Flag'.Value -band (-bnot 32))}}
    )
    foreach ($case in $cases) {
        $doc=$original | ConvertFrom-Json
        & ($case.Mutate) $doc
        [IO.File]::WriteAllText($casePath,($doc | ConvertTo-Json -Depth 30),[Text.UTF8Encoding]::new($false))
        $argsForCase=@{Server=$Server;Path=$casePath;Name=$name;DisplayName=$display;PermissionMode='Preserve'}
        if ($case.ContainsKey('Auto')) {
            $argsForCase.EnrollmentGroup=@('GG-T0-Admins')
            $argsForCase.EnrollmentPermission='EnrollAndAutoenroll'
        }
        $message=$null
        try {& $importer @argsForCase -WhatIf -ErrorAction Stop | Out-Null}
        catch {$message=$_.Exception.Message}
        $passed=$null -ne $message -and $message -match $case.Pattern
        $detail=if ($null -eq $message) {'Unexpectedly accepted.'} else {$message}
        Add-NegativeResult $case.Label $passed $detail
    }
    foreach ($collision in @('Name','DisplayName')) {
        $collisionArgs=@{Server=$Server;Path=$sourcePath;Name=$name;DisplayName=$display;PermissionMode='Preserve'}
        if ($collision -eq 'Name') {$collisionArgs.Name=$SourceTemplate;$pattern='already exists\. No objects were created'}
        else {$collisionArgs.DisplayName=[string]$source.displayName;$pattern='Destination display name exists'}
        $message=$null
        try {& $importer @collisionArgs -WhatIf -ErrorAction Stop | Out-Null}
        catch {$message=$_.Exception.Message}
        $detail=if ($null -eq $message) {'Unexpectedly accepted.'} else {$message}
        Add-NegativeResult "Existing $collision rejected" ($null -ne $message -and $message -match $pattern) $detail
    }
}
finally {
    # Always compare directory state, even if setup/control throws. Never delete AD objects.
    try {
        Add-NegativeResult 'Template GUID/USN snapshot unchanged' ($beforeTemplates -ceq (Get-NegativeSnapshot $templateBase)) 'Includes object set and existing object USNs.'
        Add-NegativeResult 'OID GUID/USN snapshot unchanged' ($beforeOids -ceq (Get-NegativeSnapshot $oidBase)) 'Includes object set and existing object USNs.'
        Add-NegativeResult 'CA publication snapshot unchanged' ($beforePublication -ceq (Get-NegativeSnapshot $caBase -Publication)) 'Includes CA object USNs and template lists.'
    }
    finally {
        # Only this run's local temporary files are removed.
        if ([IO.Directory]::Exists($work)) {[IO.Directory]::Delete($work,$true)}
        $rows | Write-Output
    }
}
$failed=@($rows | Where-Object {-not $_.Passed}).Count
[pscustomobject]@{
    ProbeVersion='0.1.1-ReleaseNegative'
    Passed=@($rows | Where-Object {$_.Passed}).Count
    Failed=$failed
    DirectoryWritesRequested=$false
    CommitPermissionsTested=$false
}
if ($failed -gt 0) {throw "Negative regression failed: $failed check(s). Inspect the returned details."}

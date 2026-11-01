#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Integrated lab smoke test of candidate creator -> original JSON -> COM importer.
.DESCRIPTION
Default is WhatIf only, no AD writes. -Create leaves UNPUBLISHED lab templates.
Four profiles by default; -Extended adds P256/P521 and any-provider RSA.
Use a new RunId per committed run. Stops at first failure; prior successes remain.
-TestRollback with -Create adds one deliberately failed temporary commit/delete.
#>
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='Medium')]
param([string]$Server,[ValidatePattern('^R[0-9]{2,4}$')][string]$RunId='R01',
    [switch]$Create,[switch]$Extended,[switch]$TestRollback,
    [string]$EnrollmentGroup='GG-T0-Admins')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ADCertificateTemplate.Portability.psm1') -Force
Import-Module ActiveDirectory
if (-not $Server) {$Server=[string]((Get-ADDomainController -Discover -Writable).HostName | Select-Object -First 1)}
$root=Get-ADRootDSE -Server $Server
$base="CN=Certificate Templates,CN=Public Key Services,CN=Services,$($root.configurationNamingContext)"
$oidBase="CN=OID,CN=Public Key Services,CN=Services,$($root.configurationNamingContext)"
$before=@(Get-ADObject -Server $Server -SearchBase $base -SearchScope OneLevel -Filter * -Properties uSNChanged)
$cases=@(
    @{Label='RSA';Algorithm='RSA';Bits=3072;Hash='SHA256';Legacy=$false;Any=$false},
    @{Label='ECDSA384';Algorithm='ECDSA_P384';Bits=384;Hash='SHA384';Legacy=$false;Any=$false},
    @{Label='ECDH384';Algorithm='ECDH_P384';Bits=384;Hash='SHA384';Legacy=$false;Any=$false},
    @{Label='Legacy';Algorithm='RSA';Bits=3072;Hash='';Legacy=$true;Any=$false}
)
if ($Extended) {
    $cases+=@(
        @{Label='ECDSA256';Algorithm='ECDSA_P256';Bits=256;Hash='SHA256';Legacy=$false;Any=$false},
        @{Label='ECDSA521';Algorithm='ECDSA_P521';Bits=521;Hash='SHA512';Legacy=$false;Any=$false},
        @{Label='ECDH256';Algorithm='ECDH_P256';Bits=256;Hash='SHA256';Legacy=$false;Any=$false},
        @{Label='ECDH521';Algorithm='ECDH_P521';Bits=521;Hash='SHA512';Legacy=$false;Any=$false},
        @{Label='RSAAny';Algorithm='RSA';Bits=4096;Hash='SHA384';Legacy=$false;Any=$true}
    )
}
# Preflight every name, including import and rollback, before any test mutation.
$destinations=@()
foreach ($case in $cases) {$destinations+="COMRC1$($case.Label)_$RunId";$destinations+="COMRC1Imp$($case.Label)_$RunId"}
if ($TestRollback) {$destinations+="COMRC1Rollback_$RunId"}
foreach ($name in $destinations) {
    if (@(Get-ADObject -Server $Server -SearchBase $base -SearchScope OneLevel -LDAPFilter "(cn=$name)").Count) {throw "Destination exists: $name. Choose a new RunId."}
}
foreach ($case in $cases) {
    $name="COMRC1$($case.Label)_$RunId"
    $p=@{Server=$Server;Name=$name;DisplayName=$name;SourceTemplate='WebServer';
        CACompatibility='Windows Server 2008 R2';RecipientCompatibility='Windows 7 / Windows Server 2008 R2';
        Algorithm=$case.Algorithm;MinimumKeySize=$case.Bits;EnrollmentGroup=$EnrollmentGroup;RenewalWeeks=6}
    if ($case.Legacy) {$p.ProviderCategory='Legacy Cryptographic Service Provider';$p.ProviderSelection='SelectedProviders';$p.Provider=@('Microsoft Enhanced RSA and AES Cryptographic Provider')}
    else {
        $p.RequestHash=$case.Hash
        if ($case.Any) {$p.ProviderSelection='AnyAvailable'}
        else {$p.ProviderSelection='SelectedProviders';$p.Provider=@('Microsoft Software Key Storage Provider')}
    }
    $approved=$false
    if ($Create) {$approved=$PSCmdlet.ShouldProcess($name,'Create and original-JSON roundtrip two unpublished lab templates')}
    if (-not $approved) {
        & (Join-Path $PSScriptRoot 'New-ADCertificateTemplate.ps1') @p -WhatIf
        [pscustomobject]@{Case=$case.Label;Stage='CreatorWhatIf';Name=$name;Verified=$null;Published=$false}
        continue
    }
    $new=& (Join-Path $PSScriptRoot 'New-ADCertificateTemplate.ps1') @p -Confirm:$false
    if ($null -eq $new -or -not $new.Verified) {throw "Creator not verified: $name"}
    [pscustomobject]@{Case=$case.Label;Stage='Create';Name=$new.Name;Verified=$new.Verified;Published=$new.Published}
    $out=Join-Path $PSScriptRoot "$name.json"
    & (Join-Path $PSScriptRoot 'Export-ADCertificateTemplate.ps1') -TemplateName $name -Path $out -Server $Server -Confirm:$false | Out-Null
    $importName="COMRC1Imp$($case.Label)_$RunId"
    $mode=if ($case.Legacy) {'TargetBaseline'} else {'Preserve'}
    $imp=@{Server=$Server;Path=$out;Name=$importName;DisplayName=$importName;PermissionMode=$mode}
    if ($mode -eq 'TargetBaseline') {$imp.PermissionTemplate='WebServer';$imp.EnrollmentGroup=@($EnrollmentGroup)}
    & (Join-Path $PSScriptRoot 'Import-ADCertificateTemplate.ps1') @imp -WhatIf
    $imported=& (Join-Path $PSScriptRoot 'Import-ADCertificateTemplate.ps1') @imp -Confirm:$false
    if ($null -eq $imported -or -not $imported.Verified) {throw "Import not verified: $importName"}
    [pscustomobject]@{Case=$case.Label;Stage='Import';Name=$imported.Name;Verified=$imported.Verified;Published=$imported.Published}
}
if ($Create -and $TestRollback -and $PSCmdlet.ShouldProcess("COMRC1Rollback_$RunId",'Create then deliberately fail verification and delete temporary template/OID')) {
    $context=[pscustomobject]@{DC=$Server;ConfigurationDN=[string]$root.configurationNamingContext;TemplateContainer=$base;OIDContainer=$oidBase}
    $doc=Get-Content (Join-Path $PSScriptRoot "COMRC1RSA_$RunId.json") -Raw | ConvertFrom-Json
    $attrs=ConvertFrom-CTAttributes $doc.Attributes
    $sd=[DirectoryServices.ActiveDirectorySecurity]::new()
    $sd.SetSecurityDescriptorBinaryForm([Convert]::FromBase64String($doc.Permissions.DaclDescriptorBase64),[Security.AccessControl.AccessControlSections]::Access)
    $rollbackName="COMRC1Rollback_$RunId"
    $plan=New-CTComPlan -Attributes $attrs -Name $rollbackName -DisplayName $rollbackName -Security $sd -Context $context
    $oidBefore=@(Get-ADObject -Server $Server -SearchBase $oidBase -SearchScope OneLevel -Filter * | ForEach-Object {[string]$_.ObjectGUID} | Sort-Object)
    $injected=$false
    try {$null=Invoke-CTComPlan -Plan $plan -InjectVerificationFailure}
    catch {if ($_.Exception.Message -ne 'LAB_INJECTED_POSTCOMMIT_VERIFICATION_FAILURE') {throw};$injected=$true}
    $oidAfter=@(Get-ADObject -Server $Server -SearchBase $oidBase -SearchScope OneLevel -Filter * | ForEach-Object {[string]$_.ObjectGUID} | Sort-Object)
    $verified=$injected -and -not (Get-CTTemplate -Context $context -Name $rollbackName -Optional) -and (($oidBefore -join ',') -ceq ($oidAfter -join ','))
    if (-not $verified) {throw 'Integrated rollback verification failed.'}
    [pscustomobject]@{Case='Rollback';Stage='Cleanup';Name=$rollbackName;Verified=$verified;Published=$false}
}
foreach ($old in $before) {
    $now=Get-ADObject -Server $Server -Identity $old.ObjectGUID -Properties uSNChanged
    if ($now.uSNChanged -ne $old.uSNChanged) {throw "Pre-existing template changed: $($old.Name)"}
}
$cas=@(Get-ADObject -Server $Server -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$($root.configurationNamingContext)" -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties certificateTemplates)
foreach ($ca in $cas) {foreach ($name in $destinations) {if ($ca.certificateTemplates -contains $name) {throw "Unexpected publication: $name"}}}
[pscustomobject]@{Case='ExistingTemplates';Stage='Final';Name='Existing GUID/USN snapshots';Verified=$true;Published=$false}
if (-not $Create -or $WhatIfPreference) {
    foreach ($name in $destinations) {
        if (@(Get-ADObject -Server $Server -SearchBase $base -SearchScope OneLevel -LDAPFilter "(cn=$name)").Count) {throw 'WhatIf created a destination unexpectedly.'}
    }
    [pscustomobject]@{Case='WhatIf';Stage='Final';Name='No destination templates';Verified=$true;Published=$false}
}

#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Integrated COM feature regression: AD subject/SAN, multi-provider, rights, supersedence.
.DESCRIPTION
Place beside the complete COM 0.2.0 package. Default invokes creator WhatIf only.
-Create creates three sources and three original-format imports, all unpublished.
No certificate enrollment, TPM key generation or client supersedence behavior tested.
Extra group ACEs are inspected explicitly; admin membership is not an effective-rights test.
Sources/previous template and OID GUID+USN snapshots checked for changes.
Local JSON exports retained. Stop on failure; earlier verified templates remain.
#>
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='Medium')]
param(
    [string]$Server='lab-dc-01.corp.michaelwaterman.nl',
    [ValidatePattern('^R[0-9]{2,4}$')][string]$RunId='R01',
    [string]$SupersededTemplate='COMJsonMultiPolicy_S3_R01',
    [ValidateSet('UserAD','MachineDNS','MultiKSP')][string[]]$SelectedCase=@('UserAD','MachineDNS','MultiKSP'),
    [switch]$Create
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ADCertificateTemplate.Portability.psm1') -Force
Import-Module ActiveDirectory
$root=Get-ADRootDSE -Server $Server
$config=[string]$root.configurationNamingContext
$base="CN=Certificate Templates,CN=Public Key Services,CN=Services,$config"
$oidBase="CN=OID,CN=Public Key Services,CN=Services,$config"
$context=[pscustomobject]@{DC=$Server;ConfigurationDN=$config;TemplateContainer=$base;OIDContainer=$oidBase}
$null=Get-CTTemplate -Context $context -Name $SupersededTemplate
$beforeTemplates=@(Get-ADObject -Server $Server -SearchBase $base -SearchScope OneLevel -Filter * -Properties uSNChanged)
$beforeOids=@(Get-ADObject -Server $Server -SearchBase $oidBase -SearchScope OneLevel -Filter * -Properties uSNChanged)
$groups=@{}
foreach ($group in @('GG-T0-Admins','Domain Computers','Schema Admins')) {$groups[$group]=Get-ADGroup -Server $Server -Identity $group}
$cases=@(
    @{Label='UserAD';Source='User';Flags=1174405120;Subject='ActiveDirectory';Format='Common name';SAN=@('UPN','E-mail name');Groups=@('GG-T0-Admins');Auto=$false;Multi=$false;Reuse=$false;PermissionMode='Preserve'},
    @{Label='MachineDNS';Source='WebServer';Flags=402653184;Subject='ActiveDirectory';Format='DNS name';SAN=@('DNS name');Groups=@('Domain Computers');Auto=$true;Multi=$false;Reuse=$false;PermissionMode='TargetBaseline'},
    @{Label='MultiKSP';Source='WebServer';Flags=9;Subject='SupplyInRequest';Format='';SAN=@();Groups=@('GG-T0-Admins');Auto=$false;Multi=$true;Reuse=$true;PermissionMode='Preserve'}
)
$cases=@($cases | Where-Object {$_.Label -in $SelectedCase})
$names=@()
foreach ($case in $cases) {$names+="COMRC1F$($case.Label)_$RunId";$names+="COMRC1FI$($case.Label)_$RunId"}
foreach ($name in $names) {
    if (Get-CTTemplate -Context $context -Name $name -Optional) {throw "Destination exists: $name. Inspect prior run; use a fresh RunId if appropriate."}
    if (Test-Path -LiteralPath (Join-Path $PSScriptRoot "$name.json")) {throw "Local JSON already exists: $name.json"}
}
function Test-SavedFeature {
    param($TemplateName,$Case,[string[]]$ExpectedGroups,[string[]]$ExpectedSuper)
    $t=Get-CTTemplate -Context $context -Name $TemplateName
    if ([int]$t.'msPKI-Certificate-Name-Flag' -ne $Case.Flags) {throw "Subject/SAN flags mismatch: $TemplateName"}
    if ([int]$t.'msPKI-Template-Schema-Version' -ne 3) {throw "Schema mismatch: $TemplateName"}
    if ($Case.Auto -and (([int]$t.'msPKI-Enrollment-Flag' -band 0x20) -eq 0)) {throw "Template autoenrollment flag missing: $TemplateName"}
    $providers=@(Get-CTStrings (Get-CTProperty $t 'pKIDefaultCSPs'))
    $wanted=@('1,Microsoft Software Key Storage Provider')
    if ($Case.Multi) {$wanted+= '2,Microsoft Platform Crypto Provider'}
    if (-not (Test-CTAttribute -Expected $wanted -Actual $providers)) {throw "Provider priority/name mismatch: $TemplateName"}
    $expectedEku=@('1.3.6.1.5.5.7.3.1')
    if ($Case.Label -eq 'UserAD') {$expectedEku=@('1.3.6.1.4.1.311.10.3.4','1.3.6.1.5.5.7.3.4','1.3.6.1.5.5.7.3.2')}
    foreach ($field in @('pKIExtendedKeyUsage','msPKI-Certificate-Application-Policy')) {
        if (-not (Test-CTAttribute -Expected $expectedEku -Actual (Get-CTProperty $t $field))) {throw "Policy mismatch $field on $TemplateName"}
    }
    if (-not (Test-CTAttribute -Expected $ExpectedSuper -Actual (Get-CTProperty $t 'msPKI-Supersede-Templates'))) {throw "Supersedence mismatch: $TemplateName"}
    $sd=Get-CTSecurity -Context $context -DistinguishedName $t.DistinguishedName
    if (-not $sd.AreAccessRulesProtected) {throw "Inheritance not protected: $TemplateName"}
    $rules=@($sd.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]))
    foreach ($groupName in $ExpectedGroups) {
        $sid=$groups[$groupName].SID.Value
        $allow=@($rules | Where-Object {$_.IdentityReference.Value -eq $sid -and $_.AccessControlType -eq 'Allow'})
        $read=@($allow | Where-Object {$_.ObjectType -eq [guid]::Empty -and (([int]$_.ActiveDirectoryRights -band [int][DirectoryServices.ActiveDirectoryRights]::GenericRead) -eq [int][DirectoryServices.ActiveDirectoryRights]::GenericRead)})
        if (-not $read.Count) {throw "Explicit group Read missing: $TemplateName / $groupName"}
        $rightIds=@([guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55')
        if ($Case.Auto) {$rightIds += [guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'}
        foreach ($right in $rightIds) {
            $aces=@($allow | Where-Object {$_.ObjectType -eq $right -and (([int]$_.ActiveDirectoryRights -band [int][DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ne 0)})
            if (-not $aces.Count) {throw "Explicit group extended right missing: $TemplateName / $groupName / $right"}
        }
    }
    [pscustomobject]@{Case=$Case.Label;Name=$TemplateName;Stage='AD feature checks';Verified=$true;NameFlags=('0x{0:X8}' -f $Case.Flags);Providers=$providers;Supersedes=@($ExpectedSuper);Groups=$ExpectedGroups;AutoenrollACE=[bool]$Case.Auto;EnrollmentFlags=[int]$t.'msPKI-Enrollment-Flag';Published=$false}
}
foreach ($case in $cases) {
    $name="COMRC1F$($case.Label)_$RunId"
    $importName="COMRC1FI$($case.Label)_$RunId"
    $p=@{Server=$Server;Name=$name;DisplayName=$name;SourceTemplate=$case.Source;
        CACompatibility='Windows Server 2008 R2';RecipientCompatibility='Windows 7 / Windows Server 2008 R2';
        ProviderCategory='Key Storage Provider';ProviderSelection='SelectedProviders';Provider=@('Microsoft Software Key Storage Provider');
        Algorithm='RSA';MinimumKeySize=3072;RequestHash='SHA256';RenewalWeeks=6;
        SubjectNameMode=$case.Subject;EnrollmentGroup=$case.Groups;ReuseSubjectOnRenewal=$case.Reuse}
    if ($case.Subject -eq 'ActiveDirectory') {$p.SubjectNameFormat=$case.Format;$p.SubjectAlternativeName=$case.SAN}
    if ($case.Auto) {$p.EnrollmentPermission='EnrollAndAutoenroll'}
    if ($case.Multi) {$p.Provider=@('Microsoft Software Key Storage Provider','Microsoft Platform Crypto Provider')}
    $approved=$false
    if ($Create) {$approved=$PSCmdlet.ShouldProcess($name,'Create and original-format import two unpublished feature-test templates')}
    if (-not $approved) {
        & (Join-Path $PSScriptRoot 'New-ADCertificateTemplate.ps1') @p -WhatIf
        [pscustomobject]@{Case=$case.Label;Stage='CreatorWhatIf';Name=$name;Verified=$null;Published=$false}
        continue
    }
    $new=& (Join-Path $PSScriptRoot 'New-ADCertificateTemplate.ps1') @p -Confirm:$false
    if ($null -eq $new -or -not $new.Verified) {throw "Creator verification failed: $name"}
    Test-SavedFeature -TemplateName $name -Case $case -ExpectedGroups $case.Groups -ExpectedSuper @()
    $path=Join-Path $PSScriptRoot "$name.json"
    & (Join-Path $PSScriptRoot 'Export-ADCertificateTemplate.ps1') -Server $Server -TemplateName $name -Path $path -Confirm:$false | Out-Null
    $sup=@()
    if ($case.Multi) {
        # Deliberate, typed configuration edit exercises IncludeSupersededTemplates.
        # Original export is retained; only the separately named import input is changed.
        $doc=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $doc.Attributes | Add-Member -NotePropertyName 'msPKI-Supersede-Templates' -NotePropertyValue ([pscustomobject]@{Type='StringArray';Value=[string[]]@($SupersededTemplate)})
        $path=Join-Path $PSScriptRoot "$importName.json"
        [IO.File]::WriteAllText($path,($doc | ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
        $sup=@($SupersededTemplate)
    }
    $imp=@{Server=$Server;Path=$path;Name=$importName;DisplayName=$importName;PermissionMode=$case.PermissionMode}
    $expectedGroups=$case.Groups
    if ($case.PermissionMode -eq 'TargetBaseline') {
        $imp.PermissionTemplate='WebServer';$imp.EnrollmentGroup=@('Domain Computers','Schema Admins');$imp.EnrollmentPermission='EnrollAndAutoenroll'
        $expectedGroups=$imp.EnrollmentGroup
    }
    if ($sup.Count) {$imp.IncludeSupersededTemplates=$true}
    & (Join-Path $PSScriptRoot 'Import-ADCertificateTemplate.ps1') @imp -WhatIf
    $imported=& (Join-Path $PSScriptRoot 'Import-ADCertificateTemplate.ps1') @imp -Confirm:$false
    if ($null -eq $imported -or -not $imported.Verified) {throw "Importer verification failed: $importName"}
    Test-SavedFeature -TemplateName $importName -Case $case -ExpectedGroups $expectedGroups -ExpectedSuper $sup
}
foreach ($snapshot in @(@{Label='Templates';Before=$beforeTemplates},@{Label='OIDObjects';Before=$beforeOids})) {
    foreach ($old in $snapshot.Before) {
        $now=Get-ADObject -Server $Server -Identity $old.ObjectGUID -Properties uSNChanged
        if ($now.uSNChanged -ne $old.uSNChanged) {throw "Pre-existing object changed: $($old.DistinguishedName)"}
    }
    [pscustomobject]@{Case=$snapshot.Label;Stage='Final';Name='Pre-existing GUID/USN unchanged';Verified=$true;Published=$false}
}
$cas=@(Get-ADObject -Server $Server -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$config" -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties certificateTemplates)
foreach ($ca in $cas) {foreach ($name in $names) {if ($ca.certificateTemplates -contains $name) {throw "Unexpected publication: $name"}}}
[pscustomobject]@{Case='Publication';Stage='Final';Name='All feature templates unpublished';Verified=$true;Published=$false}
if (-not $Create -or $WhatIfPreference) {
    foreach ($name in $names) {if (Get-CTTemplate -Context $context -Name $name -Optional) {throw 'WhatIf created a destination.'}}
    [pscustomobject]@{Case='WhatIf';Stage='Final';Name='No destinations created';Verified=$true;Published=$false}
}

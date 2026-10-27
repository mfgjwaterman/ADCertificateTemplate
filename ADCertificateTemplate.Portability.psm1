#Requires -Version 5.1
# Shared helpers for Export/Import-ADCertificateTemplate, version 1.2.0.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop

function Get-CTProperty {
    param($Object, [string]$Name)
    $property = $Object.PSObject.Properties[$Name]
    if ($null -ne $property) { return ,($property.Value) }
    return $null
}

function Get-CTStrings {
    param($Value)
    foreach ($item in $Value) {
        if ($null -ne $item) { [string]$item }
    }
}

function ConvertTo-CTBinary {
    param($Value)
    if ($Value -is [byte[]]) { return ,$Value }
    $items = @($Value)
    if ($items.Count -eq 1 -and $items[0] -is [byte[]]) { return ,([byte[]]$items[0]) }
    return ,([byte[]]$items)
}

function ConvertTo-CTLdapValue {
    param([string]$Value)
    $Value.Replace('\','\5c').Replace('*','\2a').Replace('(','\28').Replace(')','\29').Replace([string][char]0,'\00')
}

function Initialize-CTDirectory {
    param([string]$Server, $CallingCmdlet)
    if ($PSVersionTable.PSEdition -ne 'Desktop') {
        throw 'Use Windows PowerShell 5.1 (powershell.exe).'
    }
    if (-not (Get-Module ActiveDirectory -ListAvailable)) {
        if (-not $CallingCmdlet.ShouldProcess($env:COMPUTERNAME, 'Install ActiveDirectory management tools')) {
            Write-Warning 'AD tools are missing. Installation was skipped; no directory validation or file/template writes were performed.'
            return $null
        }
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        if ([int]$os.ProductType -eq 1) {
            Import-Module Dism -ErrorAction Stop -Verbose:$false
            $install = Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0' -ErrorAction Stop
            if ($install.RestartNeeded) { throw 'Restart Windows manually, then rerun. No template was created.' }
        }
        else {
            Import-Module ServerManager -ErrorAction Stop -Verbose:$false
            $install = Install-WindowsFeature RSAT-AD-PowerShell -ErrorAction Stop
            if (-not $install.Success) { throw 'AD tool installation failed.' }
            if ([string]$install.RestartNeeded -eq 'Yes') { throw 'Restart Windows manually, then rerun. No template was created.' }
        }
    }
    Import-Module ActiveDirectory -Global -ErrorAction Stop -Verbose:$false
    if (-not $Server) {
        $discovered = Get-ADDomainController -Discover -Writable -ErrorAction Stop
        $Server = [string]($discovered.HostName | Select-Object -First 1)
    }
    if ([string]::IsNullOrWhiteSpace($Server)) { throw 'No domain controller hostname was returned.' }
    $dc = Get-ADDomainController -Server $Server -Identity $Server -ErrorAction Stop
    if ($dc.IsReadOnly) { throw 'Use a writable domain controller.' }
    $root = Get-ADRootDSE -Server $Server -ErrorAction Stop
    $configDN = [string]$root.configurationNamingContext
    $configObject = Get-ADObject -Server $Server -Identity $configDN -ErrorAction Stop
    Write-Verbose "Using domain controller: $Server"
    [PSCustomObject]@{
        DC = $Server
        ConfigurationDN = $configDN
        ForestIdentity = ([guid]$configObject.ObjectGUID).ToString('D')
        TemplateContainer = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configDN"
        OIDContainer = "CN=OID,CN=Public Key Services,CN=Services,$configDN"
    }
}

function Get-CTTemplate {
    param($Context, [string]$Name, [switch]$Optional)
    $escaped = ConvertTo-CTLdapValue $Name
    $objects = @(Get-ADObject -Server $Context.DC -SearchBase $Context.TemplateContainer `
        -SearchScope OneLevel -LDAPFilter "(&(objectClass=pKICertificateTemplate)(cn=$escaped))" `
        -Properties * -ErrorAction Stop)
    if ($objects.Count -eq 0) {
        if ($Optional) { return $null }
        throw "Template '$Name' was not found on $($Context.DC)."
    }
    if ($objects.Count -ne 1) { throw "Template name '$Name' is ambiguous." }
    return $objects[0]
}

function Get-CTAttributeSpecs {
    # Fixed allowlist. Never import arbitrary AD/system/security attributes from JSON.
    @{
        'flags' = 'Int32'
        'pKIDefaultKeySpec' = 'Int32'
        'pKIKeyUsage' = 'Binary'
        'pKIMaxIssuingDepth' = 'Int32'
        'pKICriticalExtensions' = 'StringArray'
        'pKIExtendedKeyUsage' = 'StringArray'
        'pKIExpirationPeriod' = 'Binary'
        'pKIOverlapPeriod' = 'Binary'
        'pKIDefaultCSPs' = 'StringArray'
        'msPKI-Certificate-Name-Flag' = 'Int32'
        'msPKI-Enrollment-Flag' = 'Int32'
        'msPKI-Private-Key-Flag' = 'Int32'
        'msPKI-RA-Signature' = 'Int32'
        'msPKI-RA-Policies' = 'StringArray'
        'msPKI-RA-Application-Policies' = 'StringArray'
        'msPKI-Certificate-Policy' = 'StringArray'
        'msPKI-Certificate-Application-Policy' = 'StringArray'
        'msPKI-Template-Schema-Version' = 'Int32'
        'msPKI-Minimal-Key-Size' = 'Int32'
        'msPKI-Supersede-Templates' = 'StringArray'
    }
}

function ConvertTo-CTAttributes {
    param($Template)
    $specs = Get-CTAttributeSpecs
    $metadataOnly = @('msPKI-Cert-Template-OID','msPKI-Template-Minor-Revision')
    foreach ($property in $Template.PSObject.Properties) {
        if ($property.Name -match '^(pKI|msPKI-)' -and -not $specs.ContainsKey($property.Name) -and
            $property.Name -notin $metadataOnly -and $null -ne $property.Value -and
            @($property.Value).Count -gt 0) {
            throw "Unsupported populated template attribute '$($property.Name)'. Export stopped rather than silently dropping it."
        }
    }
    $result = [ordered]@{}
    foreach ($name in @($specs.Keys | Sort-Object)) {
        $value = Get-CTProperty $Template $name
        if ($null -eq $value) { continue }
        $type = $specs[$name]
        if ($type -eq 'StringArray') {
            $strings = @(Get-CTStrings $value)
            if ($strings.Count -eq 0) { continue }
            $result[$name] = [ordered]@{ Type = $type; Value = $strings }
        }
        elseif ($type -eq 'Binary') {
            $binary = ConvertTo-CTBinary $value
            if ($binary.Length -eq 0) { continue }
            $result[$name] = [ordered]@{ Type = $type; Value = [Convert]::ToBase64String($binary) }
        }
        else {
            $items = @($value)
            if ($items.Count -ne 1) { throw "Expected one integer for $name." }
            $result[$name] = [ordered]@{ Type = $type; Value = [int]$items[0] }
        }
    }
    return $result
}

function ConvertFrom-CTAttributes {
    param($Attributes)
    if ($null -eq $Attributes -or $Attributes -isnot [PSCustomObject]) {
        throw 'Configuration.Attributes must be a JSON object.'
    }
    $specs = Get-CTAttributeSpecs
    $result = @{}
    foreach ($property in $Attributes.PSObject.Properties) {
        $name = $property.Name
        if (-not $specs.ContainsKey($name)) { throw "Attribute '$name' is not permitted in this format." }
        $entry = $property.Value
        if ($null -eq $entry -or $entry -isnot [PSCustomObject] -or
            (Get-CTProperty $entry 'Type') -cne $specs[$name]) {
            throw "Unexpected type declaration for $name."
        }
        $value = Get-CTProperty $entry 'Value'
        if ($null -eq $value) { throw "Missing value for $name." }
        switch ($specs[$name]) {
            'Int32' {
                if ($value -isnot [int] -and $value -isnot [long]) { throw "$name must be an integer JSON number." }
                if ([long]$value -lt [int]::MinValue -or [long]$value -gt [int]::MaxValue) { throw "$name exceeds Int32 range." }
                $result[$name] = [int]$value
            }
            'Binary' {
                if ($value -isnot [string]) { throw "$name must contain Base64 text." }
                try { $bytes = [Convert]::FromBase64String($value) }
                catch { throw "Invalid Base64 in $name." }
                if ($bytes.Length -eq 0) { throw "$name cannot contain an empty binary value." }
                $result[$name] = [byte[]]$bytes
            }
            'StringArray' {
                if ($value -isnot [array] -or $value.Count -eq 0) { throw "$name must contain a nonempty JSON array of strings." }
                foreach ($item in $value) {
                    if ($item -isnot [string] -or [string]::IsNullOrWhiteSpace($item) -or $item.IndexOf([char]0) -ge 0) {
                        throw "$name contains an invalid string."
                    }
                }
                if (@($value | Sort-Object -Unique).Count -ne $value.Count) { throw "$name contains duplicate values." }
                $result[$name] = [string[]]$value
            }
        }
    }
    Assert-CTConfiguration $result
    return $result
}

function Get-CTKspProperties {
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Value)
    $parts = @($Value.Split([char]96))
    if ($parts[-1] -eq '') { $parts = @($parts[0..($parts.Count - 2)]) }
    if ($parts.Count -eq 0 -or ($parts.Count % 3) -ne 0) {
        throw 'Malformed KSP property triplets.'
    }
    $properties = @{}
    for ($index = 0; $index -lt $parts.Count; $index += 3) {
        $name = $parts[$index]
        if ([string]::IsNullOrWhiteSpace($name) -or $properties.ContainsKey($name)) {
            throw "Empty or duplicate KSP property: $name"
        }
        $properties[$name] = [PSCustomObject]@{
            Type = $parts[$index + 1]
            Value = $parts[$index + 2]
        }
    }
    return $properties
}

function Get-CTCryptography {
    param([hashtable]$Attributes)
    $legacy = ([int]$Attributes['msPKI-Template-Schema-Version'] -eq 2) -or
        (([int]$Attributes['msPKI-Private-Key-Flag'] -band 0x100) -ne 0)
    if ($legacy) {
        foreach ($value in @($Attributes['msPKI-RA-Application-Policies'])) {
            if ($null -ne $value -and ([string]$value).Contains('`')) {
                $encoded = Get-CTKspProperties -Value ([string]$value)
                if ($encoded.ContainsKey('msPKI-Asymmetric-Algorithm') -and
                    $encoded['msPKI-Asymmetric-Algorithm'].Value -ne 'RSA') {
                    throw 'Non-RSA KSP algorithms cannot be combined with a legacy provider/schema.'
                }
            }
        }
        return [PSCustomObject]@{
            IsLegacy = $true; Algorithm = 'RSA'; RequestHash = 'Determined by CSP'
            CngKeyUsage = $null; Properties = @{}
        }
    }
    $policy = @($Attributes['msPKI-RA-Application-Policies'])
    if ($policy.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$policy[0])) {
        throw 'KSP templates require one property-triplet string with an explicit algorithm.'
    }
    $properties = Get-CTKspProperties -Value ([string]$policy[0])
    if (-not $properties.ContainsKey('msPKI-Asymmetric-Algorithm') -or
        $properties['msPKI-Asymmetric-Algorithm'].Type -cne 'PZPWSTR') {
        throw 'KSP templates require an explicit PZPWSTR asymmetric algorithm.'
    }
    return [PSCustomObject]@{
        IsLegacy = $false
        Algorithm = ([string]$properties['msPKI-Asymmetric-Algorithm'].Value).ToUpperInvariant()
        RequestHash = $(if ($properties.ContainsKey('msPKI-Hash-Algorithm')) {
            [string]$properties['msPKI-Hash-Algorithm'].Value
        } else { $null })
        CngKeyUsage = $(if ($properties.ContainsKey('msPKI-Key-Usage')) {
            [string]$properties['msPKI-Key-Usage'].Value
        } else { $null })
        Properties = $properties
    }
}

function Assert-CTConfiguration {
    param([hashtable]$Attributes)
    foreach ($name in @('flags','msPKI-Template-Schema-Version','msPKI-Minimal-Key-Size',
        'msPKI-Private-Key-Flag','msPKI-Enrollment-Flag','msPKI-Certificate-Name-Flag',
        'pKIExpirationPeriod','pKIOverlapPeriod','pKIKeyUsage')) {
        if (-not $Attributes.ContainsKey($name)) { throw "Required configuration attribute missing: $name" }
    }
    $schema = [int]$Attributes['msPKI-Template-Schema-Version']
    if ($schema -notin 2,3,4) { throw 'This release imports/exports custom schema version 2, 3 or 4 templates only.' }
    foreach ($name in @('pKIExpirationPeriod','pKIOverlapPeriod')) {
        if ($Attributes[$name].Length -ne 8) { throw "$name must contain exactly eight bytes." }
        $ticks = [BitConverter]::ToInt64([byte[]]$Attributes[$name],0)
        if ($ticks -ge 0) { throw "$name must be a negative relative interval." }
    }
    $validity = [BitConverter]::ToInt64([byte[]]$Attributes['pKIExpirationPeriod'],0)
    $renewal = [BitConverter]::ToInt64([byte[]]$Attributes['pKIOverlapPeriod'],0)
    if ($renewal -le $validity) { throw 'Renewal period must be shorter than validity.' }
    $crypto = Get-CTCryptography -Attributes $Attributes
    $keySize = [int]$Attributes['msPKI-Minimal-Key-Size']
    if ($crypto.Algorithm -eq 'RSA') {
        if ($keySize -lt 512) { throw 'Invalid RSA minimum key size.' }
    }
    elseif ($crypto.Algorithm -match '^(ECDSA|ECDH)_P(256|384|521)$') {
        $agreement = $Matches[1] -eq 'ECDH'
        $expectedSize = [int]$Matches[2]
        if ($crypto.IsLegacy) { throw 'ECC requires a KSP template.' }
        if ($keySize -ne $expectedSize) {
            throw "Algorithm $($crypto.Algorithm) requires minimum key size $expectedSize."
        }
        if (-not $crypto.Properties.ContainsKey('msPKI-Hash-Algorithm') -or
            $crypto.Properties['msPKI-Hash-Algorithm'].Type -cne 'PZPWSTR' -or
            $crypto.RequestHash -notin 'SHA256','SHA384','SHA512') {
            throw 'ECC profiles require an explicit SHA2 request hash.'
        }
        # ECDH follows the UI's CNG AllUsages profile; the certificate extension
        # below remains Key Agreement-only. Never silently repair an old export.
        $expectedUsage = if ($agreement) { 16777215 } else { 2 }
        $expectedSpec = if ($agreement) { 1 } else { 2 }
        $expectedCertUsage = if ($agreement) { 0x08 } else { 0x80 }
        [uint32]$cngUsage = 0
        if (-not $crypto.Properties.ContainsKey('msPKI-Key-Usage') -or
            $crypto.Properties['msPKI-Key-Usage'].Type -cne 'DWORD' -or
            -not [uint32]::TryParse($crypto.CngKeyUsage, [ref]$cngUsage) -or $cngUsage -ne $expectedUsage) {
            if ($agreement) {
                throw "Algorithm $($crypto.Algorithm) requires CNG AllUsages DWORD 16777215. ECDH profiles from rc5/rc6 with value 4 must be corrected and re-exported; import does not rewrite configuration."
            }
            throw "Algorithm $($crypto.Algorithm) requires CNG key usage DWORD $expectedUsage."
        }
        if (-not $Attributes.ContainsKey('pKIDefaultKeySpec') -or
            [int]$Attributes['pKIDefaultKeySpec'] -ne $expectedSpec) {
            throw "Algorithm $($crypto.Algorithm) requires pKIDefaultKeySpec $expectedSpec."
        }
        $keyUsage = [byte[]]$Attributes['pKIKeyUsage']
        if ($keyUsage.Length -notin 1,2 -or $keyUsage[0] -ne $expectedCertUsage -or
            ($keyUsage.Length -eq 2 -and $keyUsage[1] -ne 0)) {
            throw "Algorithm $($crypto.Algorithm) requires family-specific certificate Key Usage."
        }
        if (([int]$Attributes['msPKI-Private-Key-Flag'] -band 1) -ne 0) {
            throw 'ECC profiles requiring private-key archival are outside this release scope.'
        }
    }
    else { throw "Unsupported KSP algorithm: $($crypto.Algorithm). Supported: RSA or ECDSA/ECDH on P-256/P-384/P-521." }
    if (([int]$Attributes['flags'] -band 0x40000) -ne 0) { throw 'Deleted templates are not importable.' }
}

function Get-CTSecurity {
    param($Context, [string]$DistinguishedName)
    $entry = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$($Context.DC)/$DistinguishedName")
    try {
        $entry.PSBase.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
        $entry.PSBase.RefreshCache(@('ntSecurityDescriptor'))
        $copy = [System.DirectoryServices.ActiveDirectorySecurity]::new()
        $copy.SetSecurityDescriptorBinaryForm($entry.PSBase.ObjectSecurity.GetSecurityDescriptorBinaryForm(),
            [System.Security.AccessControl.AccessControlSections]::Access)
        return ,$copy
    }
    finally { $entry.PSBase.Dispose() }
}

function ConvertTo-CTPermissionRecord {
    param([System.DirectoryServices.ActiveDirectorySecurity]$Security)
    $records = @(
        foreach ($rule in $Security.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])) {
            $account = $rule.IdentityReference.Value
            try { $account = $rule.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value } catch {}
            [ordered]@{
                SID = $rule.IdentityReference.Value; Account = $account
                AccessControlType = [string]$rule.AccessControlType
                Rights = [string]$rule.ActiveDirectoryRights
                ObjectType = [string]$rule.ObjectType
                InheritedObjectType = [string]$rule.InheritedObjectType
                IsInherited = $rule.IsInherited
                InheritanceType = [string]$rule.InheritanceType
            }
        }
    )
    [ordered]@{
        InheritanceBlocked = $Security.AreAccessRulesProtected
        # Binary descriptor avoids ambiguous DA/EA aliases when moving forests.
        DaclDescriptorBase64 = [Convert]::ToBase64String($Security.GetSecurityDescriptorBinaryForm())
        SddlForReview = $Security.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access)
        AccessRulesForReview = $records
    }
}

function Add-CTEnrollmentRules {
    param($Context, [System.DirectoryServices.ActiveDirectorySecurity]$Security,
          [string[]]$Group, [string]$Permission = 'Enroll')
    foreach ($groupName in @($Group | Sort-Object -Unique)) {
        if ([string]::IsNullOrWhiteSpace($groupName)) { continue }
        $resolved = Get-ADGroup -Server $Context.DC -Identity $groupName -ErrorAction Stop
        $sid = [System.Security.Principal.SecurityIdentifier]$resolved.SID
        $allow = [System.Security.AccessControl.AccessControlType]::Allow
        $Security.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new(
            $sid,[System.DirectoryServices.ActiveDirectoryRights]::GenericRead,$allow))
        $rights = @([guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55')
        if ($Permission -eq 'EnrollAndAutoenroll') { $rights += [guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2' }
        foreach ($right in $rights) {
            $Security.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new(
                $sid,[System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,$allow,$right))
        }
    }
}

function Test-CTAttribute {
    param($Expected, $Actual)
    if ($Expected -is [byte[]]) {
        if ($null -eq $Actual) { return $false }
        return [Convert]::ToBase64String($Expected) -ceq [Convert]::ToBase64String((ConvertTo-CTBinary $Actual))
    }
    $left = @(Get-CTStrings $Expected | Sort-Object)
    $right = @(Get-CTStrings $Actual | Sort-Object)
    return ($left.Count -eq $right.Count -and ($left -join [char]0) -ceq ($right -join [char]0))
}

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

function New-CTIdentity {
    param($Context)
    $root = Get-ADObject -Server $Context.DC -Identity $Context.OIDContainer -Properties 'msPKI-Cert-Template-OID' -ErrorAction Stop
    $base = [string]$root.'msPKI-Cert-Template-OID'
    if ($base -notmatch '^[0-2](\.[0-9]+)+$') { throw 'No valid destination forest OID base was found.' }
    do {
        $oid = "$base.$(Get-Random -Minimum 10000000 -Maximum 99999999).$(Get-Random -Minimum 10000000 -Maximum 99999999)"
        $found = @(Get-ADObject -Server $Context.DC -SearchBase $Context.OIDContainer -LDAPFilter "(msPKI-Cert-Template-OID=$oid)" -ErrorAction Stop)
    } while ($found.Count -gt 0)
    [PSCustomObject]@{ OID = $oid; ObjectName = (Get-CTOIDObjectName -OID $oid) }
}

function Assert-CTPolicyDependencies {
    param($Context, [hashtable]$Attributes)
    $oids = @()
    foreach ($name in @('pKIExtendedKeyUsage','msPKI-Certificate-Application-Policy',
        'msPKI-Certificate-Policy','msPKI-RA-Policies','msPKI-RA-Application-Policies')) {
        if (-not $Attributes.ContainsKey($name)) { continue }
        foreach ($item in $Attributes[$name]) {
            if ($name -eq 'msPKI-RA-Application-Policies' -and $item.Contains('`')) {
                $parts = $item.Split([char]96)
                for ($index = 0; $index + 2 -lt $parts.Length; $index += 3) {
                    if ($parts[$index] -eq 'msPKI-RA-Application-Policies') { $oids += $parts[$index + 2].Split(',') }
                }
            }
            else { $oids += [string]$item }
        }
    }
    foreach ($oid in @($oids | Sort-Object -Unique)) {
        if ($oid -notmatch '^[0-2](\.[0-9]+)+$') { throw "Invalid referenced policy OID: $oid" }
        # Standard and Microsoft-defined OIDs retain their meaning between forests.
        # RFC 4556: id-pkinit-KPKdc is outside the PKIX arc.
        # Accept this exact KDC EKU, not the entire Kerberos OID subtree.
        if ($oid -eq '1.3.6.1.5.2.3.5' -or
            $oid -match '^(1\.3\.6\.1\.5\.5\.7\.|1\.3\.6\.1\.4\.1\.311\.|2\.5\.)') { continue }
        $registered = @(Get-ADObject -Server $Context.DC -SearchBase $Context.OIDContainer `
            -LDAPFilter "(msPKI-Cert-Template-OID=$oid)" -ErrorAction Stop)
        if ($registered.Count -eq 0) {
            throw "Custom policy OID '$oid' is not registered in the destination. Register/review that policy separately before importing."
        }
    }
}

function Get-CTLocalCA {
    $path = Join-Path $env:SystemRoot 'System32\certutil.exe'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'certutil.exe is required for -Publish.' }
    $service = Get-Service CertSvc -ErrorAction SilentlyContinue
    if ($null -eq $service -or $service.Status -ne 'Running') { throw '-Publish requires a running local enterprise CA.' }
    $root = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
    $name = [string](Get-ItemProperty -LiteralPath $root -Name Active -ErrorAction Stop).Active
    if ([string]::IsNullOrWhiteSpace($name)) { throw 'No active local CA configuration.' }
    $type = (Get-ItemProperty -LiteralPath "$root\$name" -Name CAType -ErrorAction Stop).CAType
    if ([int]$type -notin 0,1) { throw 'Publication requires an enterprise CA.' }
    [PSCustomObject]@{ Executable = $path; Config = "$env:COMPUTERNAME\$name" }
}

function Publish-CTTemplate {
    param($CA, [string]$Name)
    $pattern = '(?im)^\s*' + [regex]::Escape($Name) + ':\s'
    $discovery = @(& $CA.Executable -f -ADTemplate $Name 2>&1)
    $code = $LASTEXITCODE
    $text = $discovery -join [Environment]::NewLine
    Write-Verbose $text
    if ($code -ne 0 -or $text -notmatch $pattern) { throw "Forced discovery failed ($code): $text" }
    $publication = @(& $CA.Executable -config $CA.Config -SetCATemplates "+$Name" 2>&1)
    $code = $LASTEXITCODE
    $text = $publication -join [Environment]::NewLine
    Write-Verbose $text
    if ($code -ne 0) { throw "Publication failed ($code): $text" }
    $verification = @(& $CA.Executable -config $CA.Config -CATemplates $Name 2>&1)
    $code = $LASTEXITCODE
    $text = $verification -join [Environment]::NewLine
    Write-Verbose $text
    if ($code -ne 0 -or $text -notmatch $pattern) { throw "CA issuance-list verification failed ($code): $text" }
}

function Get-CTAllowDaclFingerprint {
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

function Test-CTDacl {
    param([System.DirectoryServices.ActiveDirectorySecurity]$Expected,
          [System.DirectoryServices.ActiveDirectorySecurity]$Actual)
    $section = [System.Security.AccessControl.AccessControlSections]::Access
    $expectedSddl = $Expected.GetSecurityDescriptorSddlForm($section)
    $actualSddl = $Actual.GetSecurityDescriptorSddlForm($section)
    if ($expectedSddl -ceq $actualSddl) { return $true }
    $expectedFingerprint = Get-CTAllowDaclFingerprint $Expected
    $actualFingerprint = Get-CTAllowDaclFingerprint $Actual
    if ($null -ne $expectedFingerprint -and $null -ne $actualFingerprint -and
        $expectedFingerprint -ceq $actualFingerprint) {
        Write-Verbose 'DACL verified: identical allow ACEs and inheritance protection; only representation/order differs.'
        return $true
    }
    Write-Verbose "Expected DACL: $expectedSddl"
    Write-Verbose "Saved DACL:    $actualSddl"
    return $false
}


Export-ModuleMember -Function *-CT*

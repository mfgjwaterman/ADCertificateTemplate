#Requires -Version 5.1
# Shared helpers, 2.1.0. Schema 2/3 COM; schema 4 experimental native certca backend.
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
    if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess -or
        -not (($PSVersionTable.PSEdition -eq 'Desktop' -and $PSVersionTable.PSVersion -ge [version]'5.1') -or
              ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.PSVersion.Major -ge 7))) {
        throw 'Use elevated 64-bit Windows PowerShell 5.1 or PowerShell 7 on Windows.'
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




function New-CTComDerValue {
    param([byte]$Tag,[byte[]]$Content)
    $Header = [Collections.Generic.List[byte]]::new()
    $Header.Add($Tag)
    if ($Content.Length -lt 128) { $Header.Add([byte]$Content.Length) }
    elseif ($Content.Length -le 255) { $Header.Add(0x81); $Header.Add([byte]$Content.Length) }
    elseif ($Content.Length -le 65535) {
        $Header.Add(0x82); $Header.Add([byte]($Content.Length -shr 8)); $Header.Add([byte]($Content.Length -band 255))
    }
    else { throw 'DER value too large for this probe.' }
    $Header.AddRange($Content)
    return ,$Header.ToArray()
}
function New-CTComDerOid {
    param([string]$Oid)
    if ($Oid -notmatch '^[0-2](\.[0-9]+){2,}$') { throw "Invalid policy OID: $Oid" }
    $Arcs = @($Oid.Split('.') | ForEach-Object { [uint64]::Parse($_) })
    if ($Arcs[0] -lt 2 -and $Arcs[1] -gt 39) { throw "Invalid policy OID: $Oid" }
    $Bytes = [Collections.Generic.List[byte]]::new()
    $Numbers = @([uint64](40*$Arcs[0]+$Arcs[1])) + @($Arcs[2..($Arcs.Count-1)])
    foreach ($Number in $Numbers) {
        $Value = [uint64]$Number
        $Encoded = [Collections.Generic.List[byte]]::new()
        $Encoded.Insert(0,[byte]($Value -band 127)); $Value = $Value -shr 7
        while ($Value -gt 0) {
            $Encoded.Insert(0,[byte](($Value -band 127) -bor 128)); $Value = $Value -shr 7
        }
        $Bytes.AddRange($Encoded.ToArray())
    }
    return ,(New-CTComDerValue 6 $Bytes.ToArray())
}
function New-CTComPolicyDer {
    param([string[]]$Oids,[switch]$ApplicationPolicies)
    $Bytes = [Collections.Generic.List[byte]]::new()
    foreach ($Oid in $Oids) {
        [byte[]]$Encoded = New-CTComDerOid $Oid
        if ($ApplicationPolicies) { $Encoded = New-CTComDerValue 48 $Encoded }
        $Bytes.AddRange($Encoded)
    }
    return [Convert]::ToBase64String((New-CTComDerValue 48 $Bytes.ToArray()))
}


$script:CTComFixture=@'
<GetPoliciesResponse xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><response><policyID>COM-Memory-Probe</policyID><policyFriendlyName>COM Memory Probe</policyFriendlyName><nextUpdateHours>8</nextUpdateHours><policiesNotChanged xsi:nil="true" /><policies><policy><policyOIDReference>1</policyOIDReference><cAs xsi:nil="true" /><attributes><commonName>COMSchemaFixture</commonName><policySchema>4</policySchema><certificateValidity><validityPeriodSeconds>31536000</validityPeriodSeconds><renewalPeriodSeconds>3628800</renewalPeriodSeconds></certificateValidity><permission><enroll>false</enroll><autoEnroll>false</autoEnroll></permission><privateKeyAttributes><minimalKeyLength>3072</minimalKeyLength><keySpec>1</keySpec><keyUsageProperty>3</keyUsageProperty><permissions xsi:nil="true" /><algorithmOIDReference>5</algorithmOIDReference><cryptoProviders><provider>Microsoft Software Key Storage Provider</provider></cryptoProviders></privateKeyAttributes><revision><majorRevision>1</majorRevision><minorRevision>0</minorRevision></revision><supersededPolicies xsi:nil="true" /><privateKeyFlags>100990976</privateKeyFlags><subjectNameFlags>1</subjectNameFlags><enrollmentFlags>0</enrollmentFlags><generalFlags>513</generalFlags><hashAlgorithmOIDReference>6</hashAlgorithmOIDReference><rARequirements xsi:nil="true" /><keyArchivalAttributes xsi:nil="true" /><extensions><extension><oIDReference>2</oIDReference><critical>true</critical><value>AwIFoA==</value></extension><extension><oIDReference>3</oIDReference><critical>false</critical><value>MAoGCCsGAQUFBwMB</value></extension><extension><oIDReference>4</oIDReference><critical>false</critical><value>MAwwCgYIKwYBBQUHAwE=</value></extension></extensions></attributes></policy></policies></response><cAs xsi:nil="true" /><oIDs><oID><value>2.25.1</value><group>9</group><oIDReferenceID>1</oIDReferenceID><defaultName>COM Schema Fixture</defaultName></oID><oID><value>2.5.29.15</value><group>6</group><oIDReferenceID>2</oIDReferenceID><defaultName>Key Usage</defaultName></oID><oID><value>2.5.29.37</value><group>6</group><oIDReferenceID>3</oIDReferenceID><defaultName>Enhanced Key Usage</defaultName></oID><oID><value>1.3.6.1.4.1.311.21.10</value><group>6</group><oIDReferenceID>4</oIDReferenceID><defaultName>Application Policies</defaultName></oID><oID><value>1.2.840.113549.1.1.1</value><group>3</group><oIDReferenceID>5</oIDReferenceID><defaultName>RSA</defaultName></oID><oID><value>2.16.840.1.101.3.4.2.1</value><group>1</group><oIDReferenceID>6</oIDReferenceID><defaultName>SHA256</defaultName></oID></oIDs></GetPoliciesResponse>
'@
# COM candidate backend. Preparation never writes AD; Commit(1/4) is the only mutation path.
function ConvertTo-CTComUnsigned {
    param([int]$Value)
    [BitConverter]::ToUInt32([BitConverter]::GetBytes($Value),0).ToString([Globalization.CultureInfo]::InvariantCulture)
}
function Test-CTComValue {
    param([string]$Name,$Expected,$Actual)
    if ($Name -eq 'msPKI-RA-Application-Policies') {
        $left=@(Get-CTStrings $Expected);$right=@(Get-CTStrings $Actual)
        if ($left.Count -eq 0 -and $right.Count -eq 0) {return $true}
        if ($left.Count -ne 1 -or $right.Count -ne 1) {return $false}
        $a=Get-CTKspProperties $left[0];$b=Get-CTKspProperties $right[0]
        if ($a.Count -ne $b.Count) {return $false}
        foreach ($key in $a.Keys) {
            if (-not $b.ContainsKey($key) -or $a[$key].Type -cne $b[$key].Type -or $a[$key].Value -cne $b[$key].Value) {return $false}
        }
        return $true
    }
    if ($Name -eq 'pKIKeyUsage') {
        [byte[]]$a=$Expected;[byte[]]$b=ConvertTo-CTBinary $Actual
        while ($a.Count -gt 1 -and $a[-1] -eq 0) {$a=@($a[0..($a.Count-2)])}
        while ($b.Count -gt 1 -and $b[-1] -eq 0) {$b=@($b[0..($b.Count-2)])}
        return (($a -join ',') -ceq ($b -join ','))
    }
    if ($Name -in @('msPKI-RA-Signature','pKIMaxIssuingDepth','msPKI-Enrollment-Flag')) {
        if ($null -eq $Actual) {$Actual=0}
    }
    return (Test-CTAttribute -Expected $Expected -Actual $Actual)
}
function New-CTComPlan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Attributes,
        [Parameter(Mandatory)][string]$Name,[Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)]$Security,[Parameter(Mandatory)]$Context)
    if (-not [Environment]::Is64BitProcess) {throw 'COM candidate requires 64-bit Windows PowerShell.'}
    if ($Name -notmatch '^[A-Za-z][A-Za-z0-9_-]{0,63}$') {throw 'Invalid destination name.'}
    if ([string]::IsNullOrWhiteSpace($DisplayName)) {throw 'Empty display name.'}
    Assert-CTConfiguration $Attributes
    $nativeSchema4=([int]$Attributes['msPKI-Template-Schema-Version'] -eq 4)
    $expected=@{}
    foreach ($key in $Attributes.Keys) {$expected[$key]=$Attributes[$key]}
    foreach ($identity in @('msPKI-Cert-Template-OID','revision','msPKI-Template-Minor-Revision')) {$expected.Remove($identity)}
    $allowed=@('flags','pKIDefaultKeySpec','pKIKeyUsage','pKIMaxIssuingDepth','pKICriticalExtensions','pKIExtendedKeyUsage','pKIExpirationPeriod','pKIOverlapPeriod','pKIDefaultCSPs','msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag','msPKI-Private-Key-Flag','msPKI-RA-Signature','msPKI-RA-Application-Policies','msPKI-Certificate-Application-Policy','msPKI-Template-Schema-Version','msPKI-Minimal-Key-Size','msPKI-Supersede-Templates')
    foreach ($key in @($expected.Keys)) {
        if ($key -notin $allowed) {
            if (@(Get-CTStrings $expected[$key]).Count -gt 0) {throw "COM candidate does not serialize populated attribute: $key"}
            $expected.Remove($key)
        }
    }
    if ([int]$expected['msPKI-RA-Signature'] -ne 0 -or [int]$expected['pKIMaxIssuingDepth'] -ne 0) {throw 'RA signatures or nonzero max issuing depth are outside this COM candidate.'}
    if (([int]$expected['msPKI-Private-Key-Flag'] -band 1) -ne 0) {throw 'Private-key archival is outside this COM candidate.'}
    $critical=@(Get-CTStrings $expected['pKICriticalExtensions'])
    if ($critical.Count -ne 1 -or $critical[0] -cne '2.5.29.15') {throw 'This candidate supports only critical Key Usage.'}
    $ekus=@(Get-CTStrings $expected['pKIExtendedKeyUsage'])
    $apps=@(Get-CTStrings $expected['msPKI-Certificate-Application-Policy'])
    if ($apps.Count -eq 0 -or ((($ekus | Sort-Object) -join ',') -cne (($apps | Sort-Object) -join ','))) {
        throw 'COM candidate requires explicit, matching nonempty EKU and Application Policies. Import never adds missing policies silently.'
    }
    Assert-CTPolicyDependencies -Context $Context -Attributes $expected
    $crypto=Get-CTCryptography $expected
    if ($crypto.IsLegacy -and [int]$expected['msPKI-Template-Schema-Version'] -ne 2) {throw 'Legacy CSP requires schema 2 in this candidate.'}
    if (-not $crypto.IsLegacy -and [int]$expected['msPKI-Template-Schema-Version'] -notin 3,4) {throw 'KSP requires schema 3 or 4.'}
    $algorithmOid='1.2.840.113549.1.1.1'
    if (-not $crypto.IsLegacy) {
        if ($crypto.Algorithm -match '^ECD(SA|H)_P(256|384|521)$') {
            $algorithmOid=@{'256'='1.2.840.10045.3.1.7';'384'='1.3.132.0.34';'521'='1.3.132.0.35'}[$Matches[2]]
        }
        $hashOids=@{SHA1='1.3.14.3.2.26';SHA256='2.16.840.1.101.3.4.2.1';SHA384='2.16.840.1.101.3.4.2.2';SHA512='2.16.840.1.101.3.4.2.3'}
        if (-not $hashOids.ContainsKey($crypto.RequestHash)) {throw 'An explicit SHA1/SHA2 request hash is required.'}
        $p=$crypto.Properties
        foreach ($key in $p.Keys) {
            if ($key -notin @('msPKI-Asymmetric-Algorithm','msPKI-Hash-Algorithm','msPKI-Key-Usage','msPKI-Symmetric-Algorithm','msPKI-Symmetric-Key-Length')) {throw "Unsupported embedded crypto property: $key"}
        }
        if (-not $p.ContainsKey('msPKI-Key-Usage') -or $p['msPKI-Key-Usage'].Type -cne 'DWORD' -or $crypto.CngKeyUsage -notmatch '^\d+$') {throw 'Explicit DWORD CNG usage is required.'}
        if ($p['msPKI-Hash-Algorithm'].Type -cne 'PZPWSTR') {throw 'Request hash type mismatch.'}
        if (($p.ContainsKey('msPKI-Symmetric-Algorithm') -and $p['msPKI-Symmetric-Algorithm'].Value -cne '3DES') -or
            ($p.ContainsKey('msPKI-Symmetric-Key-Length') -and $p['msPKI-Symmetric-Key-Length'].Value -cne '168')) {throw 'Nondefault symmetric crypto properties are outside the candidate.'}
        # Native COM adds these defaults; normalize the EXPECTATION explicitly for creator input.
        $expected['msPKI-RA-Application-Policies']=[string[]]@('msPKI-Asymmetric-Algorithm`PZPWSTR`'+$crypto.Algorithm+'`msPKI-Hash-Algorithm`PZPWSTR`'+$crypto.RequestHash+'`msPKI-Key-Usage`DWORD`'+$crypto.CngKeyUsage+'`msPKI-Symmetric-Algorithm`PZPWSTR`3DES`msPKI-Symmetric-Key-Length`DWORD`168`')
    }
    elseif (@(Get-CTStrings $expected['msPKI-RA-Application-Policies']).Count) {throw 'Legacy embedded RA/crypto policies are outside the candidate.'}
    # Observed native custom-template flags; all other general flag bits remain exact.
    $expected['flags']=([int]$expected['flags'] -band (-bnot 0x10000)) -bor 0x20000
    $providers=@(Get-CTStrings $expected['pKIDefaultCSPs'])
    $providerNames=@()
    $ranked=@()
    foreach ($provider in $providers) {
        if ($provider -notmatch '^(\d+),(.+)$') {throw 'Invalid provider priority/name.'}
        $ranked += [pscustomobject]@{Rank=[int]$Matches[1];Name=$Matches[2]}
    }
    $ranked=@($ranked | Sort-Object Rank)
    for ($i=0;$i -lt $ranked.Count;$i++) {
        if ($ranked[$i].Rank -ne $i+1) {throw 'Provider priorities must be contiguous starting at 1.'}
        $providerNames += $ranked[$i].Name
    }
    if (@($providerNames | Select-Object -Unique).Count -ne $providerNames.Count) {throw 'Duplicate provider names.'}
    $validity=-[BitConverter]::ToInt64([byte[]]$expected['pKIExpirationPeriod'],0)/[TimeSpan]::TicksPerSecond
    $renewal=-[BitConverter]::ToInt64([byte[]]$expected['pKIOverlapPeriod'],0)/[TimeSpan]::TicksPerSecond
    if ($validity -ne [Math]::Floor($validity) -or $renewal -ne [Math]::Floor($renewal)) {throw 'COM candidate requires intervals in whole seconds.'}
    [byte[]]$ku=$expected['pKIKeyUsage']
    if ($ku.Length -notin 1,2) {throw 'Unsupported certificate key usage length.'}
    [byte]$last=$ku[-1]
    $unused=0
    if ($last -eq 0 -and $ku.Length -eq 2) {$ku=[byte[]]@($ku[0]);$last=$ku[0]}
    if ($last -eq 0) {throw 'Empty key usage.'}
    while (($last -band 1) -eq 0) {$unused++;$last=$last -shr 1}
    [byte[]]$kuDer=New-CTComDerValue 3 ([byte[]](@([byte]$unused)+@($ku)))
    $super=@(Get-CTStrings $expected['msPKI-Supersede-Templates'])
    foreach ($dependency in $super) {
        if ($dependency -ieq $Name) {throw 'Cannot supersede self.'}
        $null=Get-CTTemplate -Context $Context -Name $dependency
    }
    if (@($Security.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])).Count -eq 0) {throw 'Empty DACL refused.'}
    $autoRules=@($Security.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {
        $_.AccessControlType -eq 'Allow' -and $_.ObjectType -eq [guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2' -and
        (([int]$_.ActiveDirectoryRights -band [int][DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ne 0)
    })
    if ($autoRules.Count -gt 0 -and (([int]$expected['msPKI-Enrollment-Flag'] -band 0x20) -eq 0)) {
        throw 'Autoenroll ACE present but template autoenrollment flag 0x20 is absent. COM may add that bit. Import refuses to silently change exported enrollment flags; review the intended configuration.'
    }
    if (Get-CTTemplate -Context $Context -Name $Name -Optional) {throw "Destination exists: $Name"}
    if (@(Get-ADObject -Server $Context.DC -SearchBase $Context.TemplateContainer -SearchScope OneLevel -Filter {displayName -eq $DisplayName}).Count) {throw 'Destination display name exists.'}
    [xml]$xml=$script:CTComFixture
    $ns=[Xml.XmlNamespaceManager]::new($xml.NameTable)
    $uri='http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy'
    $ns.AddNamespace('p',$uri)
    $changes=@{
        '//p:attributes/p:commonName'=$Name
        '//p:oID[p:oIDReferenceID="1"]/p:defaultName'=$DisplayName
        '//p:attributes/p:policySchema'=[string]$expected['msPKI-Template-Schema-Version']
        '//p:certificateValidity/p:validityPeriodSeconds'=[string]$validity
        '//p:certificateValidity/p:renewalPeriodSeconds'=[string]$renewal
        '//p:privateKeyAttributes/p:minimalKeyLength'=[string]$expected['msPKI-Minimal-Key-Size']
        '//p:privateKeyAttributes/p:keySpec'=[string]$expected['pKIDefaultKeySpec']
        '//p:attributes/p:privateKeyFlags'=(ConvertTo-CTComUnsigned ([int]$expected['msPKI-Private-Key-Flag']))
        '//p:attributes/p:subjectNameFlags'=(ConvertTo-CTComUnsigned ([int]$expected['msPKI-Certificate-Name-Flag']))
        '//p:attributes/p:enrollmentFlags'=(ConvertTo-CTComUnsigned ([int]$expected['msPKI-Enrollment-Flag']))
        '//p:attributes/p:generalFlags'=(ConvertTo-CTComUnsigned ([int]$expected['flags']))
        '//p:extension[p:oIDReference="2"]/p:value'=[Convert]::ToBase64String($kuDer)
        '//p:extension[p:oIDReference="3"]/p:value'=(New-CTComPolicyDer $ekus)
        '//p:extension[p:oIDReference="4"]/p:value'=(New-CTComPolicyDer $apps -ApplicationPolicies)
    }
    foreach ($xpath in $changes.Keys) {$xml.SelectSingleNode($xpath,$ns).InnerText=$changes[$xpath]}
    $prov=$xml.SelectSingleNode('//p:privateKeyAttributes/p:cryptoProviders',$ns);$prov.RemoveAll()
    foreach ($providerName in $providerNames) {$node=$xml.CreateElement('provider',$uri);$node.InnerText=$providerName;$null=$prov.AppendChild($node)}
    if (-not $providerNames.Count) {$null=$prov.SetAttribute('nil','http://www.w3.org/2001/XMLSchema-instance','true')}
    $sup=$xml.SelectSingleNode('//p:attributes/p:supersededPolicies',$ns);$sup.RemoveAll()
    foreach ($dependency in $super) {$node=$xml.CreateElement('commonName',$uri);$node.InnerText=$dependency;$null=$sup.AppendChild($node)}
    if (-not $super.Count) {$null=$sup.SetAttribute('nil','http://www.w3.org/2001/XMLSchema-instance','true')}
    if ($crypto.IsLegacy) {
        foreach ($xpath in @('//p:privateKeyAttributes/p:keyUsageProperty','//p:privateKeyAttributes/p:algorithmOIDReference','//p:attributes/p:hashAlgorithmOIDReference')) {
            $node=$xml.SelectSingleNode($xpath,$ns);$node.RemoveAll();$null=$node.SetAttribute('nil','http://www.w3.org/2001/XMLSchema-instance','true')
        }
    }
    else {
        $xml.SelectSingleNode('//p:privateKeyAttributes/p:keyUsageProperty',$ns).InnerText=$crypto.CngKeyUsage
        $xml.SelectSingleNode('//p:oID[p:oIDReferenceID="5"]/p:value',$ns).InnerText=$algorithmOid
        $xml.SelectSingleNode('//p:oID[p:oIDReferenceID="5"]/p:defaultName',$ns).InnerText=$crypto.Algorithm
        $xml.SelectSingleNode('//p:oID[p:oIDReferenceID="6"]/p:value',$ns).InnerText=$hashOids[$crypto.RequestHash]
        $xml.SelectSingleNode('//p:oID[p:oIDReferenceID="6"]/p:defaultName',$ns).InnerText=$crypto.RequestHash
    }
    $backend=if ($nativeSchema4) {'NativeCertCa'} else {'CertEnrollCOM'}
    $plan=[pscustomobject]@{Name=$Name;DisplayName=$DisplayName;Context=$Context;Expected=$expected;Xml=$xml.OuterXml;Security=$Security;Crypto=$crypto;Backend=$backend;NativeBaseline=$null}
    if ($nativeSchema4) {
        Assert-CTNativeScope -Plan $plan
        Initialize-CTNativeBackend
        $baseline=Get-CTTemplate -Context $Context -Name 'WebServer'
        if ([int]$baseline.'msPKI-Template-Schema-Version' -ne 1) {throw 'Native RC requires the built-in schema-1 WebServer backend baseline.'}
        $plan.NativeBaseline=[pscustomobject]@{Guid=$baseline.ObjectGUID;OID=[string]$baseline.'msPKI-Cert-Template-OID';USN=[string]$baseline.uSNChanged}
        [CTNativeBackendEmbeddedProbe2]::Preflight($Context.DC,$plan.NativeBaseline.OID)
    }
    # Validate the prepared in-memory COM input before user approval or directory writes.
    $objects=Open-CTComPlan $plan
    try {
        $t=$objects.Template
        if ([string]$t.Property(1) -cne $Name -or [int]$t.Property(8) -ne [int]$expected['msPKI-Template-Schema-Version'] -or
            [int]$t.Property(11) -ne [int]$expected['msPKI-Minimal-Key-Size']) {throw 'Prepared COM input mismatch.'}
        if (-not $crypto.IsLegacy -and ([string]$t.Property(18) -cne $crypto.Algorithm -or [string]$t.Property(22) -cne $crypto.RequestHash)) {throw 'Prepared COM crypto mismatch.'}
    }
    finally {Close-CTComPlan $objects}
    return $plan
}
function Open-CTComPlan {
    param($Plan)
    $p=$null;$ts=$null;$t=$null;$w=$null
    try {
        $p=New-Object -ComObject X509Enrollment.CX509EnrollmentPolicyWebService
        $p.InitializeImport([Text.Encoding]::UTF8.GetBytes($Plan.Xml))
        $ts=$p.GetTemplates();$t=$ts.ItemByName($Plan.Name)
        $w=New-Object -ComObject X509Enrollment.CX509CertificateTemplateADWritable
        $w.Initialize($t)
        $sddl=$Plan.Security.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
        $null=$w.GetType().InvokeMember('Property',[Reflection.BindingFlags]::SetProperty,$null,$w,[object[]]@([int]28,$sddl))
        return [pscustomobject]@{Policy=$p;Templates=$ts;Template=$t;Writer=$w}
    }
    catch {Close-CTComPlan ([pscustomobject]@{Writer=$w;Template=$t;Templates=$ts;Policy=$p});throw}
}
function Close-CTComPlan {
    param($Objects)
    foreach ($object in @($Objects.Writer,$Objects.Template,$Objects.Templates,$Objects.Policy)) {
        if ($null -ne $object -and [Runtime.InteropServices.Marshal]::IsComObject($object)) {[void][Runtime.InteropServices.Marshal]::ReleaseComObject($object)}
    }
}
function Remove-CTComOwned {
    param($Plan,$Owned)
    $c=$Plan.Context
    $current=Get-CTTemplate -Context $c -Name $Plan.Name
    if ($current.ObjectGUID -ne $Owned.TemplateGuid -or [string]$current.'msPKI-Cert-Template-OID' -cne $Owned.OID) {throw 'Cleanup identity changed; deletion withheld.'}
    $oid=Get-ADObject -Server $c.DC -Identity $Owned.OidGuid -Properties msPKI-Cert-Template-OID
    if ([string]$oid.'msPKI-Cert-Template-OID' -cne $Owned.OID) {throw 'Cleanup OID identity changed.'}
    $cas=@(Get-ADObject -Server $c.DC -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$($c.ConfigurationDN)" -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties certificateTemplates | Where-Object {$_.certificateTemplates -contains $Plan.Name})
    if ($cas.Count) {throw 'Cleanup withheld: template is published.'}
    [xml]$xml=$Plan.Xml;$ns=[Xml.XmlNamespaceManager]::new($xml.NameTable);$ns.AddNamespace('p','http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy')
    $xml.SelectSingleNode('//p:oID[p:oIDReferenceID="1"]/p:value',$ns).InnerText=$Owned.OID
    $deletePlan=[pscustomobject]@{Xml=$xml.OuterXml;Name=$Plan.Name;Security=$Plan.Security}
    $o=Open-CTComPlan $deletePlan
    try {
        if ([string]$o.Template.Property(1) -cne $Plan.Name -or [string]($o.Template.Property(12).Value) -cne $Owned.OID) {throw 'Cleanup COM identity mismatch.'}
        $o.Writer.Commit(4,$c.DC)
    }
    finally {Close-CTComPlan $o}
    if (Get-CTTemplate -Context $c -Name $Plan.Name -Optional) {throw 'Cleanup left a template.'}
    if (@(Get-ADObject -Server $c.DC -SearchBase $c.OIDContainer -SearchScope OneLevel -LDAPFilter "(msPKI-Cert-Template-OID=$($Owned.OID))").Count) {throw 'Cleanup left an OID object.'}
}
function Invoke-CTComPlan {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Plan,[switch]$InjectVerificationFailure)
    if ((Get-CTProperty $Plan 'Backend') -eq 'NativeCertCa') {
        return Invoke-CTNativePlan -Plan $Plan -InjectVerificationFailure:$InjectVerificationFailure
    }
    $c=$Plan.Context
    if (Get-CTTemplate -Context $c -Name $Plan.Name -Optional) {throw 'Destination appeared after preparation; refusing Commit.'}
    $beforeOids=@(Get-ADObject -Server $c.DC -SearchBase $c.OIDContainer -SearchScope OneLevel -Filter *)
    $owned=$null;$committed=$false
    $o=Open-CTComPlan $Plan
    try {
        $o.Writer.Commit(1,$c.DC);$committed=$true
        $saved=Get-CTTemplate -Context $c -Name $Plan.Name
        $newOid=[string]$saved.'msPKI-Cert-Template-OID'
        $oids=@(Get-ADObject -Server $c.DC -SearchBase $c.OIDContainer -SearchScope OneLevel -LDAPFilter "(msPKI-Cert-Template-OID=$newOid)")
        if ($oids.Count -ne 1 -or $oids[0].ObjectGUID -in @($beforeOids.ObjectGUID)) {throw 'Cannot establish ownership of generated OID.'}
        $owned=[pscustomobject]@{TemplateGuid=$saved.ObjectGUID;OID=$newOid;OidGuid=$oids[0].ObjectGUID}
        if ($InjectVerificationFailure) {throw 'LAB_INJECTED_POSTCOMMIT_VERIFICATION_FAILURE'}
        $security=Get-CTSecurity -Context $c -DistinguishedName $saved.DistinguishedName
        if (-not (Test-CTDacl -Expected $Plan.Security -Actual $security)) {throw 'COM DACL read-back mismatch.'}
        foreach ($key in $Plan.Expected.Keys) {
            $actualValue=Get-CTProperty $saved $key
            if (-not (Test-CTComValue -Name $key -Expected $Plan.Expected[$key] -Actual $actualValue)) {
                $expectedText=(@(Get-CTStrings $Plan.Expected[$key]) -join '|')
                $actualText=(@(Get-CTStrings $actualValue) -join '|')
                throw "COM read-back mismatch on $($Plan.Name): $key; Expected=[$expectedText]; Actual=[$actualText]"
            }
        }
        if ($saved.DisplayName -cne $Plan.DisplayName -or [int]$saved.revision -ne 1 -or [int]$saved.'msPKI-Template-Minor-Revision' -ne 0) {throw 'Display name/revision mismatch.'}
        return [pscustomobject]@{Saved=$saved;Security=$security;OID=$newOid;Owned=$owned}
    }
    catch {
        $failure=$_
        if ($null -ne $owned) {
            try {Remove-CTComOwned -Plan $Plan -Owned $owned;Write-Warning 'COM verification failed; owned template and OID were removed.'}
            catch {Write-Warning "COM cleanup failed: $($_.Exception.Message). Inspect $($Plan.Name), OID $($owned.OID)."}
        }
        elseif ($committed) {Write-Warning "Commit succeeded but ownership/read-back failed. No blind cleanup performed. Inspect $($Plan.Name)."}
        else {Write-Warning "Commit failed. A partial native write cannot be excluded; inspect $($Plan.Name) before retrying."}
        throw $failure
    }
    finally {Close-CTComPlan $o}
}



function Initialize-CTNativeBackend {
    if (-not ('CTNativeBackendEmbeddedProbe2' -as [type])) {
        $nativeSource = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public sealed class CTNativeResultEmbeddedProbe2 {
    public string Stage;
    public bool CloneAttempted, CloneReturned, SaveAttempted, SaveReturned;
    public string Error, NativeOID;
    public List<Dictionary<string,string>> Snapshots = new List<Dictionary<string,string>>();
}

public static class CTNativeBackendEmbeddedProbe2 {
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wldap32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]
    static extern IntPtr ldap_initW(string host, uint port);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wldap32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]
    static extern uint ldap_set_optionW(IntPtr ld, int option, ref uint value);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wldap32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]
    static extern uint ldap_bind_sW(IntPtr ld, string dn, IntPtr credentials, uint method);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wldap32.dll",ExactSpelling=true)]
    static extern uint ldap_unbind(IntPtr ld);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]
    static extern int CAFindCertTypeByName(string name, IntPtr scope, uint flags, out IntPtr certType);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]
    static extern int CACloneCertType(IntPtr source, string name, string displayName, IntPtr ldap, uint flags, out IntPtr clone);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]
    static extern int CADCSetCertTypePropertyEx(IntPtr certType, string name, IntPtr value, IntPtr ldap);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",CharSet=CharSet.Unicode,ExactSpelling=true,EntryPoint="CAGetCertTypePropertyEx")]
    static extern int GetDword(IntPtr certType, string name, out uint value);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",CharSet=CharSet.Unicode,ExactSpelling=true,EntryPoint="CAGetCertTypePropertyEx")]
    static extern int GetStringArray(IntPtr certType, string name, out IntPtr values);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",ExactSpelling=true)]
    static extern int CAFreeCertTypeProperty(IntPtr certType, IntPtr values);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",ExactSpelling=true)]
    static extern int CASetCertTypeFlagsEx(IntPtr certType, uint option, uint flags);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",ExactSpelling=true)]
    static extern int CAGetCertTypeFlagsEx(IntPtr certType, uint option, out uint flags);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",ExactSpelling=true)]
    static extern int CASetCertTypeKeySpec(IntPtr certType, uint spec);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",ExactSpelling=true)]
    static extern int CAUpdateCertTypeEx(IntPtr ldap, uint flags, IntPtr certType);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",ExactSpelling=true)]
    static extern int CACloseCertType(IntPtr certType);

    static void Check(int hr, string operation) {
        if (hr != 0) throw new COMException(operation+" returned 0x"+unchecked((uint)hr).ToString("X8"),hr);
    }
    static void LdapCheck(uint code, string operation) {
        if (code != 0) throw new InvalidOperationException(operation+" returned LDAP code "+code);
    }
    static string UIntText(IntPtr h, string name) {
        uint value; int hr=GetDword(h,name,out value);
        return hr==0 ? value.ToString() : "Unavailable:0x"+unchecked((uint)hr).ToString("X8");
    }
    static string Strings(IntPtr h, string name) {
        IntPtr values=IntPtr.Zero;
        try {
            int hr=GetStringArray(h,name,out values);
            if (hr!=0) return "Unavailable:0x"+unchecked((uint)hr).ToString("X8");
            var items=new List<string>();
            if (values!=IntPtr.Zero) for (int i=0;i<128;i++) {
                IntPtr item=Marshal.ReadIntPtr(values,i*IntPtr.Size);
                if (item==IntPtr.Zero) return String.Join("|",items.ToArray());
                items.Add(Marshal.PtrToStringUni(item));
            }
            if (values!=IntPtr.Zero) throw new InvalidOperationException("Unterminated native string array");
            return "";
        } finally { if (values!=IntPtr.Zero) CAFreeCertTypeProperty(h,values); }
    }
    static void SetUInt(IntPtr h,IntPtr ld,string name,uint value) {
        IntPtr p=Marshal.AllocHGlobal(4);
        try {Marshal.WriteInt32(p,unchecked((int)value));Check(CADCSetCertTypePropertyEx(h,name,p,ld),"Set "+name);}
        finally {Marshal.FreeHGlobal(p);}
    }
    static void SetStrings(IntPtr h,IntPtr ld,string name,params string[] values) {
        IntPtr array=Marshal.AllocHGlobal((values.Length+1)*IntPtr.Size);
        var allocated=new List<IntPtr>();
        try {
            for (int i=0;i<values.Length;i++) {
                IntPtr p=Marshal.StringToHGlobalUni(values[i]);allocated.Add(p);
                Marshal.WriteIntPtr(array,i*IntPtr.Size,p);
            }
            Marshal.WriteIntPtr(array,values.Length*IntPtr.Size,IntPtr.Zero);
            Check(CADCSetCertTypePropertyEx(h,name,array,ld),"Set "+name);
        } finally {foreach(IntPtr p in allocated) Marshal.FreeHGlobal(p);Marshal.FreeHGlobal(array);}
    }
    [StructLayout(LayoutKind.Sequential)]
    struct BitBlob { public uint Length; public IntPtr Data; public uint UnusedBits; }
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]
    static extern int CASetCertTypeExtension(IntPtr certType,string oid,uint flags,IntPtr extension);
    static void SetCertificateKeyUsage(IntPtr h,byte usage) {
        IntPtr data=Marshal.AllocHGlobal(1),blob=IntPtr.Zero;
        try {
            Marshal.WriteByte(data,usage);
            uint unused=0; int bit=usage;
            while ((bit&1)==0 && unused<7) {unused++;bit>>=1;}
            var b=new BitBlob {Length=1,Data=data,UnusedBits=unused};
            blob=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(BitBlob)));
            Marshal.StructureToPtr(b,blob,false);
            Check(CASetCertTypeExtension(h,"2.5.29.15",1,blob),"Set certificate Key Usage");
        } finally {if(blob!=IntPtr.Zero) Marshal.FreeHGlobal(blob);Marshal.FreeHGlobal(data);}
    }
    static void Snapshot(CTNativeResultEmbeddedProbe2 result,IntPtr h,string stage) {
        uint flags; int hr=CAGetCertTypeFlagsEx(h,3,out flags);
        result.Snapshots.Add(new Dictionary<string,string> {
            {"Stage",stage},{"Schema",UIntText(h,"msPKI-Template-Schema-Version")},
            {"KeySize",UIntText(h,"msPKI-Minimal-Key-Size")},
            {"Algorithm",Strings(h,"msPKI-Asymmetric-Algorithm")},
            {"Hash",Strings(h,"msPKI-Hash-Algorithm")},
            {"Flags",hr==0 ? "0x"+flags.ToString("X8") : "Unavailable"}
        });
    }

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",ExactSpelling=true)]
    static extern int CASetCertTypeExpiration(IntPtr h,ref long validity,ref long renewal);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",ExactSpelling=true)]
    static extern int CACertTypeSetSecurity(IntPtr h,byte[] security);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",ExactSpelling=true)]
    static extern int CADeleteCertTypeEx(IntPtr ld,uint flags,IntPtr h);

    static IntPtr Bind(string server) {
        IntPtr ld=ldap_initW(server,389);
        if(ld==IntPtr.Zero) throw new InvalidOperationException("ldap_initW failed");
        try {
            uint version=3,on=1;
            LdapCheck(ldap_set_optionW(ld,0x11,ref version),"LDAP version 3");
            LdapCheck(ldap_set_optionW(ld,0x95,ref on),"LDAP signing");
            LdapCheck(ldap_set_optionW(ld,0x96,ref on),"LDAP sealing");
            LdapCheck(ldap_bind_sW(ld,null,IntPtr.Zero,0x486),"LDAP Negotiate bind");
            return ld;
        } catch {ldap_unbind(ld);throw;}
    }
    // Read-only preparation. In particular: never clone during WhatIf.
    public static void Preflight(string server,string sourceOid) {
        IntPtr ld=IntPtr.Zero,h=IntPtr.Zero;
        try {
            ld=Bind(server);
            Check(CAFindCertTypeByName("WebServer",ld,0xCC0,out h),"Find native baseline");
            if(h==IntPtr.Zero || Strings(h,"msPKI-Cert-Template-OID")!=sourceOid)
                throw new InvalidOperationException("Native baseline OID differs from directory preflight");
        } finally {if(h!=IntPtr.Zero)CACloseCertType(h);if(ld!=IntPtr.Zero)ldap_unbind(ld);}
    }
    static void SetKeyUsage(IntPtr h,byte[] usage) {
        if(usage==null || usage.Length<1 || usage.Length>2) throw new ArgumentException("Key Usage length");
        int length=usage.Length;
        while(length>1 && usage[length-1]==0)length--;
        int last=usage[length-1];
        if(last==0)throw new ArgumentException("Empty Key Usage");
        uint unused=0;while((last&1)==0){unused++;last>>=1;}
        IntPtr data=Marshal.AllocHGlobal(length),blob=IntPtr.Zero;
        try {
            Marshal.Copy(usage,0,data,length);
            var b=new BitBlob{Length=(uint)length,Data=data,UnusedBits=unused};
            blob=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(BitBlob)));
            Marshal.StructureToPtr(b,blob,false);
            Check(CASetCertTypeExtension(h,"2.5.29.15",1,blob),"Set certificate Key Usage");
        } finally {if(blob!=IntPtr.Zero)Marshal.FreeHGlobal(blob);Marshal.FreeHGlobal(data);}
    }
    public static CTNativeResultEmbeddedProbe2 Run(string server,string name,string displayName,string sourceOid,
        string algorithm,uint size,string hash,uint spec,uint usage,uint privateFlags,uint enrollmentFlags,
        uint subjectFlags,uint generalFlags,long validity,long renewal,byte[] certUsage,byte[] security,
        string[] providers,string[] ekus,string[] apps,string[] supersedes) {
        var r=new CTNativeResultEmbeddedProbe2();
        IntPtr ld=IntPtr.Zero,source=IntPtr.Zero,clone=IntPtr.Zero;
        try {
            r.Stage="LdapBind";ld=Bind(server);
            r.Stage="FindWebServer";
            Check(CAFindCertTypeByName("WebServer",ld,0xCC0,out source),"Find baseline");
            if(source==IntPtr.Zero || Strings(source,"msPKI-Cert-Template-OID")!=sourceOid)
                throw new InvalidOperationException("Baseline OID mismatch");
            r.Stage="Clone";r.CloneAttempted=true;
            Check(CACloneCertType(source,name,displayName,ld,3,out clone),"Clone new template");
            r.CloneReturned=true;
            if(clone==IntPtr.Zero || clone==source)throw new InvalidOperationException("Invalid/aliased clone handle");
            r.NativeOID=Strings(clone,"msPKI-Cert-Template-OID");
            if(String.IsNullOrEmpty(r.NativeOID)||r.NativeOID==sourceOid||r.NativeOID.StartsWith("Unavailable:"))
                throw new InvalidOperationException("No distinct generated OID");
            Snapshot(r,clone,"AfterClone");
            // Deliberately make the provider transition before final crypto setters.
            r.Stage="LegacyCompatibility";
            Check(CASetCertTypeFlagsEx(clone,3,privateFlags|0x100),"Set temporary legacy-provider bit");
            r.Stage="Schema4";SetUInt(clone,ld,"msPKI-Template-Schema-Version",4);
            r.Stage="ProviderTransition";
            Check(CASetCertTypeFlagsEx(clone,3,privateFlags),"Transition to KSP before final crypto");
            Snapshot(r,clone,"AfterKspTransition");
            r.Stage="Configuration";
            Check(CASetCertTypeFlagsEx(clone,4,generalFlags&0xFFFF),"Set general flags");
            Check(CASetCertTypeFlagsEx(clone,2,subjectFlags),"Set subject flags");
            Check(CASetCertTypeFlagsEx(clone,1,enrollmentFlags),"Set enrollment flags");
            Check(CASetCertTypeExpiration(clone,ref validity,ref renewal),"Set validity and renewal");
            SetUInt(clone,ld,"msPKI-RA-Signature",0);
            SetStrings(clone,ld,"pKIExtendedKeyUsage",ekus);
            SetStrings(clone,ld,"msPKI-Certificate-Application-Policy",apps);
            SetStrings(clone,ld,"msPKI-Supersede-Templates",supersedes);
            SetStrings(clone,ld,"pKICriticalExtensions",new string[]{"2.5.29.15"});
            r.Stage="FinalCryptography";
            SetStrings(clone,ld,"pKIDefaultCSPs",providers);
            SetStrings(clone,ld,"msPKI-Asymmetric-Algorithm",algorithm);
            Check(CASetCertTypeKeySpec(clone,spec),"Set KeySpec");
            SetUInt(clone,ld,"msPKI-Minimal-Key-Size",size);
            SetStrings(clone,ld,"msPKI-Hash-Algorithm",hash);
            SetUInt(clone,ld,"msPKI-Key-Usage",usage);
            SetKeyUsage(clone,certUsage);
            r.Stage="Security";Check(CACertTypeSetSecurity(clone,security),"Set exact planned security descriptor");
            Snapshot(r,clone,"BeforeSave");
            if(UIntText(clone,"msPKI-Template-Schema-Version")!="4" ||
                UIntText(clone,"msPKI-Minimal-Key-Size")!=size.ToString() ||
                Strings(clone,"msPKI-Asymmetric-Algorithm")!=algorithm ||
                Strings(clone,"msPKI-Hash-Algorithm")!=hash)
                throw new InvalidOperationException("Native pre-save crypto mismatch");
            r.Stage="NativeSave";r.SaveAttempted=true;
            Check(CAUpdateCertTypeEx(ld,0x800,clone),"Save native template");r.SaveReturned=true;
            Snapshot(r,clone,"AfterSave");r.Stage="Completed";
        } catch(Exception e){r.Error=e.ToString();}
        finally {
            if(clone!=IntPtr.Zero&&clone!=source)CACloseCertType(clone);
            if(source!=IntPtr.Zero)CACloseCertType(source);
            if(ld!=IntPtr.Zero)ldap_unbind(ld);
        }
        return r;
    }
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("certca.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]
    static extern int CAOIDDeleteEx(uint flags,IntPtr ld,string oid);
    // Called only after PowerShell rechecks owned GUID/USN and zero template references.
    public static void DeleteOwnedOid(string server,string oid) {
        IntPtr ld=IntPtr.Zero;
        try {ld=Bind(server);Check(CAOIDDeleteEx(0x800,ld,oid),"Delete owned OID registration");}
        finally {if(ld!=IntPtr.Zero)ldap_unbind(ld);}
    }
    public static void DeleteOwned(string server,string name,string oid) {
        IntPtr ld=IntPtr.Zero,h=IntPtr.Zero;
        try {
            ld=Bind(server);Check(CAFindCertTypeByName(name,ld,0xCC0,out h),"Find owned template for deletion");
            if(h==IntPtr.Zero || Strings(h,"msPKI-Cert-Template-OID")!=oid)
                throw new InvalidOperationException("Native deletion identity mismatch");
            Check(CADeleteCertTypeEx(ld,0x800,h),"Delete owned template and OID");
        } finally {if(h!=IntPtr.Zero)CACloseCertType(h);if(ld!=IntPtr.Zero)ldap_unbind(ld);}
    }
}
'@
        Add-Type -TypeDefinition $nativeSource -Language CSharp -ErrorAction Stop
    }
}

function Get-CTNativeProviderNames {
    param([Parameter(Mandatory)]$Attributes)
    $items=@(Get-CTStrings $Attributes['pKIDefaultCSPs'])
    if (-not $items.Count) {throw 'Native provider probe requires an explicit nonempty provider list.'}
    $ranked=@(foreach ($item in $items) {
        if ($item -notmatch '^([1-9][0-9]*),(.+)$') {throw 'Invalid native provider priority/name.'}
        $rank=0
        if (-not [int]::TryParse($Matches[1],[ref]$rank)) {throw 'Native provider priority exceeds Int32.'}
        [pscustomobject]@{Rank=$rank;Name=$Matches[2]}
    })
    $ranked=@($ranked | Sort-Object Rank)
    for ($i=0;$i -lt $ranked.Count;$i++) {
        if ($ranked[$i].Rank -ne $i+1) {throw 'Native provider priorities must be contiguous starting at 1.'}
        if ($ranked[$i].Name -cnotin @('Microsoft Software Key Storage Provider','Microsoft Platform Crypto Provider')) {
            throw 'Native provider probe allows Software KSP and Platform Crypto Provider only.'
        }
    }
    $names=@($ranked | ForEach-Object {$_.Name})
    if (@($names | Select-Object -Unique).Count -ne $names.Count) {throw 'Duplicate native provider names.'}
    return $names
}

function Assert-CTNativeScope {
    param($Plan)
    $a=$Plan.Expected;$crypto=$Plan.Crypto
    if ($crypto.IsLegacy) {throw 'Schema 4 native RC requires a KSP; schema-4 legacy CSP is outside RC scope.'}
    if ($crypto.Algorithm -notin 'RSA','ECDSA_P256','ECDSA_P384','ECDH_P256','ECDH_P384') {
        throw 'Schema 4 native RC supports RSA and ECDSA/ECDH P-256/P-384 only. P-521 still uses schema 3.'
    }
    $nativeProviders=@(Get-CTNativeProviderNames -Attributes $a)
    $platform=$nativeProviders -contains 'Microsoft Platform Crypto Provider'
    if ($platform -and $crypto.Algorithm -ne 'RSA') {throw 'Platform provider probe is limited to RSA.'}
    if ($platform -and (([int]$a['msPKI-Private-Key-Flag'] -band 0x10) -ne 0)) {throw 'Platform provider probe requires a nonexportable key.'}
    $rsaSizes=if ($platform) {@(2048,3072,4096)} else {@(3072,4096)}
    if ($crypto.Algorithm -eq 'RSA' -and [int]$a['msPKI-Minimal-Key-Size'] -notin $rsaSizes) {
        throw 'Schema 4 native RC limits RSA to 3072 or 4096 bits.'
    }
    if ($crypto.RequestHash -notin 'SHA256','SHA384','SHA512') {throw 'Schema 4 native RC requires SHA256/SHA384/SHA512.'}
    [uint32]$usage=0
    if (-not [uint32]::TryParse($crypto.CngKeyUsage,[ref]$usage)) {throw 'CNG usage exceeds UInt32.'}
    if ($crypto.Algorithm -eq 'RSA' -and $usage -notin 3,16777215) {throw 'Schema 4 RSA CNG usage must be 3 or 16777215.'}
    # Only known custom/built-in general bits plus the existing low word are serialized.
    if (([int]$a['flags'] -band (-bnot 0x0003FFFF)) -ne 0) {throw 'Unsupported schema-4 general flag bits.'}
    # Clone is a mutation: all unsupported settings are rejected above, before it is called.
}

function Assert-CTNativeOidCleanup {
    param([object[]]$Remaining,$Owned,[object[]]$References)
    if ($Remaining.Count -ne 1 -or $Remaining[0].ObjectGUID -ne $Owned.OidGuid -or
        [string]$Remaining[0].uSNChanged -ne $Owned.OidUSN -or [int]$Remaining[0].flags -ne 1) {
        throw 'OID cleanup withheld: identity, USN or template OID type changed.'
    }
    if ($References.Count) {throw 'OID cleanup withheld: another template references the OID.'}
}

function Remove-CTNativeOwned {
    param($Plan,$Owned)
    $c=$Plan.Context
    $current=Get-CTTemplate -Context $c -Name $Plan.Name
    if ($current.ObjectGUID -ne $Owned.TemplateGuid -or
        [string]$current.'msPKI-Cert-Template-OID' -cne $Owned.OID -or
        [string]$current.uSNChanged -ne $Owned.TemplateUSN) {throw 'Cleanup withheld: template identity or USN changed.'}
    $oid=Get-ADObject -Server $c.DC -Identity $Owned.OidGuid -Properties msPKI-Cert-Template-OID,uSNChanged
    if ([string]$oid.'msPKI-Cert-Template-OID' -cne $Owned.OID -or [string]$oid.uSNChanged -ne $Owned.OidUSN) {
        throw 'Cleanup withheld: OID identity or USN changed.'
    }
    $cas=@(Get-ADObject -Server $c.DC -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$($c.ConfigurationDN)" -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties certificateTemplates |
        Where-Object {$_.certificateTemplates -contains $Plan.Name})
    if ($cas.Count) {throw 'Cleanup withheld: template is published.'}
    [CTNativeBackendEmbeddedProbe2]::DeleteOwned($c.DC,$Plan.Name,$Owned.OID)
    if (Get-CTTemplate -Context $c -Name $Plan.Name -Optional) {throw 'Native cleanup left a template.'}
    # CADeleteCertTypeEx removed only the template in the Server 2025 RC1 test.
    # OID registration deletion is a separate API operation; re-establish ownership.
    $remaining=@(Get-ADObject -Server $c.DC -SearchBase $c.OIDContainer -SearchScope OneLevel -LDAPFilter "(msPKI-Cert-Template-OID=$($Owned.OID))" -Properties uSNChanged,flags)
    if ($remaining.Count) {
        $references=@(Get-ADObject -Server $c.DC -SearchBase $c.TemplateContainer -SearchScope OneLevel -LDAPFilter "(msPKI-Cert-Template-OID=$($Owned.OID))")
        Assert-CTNativeOidCleanup -Remaining $remaining -Owned $Owned -References $references
        [CTNativeBackendEmbeddedProbe2]::DeleteOwnedOid($c.DC,$Owned.OID)
    }
    if (@(Get-ADObject -Server $c.DC -SearchBase $c.OIDContainer -SearchScope OneLevel -LDAPFilter "(msPKI-Cert-Template-OID=$($Owned.OID))").Count) {throw 'Native cleanup left an OID object after separate OID deletion.'}
}

function Invoke-CTNativePlan {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Plan,[switch]$InjectVerificationFailure)
    $c=$Plan.Context;$a=$Plan.Expected;$crypto=$Plan.Crypto
    Assert-CTConfiguration $a
    Assert-CTNativeScope $Plan
    Initialize-CTNativeBackend
    if (Get-CTTemplate -Context $c -Name $Plan.Name -Optional) {throw 'Destination appeared after preparation; refusing native clone.'}
    $displayName=$Plan.DisplayName
    if (@(Get-ADObject -Server $c.DC -SearchBase $c.TemplateContainer -SearchScope OneLevel -Filter {displayName -eq $displayName}).Count) {
        throw 'Destination display name appeared after preparation.'
    }
    Assert-CTPolicyDependencies -Context $c -Attributes $a
    foreach ($dependency in @(Get-CTStrings $a['msPKI-Supersede-Templates'])) {$null=Get-CTTemplate -Context $c -Name $dependency}
    $baseline=Get-CTTemplate -Context $c -Name 'WebServer'
    if ($baseline.ObjectGUID -ne $Plan.NativeBaseline.Guid -or [string]$baseline.uSNChanged -ne $Plan.NativeBaseline.USN -or
        [string]$baseline.'msPKI-Cert-Template-OID' -cne $Plan.NativeBaseline.OID) {throw 'Native baseline changed after preparation.'}
    $beforeOids=@(Get-ADObject -Server $c.DC -SearchBase $c.OIDContainer -SearchScope OneLevel -Filter *)
    $owned=$null;$native=$null
    try {
        $native=[CTNativeBackendEmbeddedProbe2]::Run($c.DC,$Plan.Name,$Plan.DisplayName,$Plan.NativeBaseline.OID,
            $crypto.Algorithm,[uint32]$a['msPKI-Minimal-Key-Size'],$crypto.RequestHash,
            [uint32]$a['pKIDefaultKeySpec'],[uint32]$crypto.CngKeyUsage,
            [uint32](ConvertTo-CTComUnsigned ([int]$a['msPKI-Private-Key-Flag'])),
            [uint32](ConvertTo-CTComUnsigned ([int]$a['msPKI-Enrollment-Flag'])),
            [uint32](ConvertTo-CTComUnsigned ([int]$a['msPKI-Certificate-Name-Flag'])),
            [uint32](ConvertTo-CTComUnsigned ([int]$a['flags'])),
            [BitConverter]::ToInt64([byte[]]$a['pKIExpirationPeriod'],0),
            [BitConverter]::ToInt64([byte[]]$a['pKIOverlapPeriod'],0),
            [byte[]]$a['pKIKeyUsage'],$Plan.Security.GetSecurityDescriptorBinaryForm(),
            [string[]]@(Get-CTNativeProviderNames -Attributes $a),
            [string[]]@(Get-CTStrings $a['pKIExtendedKeyUsage']),
            [string[]]@(Get-CTStrings $a['msPKI-Certificate-Application-Policy']),
            [string[]]@(Get-CTStrings $a['msPKI-Supersede-Templates']))
        if ($native.Error -or -not $native.SaveReturned) {throw "Native failure at $($native.Stage): $($native.Error)"}
        $saved=Get-CTTemplate -Context $c -Name $Plan.Name
        $oid=[string]$saved.'msPKI-Cert-Template-OID'
        if ($oid -notmatch '^[0-2](\.[0-9]+)+$' -or $oid -cne $native.NativeOID) {throw 'Cannot establish generated native OID identity.'}
        $oids=@(Get-ADObject -Server $c.DC -SearchBase $c.OIDContainer -SearchScope OneLevel -LDAPFilter "(msPKI-Cert-Template-OID=$oid)" -Properties uSNChanged)
        if ($oids.Count -ne 1 -or $oids[0].ObjectGUID -in @($beforeOids.ObjectGUID)) {throw 'Cannot establish ownership of generated native OID object.'}
        $owned=[pscustomobject]@{TemplateGuid=$saved.ObjectGUID;TemplateUSN=[string]$saved.uSNChanged;OID=$oid;OidGuid=$oids[0].ObjectGUID;OidUSN=[string]$oids[0].uSNChanged}
        if ($InjectVerificationFailure) {throw 'LAB_INJECTED_POSTCOMMIT_VERIFICATION_FAILURE'}
        $sourceAfter=Get-ADObject -Server $c.DC -Identity $Plan.NativeBaseline.Guid -Properties uSNChanged
        if ([string]$sourceAfter.uSNChanged -ne $Plan.NativeBaseline.USN) {throw 'Native backend baseline changed during execution.'}
        $security=Get-CTSecurity -Context $c -DistinguishedName $saved.DistinguishedName
        if (-not (Test-CTDacl -Expected $Plan.Security -Actual $security)) {throw 'Native DACL/protection read-back mismatch.'}
        foreach ($key in $a.Keys) {
            if (-not (Test-CTComValue -Name $key -Expected $a[$key] -Actual (Get-CTProperty $saved $key))) {
                throw "Native read-back mismatch on $($Plan.Name): $key; Expected=[$(@(Get-CTStrings $a[$key]) -join '|')]; Actual=[$(@(Get-CTStrings (Get-CTProperty $saved $key)) -join '|')]"
            }
        }
        # Native clone/save owns revision assignment; do not impose COM's 1/0 on it.
        if ($saved.DisplayName -cne $Plan.DisplayName -or [int]$saved.revision -lt 1 -or
            $null -eq (Get-CTProperty $saved 'msPKI-Template-Minor-Revision') -or [int]$saved.'msPKI-Template-Minor-Revision' -lt 0) {throw 'Native display name/revision validation failed.'}
        return [pscustomobject]@{Saved=$saved;Security=$security;OID=$oid;Owned=$owned;Backend='NativeCertCa';Native=$native}
    }
    catch {
        $failure=$_
        if ($null -ne $owned) {
            try {Remove-CTNativeOwned -Plan $Plan -Owned $owned;Write-Warning 'Native verification failed; owned template and OID were removed.'}
            catch {Write-Warning "Native cleanup failed: $($_.Exception.Message). Inspect $($Plan.Name), OID $($owned.OID)."}
        } else {
            $details=if ($null -ne $native) {"Stage=$($native.Stage); generated OID=$($native.NativeOID)"} else {'Native result unavailable.'}
            Write-Warning "Native operation failed before ownership was established. No blind cleanup. Inspect $($Plan.Name). $details"
        }
        throw $failure
    }
}

Export-ModuleMember -Function *-CT*

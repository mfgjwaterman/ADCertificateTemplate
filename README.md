# ADCertificateTemplate 2.2.0

Create, export and import AD CS certificate templates. Configuration JSON FormatVersion remains 1.0. Import creates a NEW template/OID; it does not update the source.

## Files and requirements
Keep the three .ps1 scripts and ADCertificateTemplate.Portability.psm1 together. Native C# is embedded in the module and compiled on demand; no .cs file is required.

Use elevated 64-bit Windows PowerShell 5.1 or PowerShell 7 on Windows, AD management tools and domain connectivity. Local elevation does not grant AD PKI write permissions or CA publication permissions. Delegated directory access is required. Provision AD management tools before using PowerShell 7; automatic RSAT installation was not tested under PowerShell 7. Do not assume WindowsCompatibility/deserialized objects are equivalent to native module loading.

Lab execution covered Windows Server 2022/2025 with Windows PowerShell 5.1; PowerShell 7 testing was specifically version 7.6.9 on the Server 2025 lab host. Other PowerShell 7 versions pass the runtime gate but are not claimed as tested. See VALIDATION.md.

## Schema 4 scope
| Provider configuration | Algorithms / size | Restrictions |
|---|---|---|
| Microsoft Software Key Storage Provider only | RSA3072/4096 with SHA256/384/512; ECDSA/ECDH P-256/P-384 | Explicit selection required |
| Microsoft Platform Crypto Provider, alone or with Software KSP | RSA2048/3072/4096 with SHA256/384/512 | Nonexportable; device support determines usable sizes. TPM lab evidence covers RSA2048 only. |

Provider argument order sets priority. Ranked AD strings are decoded and sorted before passing unranked names to the native backend; directory readback verifies the persisted priorities. A mixed list permits software selection/fallback and does not guarantee TPM use. Platform KSP selection is separate from CA-enforced key attestation, which is outside this release's scope. HSM/vendor KSPs, Platform ECC, schema-4 P-521 and unrestricted provider selection are not supported by this implementation.

The retained AnyAvailable default is outside schema-4 scope: explicitly select providers. Schema 2/3 retain their existing COM path, including legacy CSP and the previously tested ECC P-521/provider scenarios. Other exclusions include private-key archival, nonzero RA signatures/max issuing depth, issuance policies, nonmatching EKU/Application Policies and nondefault symmetric settings. Unsupported populated settings fail validation rather than being silently discarded or downgraded.

## Create a template
The enrollment group must already exist. Review inherited source permissions; adding a group does not remove source permissions.

```powershell
$settings = @{
    Name = 'MWWebServer220'
    DisplayName = 'MW Web Server 2.2.0'
    SourceTemplate = 'WebServer'
    ProviderSelection = 'SelectedProviders'
    Provider = @('Microsoft Software Key Storage Provider')
    Algorithm = 'RSA'
    MinimumKeySize = 3072
    RequestHash = 'SHA256'
    EnrollmentGroup = 'GG-PKI-WebServer-Enroll'
    ValidityYears = 1
    RenewalWeeks = 6
}
.\New-ADCertificateTemplate.ps1 @settings -WhatIf
.\New-ADCertificateTemplate.ps1 @settings
```

For a TPM-oriented configuration, select Platform KSP, use a device-supported RSA size and set AllowPrivateKeyExport=$false. To allow software fallback, pass Platform then Software in the Provider array. Both provider names must be exact. A local provider inventory on a management host does not establish enrollment-client capabilities.

## Export / import
```powershell
.\Export-ADCertificateTemplate.ps1 -TemplateName 'MWWebServer220' -Path '.\template.json'
.\Import-ADCertificateTemplate.ps1 -Path '.\template.json' -Name 'MWWebServer220Copy' -DisplayName 'MW Web Server 2.2.0 Copy' -PermissionMode Preserve -WhatIf
.\Import-ADCertificateTemplate.ps1 -Path '.\template.json' -Name 'MWWebServer220Copy' -DisplayName 'MW Web Server 2.2.0 Copy' -PermissionMode Preserve
```

Preserve permissions is a same-forest option; review SID references when moving configurations. Use Get-Help on each command for parameters and other permission modes.

## Publication and failure handling
Without -Publish the template remains unpublished. -Publish requires execution on the issuing enterprise CA with a running CA service. Server selects a writable DC, not a remote CA. Publication follows verified directory creation and is reported separately. A publication failure retains verified template/OID objects for inspection; check state before retrying.

WhatIf prepares and validates but does not create template/OID objects or publish. Failed post-save verification triggers guarded cleanup only after ownership is established. Ambiguous/partial native failures can retain objects and report the stage; there is no blind deletion. Successful lab objects and certificates are not automatically cleaned up.

The schema-4 COM reset finding and native implementation were shared with Microsoft's product group. API behaviour/support confirmation remains pending. Lab success is not a Microsoft support statement. ML-DSA and ML-KEM are not implemented in 2.2.0; installing Windows updates does not extend the script's scope automatically.

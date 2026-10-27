# New-ADCertificateTemplate — version 1.2.0

Creates an RSA, ECDSA or ECDH certificate template in Active Directory from a version 1/2
source. It registers a unique template OID, copies the source DACL and inheritance
setting, applies the selected settings and verifies the saved configuration.
Optional publication uses `certutil` on the local enterprise CA.

Version 1.0.0 preserved the implementation validated in 0.2.2. Patch 1.0.1
adds forced AD template discovery before publication, based on the subsequent
MWWebServerProd lab observation.

## Requirements and installation

- Run **Windows PowerShell 5.1 as Administrator**, not PowerShell 7.
- Use a domain-connected management machine for creation. With `-Publish`, run
  on the issuing enterprise CA with the Certificate Services service running.
- The account needs AD permissions to create OID/template objects and write
  the template DACL. Publication additionally requires the appropriate CA rights.
  Local elevation alone does not grant these permissions.
- Missing ActiveDirectory tools are installed automatically: `RSAT-AD-PowerShell`
  on Windows Server, or `Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0` on supported
  Windows clients. Servicing requires an available, approved component source.
- No CA role is installed; no automatic restart occurs. If tools require a
  restart, the script stops before creating the template.
- `ADCSAdministration` is not required. Publication uses the local `certutil.exe`.

Keep the two ps1 files in the same directory when using the test runner.
The script does not change execution policy or unblock downloaded files itself.

## Quick start

```powershell
$settings = @{
    Name = 'MWWebServer01'
    DisplayName = 'MW Web Server 01'
    ProviderSelection = 'SelectedProviders'
    Provider = 'Microsoft Software Key Storage Provider'
    EnrollmentGroup = 'GG-T0-Admins'
}

# Preview: discovery and validation, no writes
.\New-ADCertificateTemplate.ps1 @settings -WhatIf -Verbose

# Create in AD, without publishing
.\New-ADCertificateTemplate.ps1 @settings -Verbose
```

To create AND publish, use a new unique name and add `-Publish` when executing
on the issuing CA. Do not rerun creation with a name that already exists.

```powershell
$settings.Name = 'MWWebServer02'
$settings.DisplayName = 'MW Web Server 02'
.\New-ADCertificateTemplate.ps1 @settings -Publish -WhatIf
.\New-ADCertificateTemplate.ps1 @settings -Publish
```

## Parameters

| Parameter | Choices / meaning | Default |
|---|---|---|
| `Name` | Unique internal name; starts with a letter; letters, digits, `_`, `-`; max 64 characters | Required |
| `DisplayName` | Template display name | Required |
| `SourceTemplate` | Internal name of a version 1/2 RSA source; WebServer, User and KerberosAuthentication validated | WebServer |
| `CACompatibility` | UI labels listed below | Windows Server 2012 R2 |
| `RecipientCompatibility` | UI labels listed below | Windows 10 / Windows Server 2016 |
| `ProviderCategory` | `Legacy Cryptographic Service Provider`, `Key Storage Provider` | Key Storage Provider |
| `ProviderSelection` | `AnyAvailable`, `SelectedProviders` | AnyAvailable |
| `Provider` | One or more exact provider names in preference order; required only for SelectedProviders | None |
| `Algorithm` | RSA; ECDSA/ECDH on P-256/P-384/P-521; ECC requires KSP | RSA |
| `MinimumKeySize` | RSA: 1024–16384 from the supported list; ECC: 256, 384 or 521 matching its curve | RSA 3072; ECC derives curve size |
| `RequestHash` | RSA KSP: SHA1/SHA2; ECC: SHA256/SHA384/SHA512; omit for legacy CSP | SHA256; P-384 SHA384; P-521 SHA512 |
| `ValidityYears` | Integer 1–100; a year is encoded as 365 days | 1 |
| `RenewalWeeks` | Integer 1–5200; must be positive and less than validity | Inherited from source |
| `SubjectNameMode` | `SupplyInRequest`, `ActiveDirectory` | SupplyInRequest |
| `ReuseSubjectOnRenewal` | Boolean; use existing Subject/SAN for autoenrollment renewals; SupplyInRequest only | False |
| `SubjectNameFormat` | `None`, `Common name`, `Fully distinguished name`, `DNS name`, `E-mail name`; AD mode only | Required in AD mode |
| `SubjectAlternativeName` | Array: `DNS name`, `Domain DNS name`, `E-mail name`, `UPN`, `SPN`, `Directory GUID`; AD mode only | None |
| `RequireManagerApproval` | Boolean: CA certificate manager approval | False |
| `AllowPrivateKeyExport` | Boolean: allow export of newly generated private keys | False |
| `ApplicationPolicy` | Additional friendly policy names or dotted OIDs; existing policies retained | No additions |
| `EnrollmentGroup` | One or more existing AD group identities | No new enrollment ACEs |
| `EnrollmentPermission` | `Enroll`, `EnrollAndAutoenroll`; requires EnrollmentGroup | Enroll |
| `Server` | Optional writable DC override | Automatically discovered |
| `Publish` | Switch: publish on the local enterprise CA | Off |
| `WhatIf`, `Confirm`, `Verbose` | Standard PowerShell common parameters | Standard behavior |

Boolean examples: `-RequireManagerApproval $true`, `-AllowPrivateKeyExport $false`.
Arrays can be passed as `@('value1', 'value2')` in a settings hashtable.

### Compatibility labels

| Certification Authority | Certificate recipient |
|---|---|
| Windows Server 2003 | Windows XP / Windows Server 2003 |
| Windows Server 2008 | Windows Vista / Windows Server 2008 |
| Windows Server 2008 R2 | Windows 7 / Windows Server 2008 R2 |
| Windows Server 2012 | Windows 8 / Windows Server 2012 |
| Windows Server 2012 R2 | Windows 8.1 / Windows Server 2012 R2 |
| Windows Server 2016 | Windows 10 / Windows Server 2016 |

CA and recipient are separate choices. They represent minimum versions, not the
actual OS. KSP requires at least CA2008/Vista. In this implementation a 2012+
choice selects schema 4 and requires both sides to be 2012+/Windows8+; otherwise
KSP selects schema 3 and legacy CSP selects schema 2. Inconsistent combinations
are rejected. Newer OS versions do not require a matching year in these labels.

CEP/CES has a documented limitation with Windows10/Server2016 template
compatibility. If that enrollment route is used, assess the CA2012R2 and
Windows8.1/Server2012R2 settings instead. CEP/CES was not part of these script tests.

### Friendly application policy names

| Name | OID |
|---|---|
| Server Authentication | 1.3.6.1.5.5.7.3.1 |
| Client Authentication | 1.3.6.1.5.5.7.3.2 |
| Code Signing | 1.3.6.1.5.5.7.3.3 |
| Secure Email | 1.3.6.1.5.5.7.3.4 |
| Time Stamping | 1.3.6.1.5.5.7.3.8 |
| OCSP Signing | 1.3.6.1.5.5.7.3.9 |

Application policies are additive and deduplicated separately in the EKU and
Application Policy attributes. Adding Client Authentication to User retains its
Secure Email and Encrypting File System purposes. Adding policies does not create
a purpose-specific security profile; choose the source and final purposes deliberately.

## Examples

### Computer DNS subject/SAN with autoenrollment

```powershell
$settings = @{
    Name = 'MWComputer01'
    DisplayName = 'MW Computer 01'
    ProviderSelection = 'SelectedProviders'
    Provider = 'Microsoft Software Key Storage Provider'
    SubjectNameMode = 'ActiveDirectory'
    SubjectNameFormat = 'DNS name'
    SubjectAlternativeName = 'DNS name'
    ApplicationPolicy = 'Client Authentication'
    EnrollmentGroup = 'GG-Lab-Certificate-Computers'
    EnrollmentPermission = 'EnrollAndAutoenroll'
    Publish = $true
}
.\New-ADCertificateTemplate.ps1 @settings -WhatIf
.\New-ADCertificateTemplate.ps1 @settings
```

The group must contain the requesting COMPUTER account. Computer autoenrollment
also needs the applicable GPO. DNS values are derived from the computer's AD
attributes. A user's enrollment rights do not automatically grant computer rights.

### User with UPN and email SANs

```powershell
.\New-ADCertificateTemplate.ps1 `
    -Name MWUserMultiSAN01 -DisplayName 'MW User Multi SAN 01' `
    -SourceTemplate User `
    -SubjectNameMode ActiveDirectory `
    -SubjectNameFormat 'Common name' `
    -SubjectAlternativeName @('UPN', 'E-mail name') `
    -EnrollmentGroup 'GG-T0-Admins' -Publish
```

Enroll in CurrentUser context. Both userPrincipalName and mail must be populated.
This example retains User's existing EKUs and permissions.

### Server request with multiple DNS SANs

```powershell
.\New-ADCertificateTemplate.ps1 `
    -Name MWWebMultiSAN01 -DisplayName 'MW Web Multi SAN 01' `
    -ProviderSelection SelectedProviders `
    -Provider 'Microsoft Software Key Storage Provider' `
    -SubjectNameMode SupplyInRequest `
    -EnrollmentGroup 'GG-T0-Admins' -Publish
```

The DNS values are supplied in the certificate request, not stored as a fixed
list in the template. In the enrollment wizard add each DNS SAN separately, for
example web01.example.test, portal.example.test and api.example.test.

### Approval, export, renewal and legacy provider

```powershell
.\New-ADCertificateTemplate.ps1 `
    -Name MWApproval01 -DisplayName 'MW Approval 01' `
    -MinimumKeySize 4096 -RequestHash SHA384 `
    -ValidityYears 2 -RenewalWeeks 8 `
    -ReuseSubjectOnRenewal $true `
    -RequireManagerApproval $true -AllowPrivateKeyExport $true `
    -EnrollmentGroup 'GG-T0-Admins'

.\New-ADCertificateTemplate.ps1 `
    -Name MWLegacy01 -DisplayName 'MW Legacy 01' `
    -ProviderCategory 'Legacy Cryptographic Service Provider' `
    -ProviderSelection SelectedProviders `
    -Provider 'Microsoft Enhanced RSA and AES Cryptographic Provider' `
    -CACompatibility 'Windows Server 2003' `
    -RecipientCompatibility 'Windows XP / Windows Server 2003' `
    -MinimumKeySize 2048 -EnrollmentGroup 'GG-T0-Admins'
```

Legacy CSP shows Determined by CSP; do not pass RequestHash. The request hash
signs the CSR. The CA's certificate signature hash is independently configured.

## Permissions, publication and failure behavior

- Source DACL, inheritance protection and source permissions are preserved;
  source owner and SACL are not copied. New groups receive the requested grants.
- Source rights are not reduced. A source may already grant broader enrollment,
  autoenrollment or administrative permissions. In particular, review User's ACL.
- Canonical allow-only DACLs are compared independently of equivalent ACE order
  and merging. SID, ACE type, flags, object GUIDs, rights and protection remain
  checked. Other DACLs use strict comparison. Differences are logged with Verbose.
- Missing dependencies are handled before object creation. WhatIf writes nothing.
  If AD tools are missing, WhatIf cannot perform AD validation and says so.
- Creation/verification failure attempts to remove only the template and OID
  created by that run. Cleanup failures are reported, including object identity.
- Publication happens only after successful verification. The `+` in
  `certutil -SetCATemplates "+<name>"` adds the template to the CA list.
- Before publication, `certutil -f -ADTemplate <name>` refreshes template discovery.
  Its exit code must be zero AND its output must contain the expected internal
  name. A zero exit code with no template is treated as a discovery failure.
- Publication success requires exit code zero and an issuance-list entry for the
  exact internal name. `Auto-Enroll: Access is denied` is expected for Enroll-only
  identities and is not treated as a publication failure.
- Publication failure keeps the verified AD objects. Inspect `PublicationStatus`
  and `PublicationError`; a warning and result object are returned. Creation
  failures throw. Publication failure does not automatically throw a terminating
  error: automation must inspect the returned status.
- Do not rerun creation to retry publication. Publish the existing template
  separately after checking CA state and AD visibility.

```powershell
certutil -config 'CAHOST\CAName' -SetCATemplates '+ExistingTemplateName'
certutil -config 'CAHOST\CAName' -CATemplates ExistingTemplateName
```

Existing templates are never overwritten. This is a creation tool, not an update,
remove or template-publication-only command.

## Domain DNS names for Kerberos templates

In ActiveDirectory mode, `-SubjectAlternativeName 'DNS name','Domain DNS name'`
requests host DNS plus domain DNS/NetBIOS names. With SubjectNameFormat None,
name flags are 0x08400000; with DNS name as the subject format, 0x18400000.
Use the computer enrollment context and appropriate Read/Enroll permissions.
Both subject variants and imported-template issuance passed in the lab.

The generator applies its parameter defaults; selecting a source is not a
promise to preserve every source setting unchanged. Review with -WhatIf and
inspect the created template before publishing.

## ECC and parameter completion

See ALGORITHMS.md for all curve sizes, hashes, purpose and usage mappings.
RSA remains the default. ECDH uses CNG AllUsages 16777215 while the issued
certificate Key Usage remains Key Agreement only. Existing templates are not
changed when replacing these files.

Use Tab or Ctrl+Space after parameter names to see choices. Provider discovery
uses the local machine, not the eventual enrollment client. Manual provider
names and numeric application policy OIDs remain accepted. See COMPLETION.md.

## Validation

See README.md for the 27 October 2026 lab record and scope. The final runtime
files retain the tested rc7 logic, with version strings changed to 1.2.0.
Development tests and test plans are not part of this download.

```powershell
Get-Help .\New-ADCertificateTemplate.ps1 -Full
```

# AD Certificate Template Tools 1.2.0

PowerShell scripts to create AD CS certificate templates and export/import their
configuration. RSA is the default. ECDSA and ECDH support P-256, P-384 and P-521.
Release date: 27 October 2026. JSON FormatVersion remains 1.0.

## Files

| File | Purpose |
|---|---|
| New-ADCertificateTemplate.ps1 | Create a new template with configurable settings |
| Export-ADCertificateTemplate.ps1 | Export supported template configuration and a DACL snapshot to JSON |
| Import-ADCertificateTemplate.ps1 | Import as a new template with a fresh OID |
| ADCertificateTemplate.Portability.psm1 | Required shared module for export/import |
| CREATOR.md | Generator parameters and examples |
| EXPORT-IMPORT.md | Portability, permissions and dependencies |
| ALGORITHMS.md | RSA/ECDSA/ECDH profiles and limits |
| COMPLETION.md | Tab/Ctrl+Space choices and provider discovery |
| CHANGELOG.md | Changes and upgrade notes |
| SHA256SUMS.txt | SHA256 checksums for the other files |

Extract the complete package and keep the files together. The generator is
standalone; export/import require the supplied module beside them. These are
custom scripts, not built-in Microsoft cmdlets. Development tests and test plans
are not included in this distribution.

## Requirements

Run in elevated Windows PowerShell 5.1 with appropriate AD permissions. A writable
DC is discovered automatically. Missing AD PowerShell tools can be installed
automatically if a Windows component source is available. WhatIf does not install
tools or write configuration; directory reads still require available AD tools.
No CA role is installed and no automatic reboot is performed.

Publication is optional. For `-Publish`, run on the local issuing enterprise CA
with the required CA permissions. Publication uses certutil with forced template
discovery and issuance-list verification; ADCSAdministration is not required.
Publication may also be a separate action on the CA.

## Create

Use an existing source and a fresh unique name. The generator applies its own
parameter defaults; it is not an exact clone of every source setting.

```powershell
$Settings = @{
    SourceTemplate    = 'WebServer'
    Name              = 'ExampleWeb01'
    DisplayName       = 'Example Web 01'
    ProviderCategory  = 'Key Storage Provider'
    ProviderSelection = 'SelectedProviders'
    Provider          = 'Microsoft Software Key Storage Provider'
    EnrollmentGroup   = 'GG-PKI-WebServer-Enroll'
}
.\New-ADCertificateTemplate.ps1 @Settings -WhatIf -Verbose
.\New-ADCertificateTemplate.ps1 @Settings -Verbose
```

Use a group that exists in your environment. Source permissions and DACL
inheritance protection are copied, with any explicitly requested enrollment
groups added. Owner and audit ACL are not copied. See CREATOR.md for parameters.
Use Tab/Ctrl+Space directly on parameters for available choices; ordinary
hashtable values do not inherit parameter completion in PowerShell 5.1.

## Export and import

```powershell
.\Export-ADCertificateTemplate.ps1 `
    -TemplateName 'ExampleWeb01' -Path '.\ExampleWeb01.json'

$Import = @{
    Path           = '.\ExampleWeb01.json'
    Name           = 'ExampleWebImported01'
    DisplayName    = 'Example Web Imported 01'
    PermissionMode = 'Preserve'
}
.\Import-ADCertificateTemplate.ps1 @Import -WhatIf -Verbose
.\Import-ADCertificateTemplate.ps1 @Import -Verbose
```

Preserve copies the exported DACL and inheritance state in the same forest;
owner and audit ACL are not transferred. TargetBaseline is the default permission
mode and uses a destination baseline instead. Preserve is rejected across
forests. Cross-forest TargetBaseline behavior still needs dedicated validation.

Imports always create a new identity and OID. They do not overwrite a template
or perform an identity-preserving disaster recovery restore. JSON contains
configuration/account metadata, not certificates or private keys. Unsupported
populated PKI fields are rejected instead of silently dropped.

## Publication and verification

Creation/import does not publish unless `-Publish` is supplied. To publish
separately, run on the CA with the actual CA configuration and template name:

```powershell
certutil -f -ADTemplate ExampleWebImported01
certutil -config 'CAHOST\CAName' -SetCATemplates '+ExampleWebImported01'
certutil -config 'CAHOST\CAName' -CATemplates ExampleWebImported01
```

Verified True means the saved configuration and DACL passed read-back checks.
It does not prove issuance or application interoperability. Inspect the template
in certtmpl.msc and test actual enrollment. With -Publish, also inspect Published,
PublicationStatus and PublicationError. Publication failure retains the verified
template for a later retry. Existing template names are never overwritten.

## Validation record

Windows lab feedback received on 27 October 2026:

| Area | Observed result |
|---|---|
| Development configuration/OID/ACL suite | 155 passed, 0 failed |
| Parameter completion suite | 30 passed, 0 failed; local KSP/CSP enumeration |
| ECDH P-256, P-384, P-521 | Fresh rc7 creation, publication, enrollment and real private-key agreement passed |
| ECDH P-256, P-384, P-521 imports | Same-forest Preserve export/import, issuance and real private-key agreement passed |
| ECDSA P-256/P-384 | Creation, issuance, export/import and private-key signing passed |
| ECDSA P-521 | Issuance and private-key signing passed |
| Kerberos SAN options | Host/domain DNS SANs with empty or DNS CN subject, plus imported-template issuance, passed |
| RSA regression | RSA3072 issuance passed |
| OID registration cleanup | Deterministic name matched UI-created template; MMC deletion removed template and OID objects in earlier creator/importer tests |

The successful ECDH key tests confirmed matching secrets on both sides, the
certificate's public key matching the private key, and different secrets for a
different peer. These are cryptographic tests, not EFS file-encryption or complete
application-protocol tests. The ECDH tests used Microsoft Software KSP on the lab
systems. They do not establish compatibility with every provider, OS or source.

Final runtime logic is unchanged from tested rc7 apart from version strings.
This final package has syntax and archive/checksum validation in the build
environment; it has not had a separate complete Windows live rerun. The internal
test-suite module selection was made explicit after the earlier multi-module
session issue; that test-only adjustment has syntax validation and is not shipped.

Not established by these tests: cross-forest imports, full trust/revocation or
TLS/EFS application behavior, actual legacy OS interoperability, or ECDSA P-521
live export/import. EC archival and schema 1 export/import are outside scope.

## Upgrade notes

ECDH uses CNG AllUsages 16777215, matching the working UI-created control. The
certificate Key Usage remains Key Agreement only. Earlier ECDH candidates using
CNG value 4 could fail request creation with NTE_PERM. Such exports are rejected;
correct the source and re-export, or create a new template. Replacing scripts
does not repair existing templates or certificates and does not rewrite JSON.

Deterministic OID registration names use the final OID arc followed by the MD5
of the full OID encoded as UTF-16LE without a terminator. Older GUID-named OID
registrations are not automatically renamed or removed. Never change template
OIDs or delete OID registrations as blanket cleanup. Deleting a template does
not revoke certificates already issued from it.

These tools write directly to AD and have not been migrated to the CertEnroll
COM template API. Lab success does not establish a Microsoft support statement
for direct AD template automation.

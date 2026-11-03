# ADCertificateTemplate 2.1.0

PowerShell tools to create AD CS certificate templates and export/import their configuration. Release date: **3 November 2026**. JSON configuration format remains **1.0**.

Schema 2/3 uses the existing CertEnroll COM implementation. Schema 4 KSP uses the native `certca.dll` sequence validated in the lab: compatibility/schema first, provider transition next, final cryptography last. This avoids the late crypto reset observed with the investigated schema-4 COM save path. No debugger, DLL patch or direct template/OID AD write cmdlets are used.

**Microsoft PG confirmation of the native API support status is pending.** The validation below describes observed behavior within the tested scope, not a Microsoft support statement.

## Installation

Extract the complete package into a separate directory. Keep these files together:

| File | Purpose |
|---|---|
| `New-ADCertificateTemplate.ps1` | Create a new template from a version-1/2 RSA source |
| `Export-ADCertificateTemplate.ps1` | Export supported configuration and a DACL snapshot |
| `Import-ADCertificateTemplate.ps1` | Import as a new template with a fresh OID |
| `ADCertificateTemplate.Portability.psm1` | Shared validation, backends and verification |
| `ADCertificateTemplate.Native.cs` | Required schema-4 native API wrapper |
| `TESTING.md` / `VALIDATION.md` | Test commands, evidence and limits |
| `RELEASE-NOTES.md` | Changes and upgrade notes |
| `SHA256SUMS.txt` | SHA256 hashes of the other package files |

Use a fresh, elevated **64-bit Windows PowerShell 5.1** session. Domain connectivity, a writable DC and delegated permissions to create templates/OIDs and apply security are required. Local elevation alone does not grant AD permissions. Missing AD tools can be installed through Windows servicing after ShouldProcess approval; no CA role is installed and no automatic reboot is performed.

For `-Publish`, run on the local enterprise issuing CA with CertSvc running and appropriate CA permissions. Other template operations do not require a local CA role. Do not mix files or loaded modules from different releases.

## Implemented scope

| Area | Schema 4 native route | Schema 2/3 COM route |
|---|---|---|
| Crypto | RSA 3072/4096; ECDSA/ECDH P-256/P-384 | Existing RSA and ECDSA/ECDH P-256/P-384/P-521 scope |
| Request hash | Explicit SHA256/SHA384/SHA512 | Existing SHA1/SHA2 validation; legacy CSP determines its request hash |
| Providers | Exactly Microsoft Software Key Storage Provider | Selected single/multiple providers or any-provider configurations in existing scope |
| Legacy CSP | Rejected | Schema 2 RSA |
| Subject | Supplied subject or supported AD-derived subject/SAN flags | Same existing options |
| Policies | Matching, explicit, nonempty EKU and Application Policies; critical Key Usage | Same existing restrictions |
| Permissions | Same-forest Preserve or TargetBaseline; optional Read/Enroll/Autoenroll groups | Same existing options |
| Other | Supported flags, validity/renewal in whole seconds, supersedence | Same existing options |

Private-key archival, nonzero RA signatures or maximum issuing depth, populated issuance/RA policies, other critical extensions, unsupported embedded crypto properties and nondefault symmetric properties are rejected before writes. Export can retain a schema-4 configuration outside the importer scope; exportability of configuration does not imply that every exported profile can be imported.

The creator retains the previous **AnyAvailable** provider default. For schema 4, explicitly select Software KSP; unsupported provider choices are rejected rather than substituted. Schema-4 RSA accepts CNG usage 3 (creator profile) or 16777215 (MMC-style profile). EC retains its family-specific KeySpec, CNG usage and certificate Key Usage validation.

## Create

Use an existing enrollment group and a new, unique name:

```powershell
$settings = @{
    Name              = 'ExampleWeb01'
    DisplayName       = 'Example Web 01'
    SourceTemplate    = 'WebServer'
    ProviderCategory  = 'Key Storage Provider'
    ProviderSelection = 'SelectedProviders'
    Provider          = @('Microsoft Software Key Storage Provider')
    Algorithm         = 'RSA'
    MinimumKeySize    = 3072
    RequestHash       = 'SHA256'
    ValidityYears     = 1
    RenewalWeeks      = 6
    EnrollmentGroup   = @('GG-PKI-WebServer-Enroll')
}
.\New-ADCertificateTemplate.ps1 @settings -WhatIf
.\New-ADCertificateTemplate.ps1 @settings
```

Modern CA/recipient compatibility defaults select schema 4. To select the existing schema-3 KSP or schema-2 legacy route, explicitly use pre-2012 minimum compatibility declarations, such as:

```powershell
-CACompatibility 'Windows Server 2008 R2' `
-RecipientCompatibility 'Windows 7 / Windows Server 2008 R2'
```

These declarations describe minimum compatibility, not the executing OS. There is no silent schema downgrade. The creator applies parameter defaults; it is not an exact clone of every source property. SourceTemplate supplies supported configuration and permissions. Internally the schema-4 backend uses the built-in WebServer template as a serialization baseline, then applies the complete validated plan.

Use `Get-Help .\New-ADCertificateTemplate.ps1 -Full` for parameters. Completion supports Tab/Ctrl+Space on command parameters; ordinary hashtable values do not inherit parameter completion in PowerShell 5.1.

## Export and import

```powershell
.\Export-ADCertificateTemplate.ps1 `
    -TemplateName ExampleWeb01 -Path .\ExampleWeb01.json

$import = @{
    Path           = '.\ExampleWeb01.json'
    Name           = 'ExampleWebImported01'
    DisplayName    = 'Example Web Imported 01'
    PermissionMode = 'Preserve'
}
.\Import-ADCertificateTemplate.ps1 @import -WhatIf
.\Import-ADCertificateTemplate.ps1 @import
```

Preserve requires the same forest and carries the exported DACL/inheritance protection, not owner or SACL. TargetBaseline is the default and uses a destination permission baseline; review destination enrollment groups explicitly. Cross-forest behavior has not been live-tested. Supersedence references are omitted unless IncludeSupersededTemplates is requested and destination dependencies resolve. JSON contains configuration/account metadata, not certificates or private keys.

Omit Server for writable DC discovery, or supply it explicitly. Imports always create a new identity and OID. Existing templates are not overwritten. This is configuration portability, not an identity-preserving disaster recovery restore.

## Publication, verification and failures

Creation/import leaves the template unpublished unless Publish is supplied. Publication runs separately after successful saved-state verification. Inspect `Backend`, `Verified`, `Published`, `PublicationStatus`, `PublicationError` and `PublicationCA` in the returned result. A publication failure retains the verified template and OID for inspection and a later publication attempt.

WhatIf performs directory reads and in-memory preparation but no clone, save, delete or publication. Native preflight does not clone: cloning can allocate an OID and occurs only after ShouldProcess approves the mutation. General custom-template flags, embedded native 3DES/168 defaults, crypto-property ordering and trailing zero Key Usage bytes retain the existing explicit normalization rules; no unexpected setting reset is accepted.

After saving, configuration, provider/crypto settings and DACL/protection are read back from the selected DC. Fresh identity/OID ownership and unchanged native baseline are checked. Native revision allocation differs from COM; schema 4 checks valid revision metadata without imposing COM's 1/0 pair.

A verification failure triggers cleanup only after ownership is established. Native cleanup guards template/OID GUID, OID value, USN and absence of publication; after template deletion it separately deletes the owned OID registration if still present, with renewed identity/type/reference checks. Absence is verified. Partial clone/save failures before ownership capture retain potentially created objects and report stage/name/OID for inspection. Operations are not transactional; do not blindly rerun a failed write.

Explicit Autoenroll ACEs must agree with enrollment flag 0x20. Creator requests with additional Autoenroll groups set that flag; import rejects contradictory exported intent. This consistency check is not a full effective-permission calculation.

## Validation and limitations

The tested RC2 runtime is retained for 2.1.0; final packaging changes version labels, test version checks and documentation. See [VALIDATION.md](VALIDATION.md) for exact scope and build versions.

- Schema-4 create/import and native rollback passed from Server 2022 and Server 2025.
- The integrated Server 2025 run passed eight published imports, certificate enrollment and RSA/ECDSA/ECDH private-key tests.
- Schema-4 subject/SAN, policy, interval, approval/exportability flag, permissions and supersedence storage checks passed for six create/import cases.
- Schema-2/3 regressions passed 18 create/import cases, COM rollback, six feature checks and 20 negative checks.
- Workstation machine-account enrollment and schema-4 autoenrollment passed; the lifecycle event identifies the workstation account, machine context and target template/thumbprint.
- Denied AD writes were rejected with 0x80070005 and no PKI snapshot changes. Injected publication faults preserved verified templates/OIDs and unchanged CA publication state.

Not established: Microsoft support status, actual CA authorization-denied publication, approval/rejection workflow, PFX export workflow, renewal behavior, all providers/OS builds, cross-forest imports, full TLS/EFS application behavior, CSR hash verification or trust/revocation validation. Stored flags and successful issuance alone do not prove those workflows.

## Lab tests

See [TESTING.md](TESTING.md). Test scripts are optional and do not run automatically. They create real objects when mutation switches are supplied; successful objects normally remain. Scripts with historical COM/RC names use their adjacent release commands/module, not an older implementation.

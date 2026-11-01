# ADCertificateTemplate 2.0.0

Version 2.0.0, 1 November 2026. This major release replaces the direct-AD write implementation with native CertEnroll COM for the supported scope. It creates and imports new AD CS templates. Derived from the original 1.2.0 commands; export retains `ADCertificateTemplate.Configuration` format version `1.0`.

Version 2.0.0 follows the published 1.2.0 release. The major version reflects breaking compatibility changes: schema 4 and several previously available configuration paths are rejected, and the retained modern compatibility defaults require explicit overrides. It is not a full feature-parity replacement or a Microsoft support statement.

The implementation was exercised in the COM release candidates; the final negative checks completed with **20 passed, 0 failed**. The earlier 0.2.0 labels were development labels, not the public successor version. See [RELEASE-NOTES.md](RELEASE-NOTES.md) for migration details and [VALIDATION.md](VALIDATION.md) for the test history.

## Installation and requirements

Extract into a separate directory. Keep the three commands, companion module and three test scripts in the repository root. The test scripts resolve their companion files relative to their own location. Preserve the original working release and do not mix modules between releases.

- Elevated, **64-bit Windows PowerShell 5.1** on Windows, domain connectivity and a writable DC.
- Delegated AD permissions to create template/OID objects and apply template permissions. Local elevation does not grant AD permissions.
- ActiveDirectory management tools. Commands can install missing tools using Windows servicing; WhatIf does not install them. No automatic reboot or CA role installation.
- For `-Publish`, run on the local enterprise issuing CA with CertSvc running and appropriate CA permissions. Publication uses certutil, forced template discovery and issuance-list verification.

## Supported scope

| Area | Scope |
|---|---|
| Create | New template from a version 1/2 RSA baseline, such as WebServer or User |
| Import | New template from supported original-format JSON; fresh native OID |
| Crypto | Schema 3 RSA, ECDSA/ECDH P-256/P-384/P-521; schema 2 legacy RSA |
| Providers | Selected single/multiple providers with priorities, or any available provider |
| Naming | Supplied subject, supported AD-derived subject/SAN flags, reuse on renewal |
| Policies | Matching, nonempty EKU and explicit Application Policies; critical Key Usage |
| Permissions | Same-forest Preserve or TargetBaseline, additional Read/Enroll/Autoenroll groups |
| Other | Whole-second validity/renewal intervals, supported flags, supersedence names |
| Publication | Optional local enterprise CA publication after successful verification |

Provider configuration does not prove provider availability on clients or TPM-backed key operation. Supersedence storage does not prove automatic client certificate replacement. Certificate issuance does not prove every application can use the resulting certificate.

## Schema 4 and compatibility

**Schema 4 creation/import is blocked** because the lab reproduced a native COM crypto-reset defect. No silent schema downgrade is performed. The original modern compatibility defaults remain; a default creator invocation therefore fails before AD writes. Explicitly use the following minimum compatibility declarations for the supported COM route:

```powershell
-CACompatibility 'Windows Server 2008 R2' `
-RecipientCompatibility 'Windows 7 / Windows Server 2008 R2'
```

These declarations do not describe the current OS version. Do not edit an export's schema to bypass the guard. Export may preserve a schema 4 configuration that this importer cannot apply.

Other rejected configurations include private-key archival; nonzero RA signatures or maximum issuing depth; populated certificate issuance policies or RA policies; unsupported embedded crypto properties; nondefault symmetric properties; missing/different Application Policies versus EKU; and other critical extensions. Unsupported configurations fail before the native save.

## Example: create

```powershell
$Create = @{
    Name                   = 'ExampleCOMWeb01'
    DisplayName            = 'Example COM Web 01'
    SourceTemplate         = 'WebServer'
    CACompatibility        = 'Windows Server 2008 R2'
    RecipientCompatibility = 'Windows 7 / Windows Server 2008 R2'
    ProviderCategory       = 'Key Storage Provider'
    ProviderSelection      = 'SelectedProviders'
    Provider               = 'Microsoft Software Key Storage Provider'
    Algorithm              = 'RSA'
    MinimumKeySize         = 3072
    RequestHash            = 'SHA256'
    EnrollmentGroup        = @('GG-T0-Admins')
}
.\New-ADCertificateTemplate.ps1 @Create -WhatIf
# After reviewing the intended new object:
.\New-ADCertificateTemplate.ps1 @Create
```

Omit `-Server` for writable DC discovery, or supply the intended DC explicitly. The example leaves the template unpublished and uses a subject supplied in the request. Add `-Publish` only on the issuing CA when publication is intended.

## Example: export and import

```powershell
.\Export-ADCertificateTemplate.ps1 -TemplateName ExampleCOMWeb01 -Path .\ExampleCOMWeb01.json

$Import = @{
    Path           = '.\ExampleCOMWeb01.json'
    Name           = 'ExampleCOMWebImported01'
    DisplayName    = 'Example COM Web Imported 01'
    PermissionMode = 'Preserve'
}
.\Import-ADCertificateTemplate.ps1 @Import -WhatIf
.\Import-ADCertificateTemplate.ps1 @Import
```

`Preserve` checks the forest GUID and is limited to the same forest. `TargetBaseline` derives permissions from the destination baseline (`WebServer` by default); review destination enrollment groups separately. Cross-forest behavior has not been live-tested. Superseded-template references are omitted unless `-IncludeSupersededTemplates` is supplied and destination dependencies resolve.

JSON contains configuration and a DACL snapshot, not certificates or private keys. Protect and review it as security configuration. Source identity/OID are metadata; import generates a new template/OID and does not overwrite an existing template.

## Autoenrollment consistency

Creator requests with enrollment groups and `EnrollAndAutoenroll` explicitly set enrollment flag `0x20` as well as the ACL entries. Import preserves exported enrollment flags and rejects an explicit Allow Autoenroll ACE when that flag is missing. It does not silently enable autoenrollment or mask the native read-back mismatch. This is a consistency check on explicit ACEs, not a full effective-permission calculation.

## Verification and cleanup

New/Import prepare the in-memory XCEP/COM configuration before ShouldProcess. After Commit, the shared backend verifies serialized attributes, DACL/protection, display name and revisions. General flags explicitly account for the observed native custom bit `0x20000`, removing built-in bit `0x10000`; other bits remain exact. Comparisons normalize CNG property ordering/trailing delimiter and trailing zero Key Usage bytes. Native embedded 3DES/168 defaults are explicit; they do not describe the certificate public-key algorithm.

For a verification failure after ownership is captured, guarded COM deletion checks template/OID identities and publication, then verifies absence. A failure inside Commit or before ownership capture requires inspection; automatic recovery of partial native failure is not guaranteed. AD operations are not transactional.

Publication occurs separately after successful verification. A publication failure retains the verified template and reports the publication error; it does not delete the template. Inspect the result before retrying publication. WhatIf performs reads and in-memory preparation but no template/OID writes or publication.

## Regression commands

Use unused RunIds; successful lab templates remain. The historical `COMRC1` name prefix in the harness does not select an old implementation. The adjacent commands/module determine the implementation.

```powershell
.\Test-COMCandidate.ps1 -RunId R04 -Extended -TestRollback
.\Test-COMCandidate.ps1 -RunId R04 -Extended -TestRollback -Create

.\Test-COMCandidateFeatures.ps1 -RunId R04
.\Test-COMCandidateFeatures.ps1 -RunId R04 -Create
```

The main regression creates nine source profiles and nine imports, all unpublished, and tests one deliberate post-save verification failure/rollback. The feature harness covers AD subject/SAN, provider priorities, permissions and supersedence. These are lab commands that create real AD objects when `-Create` is supplied; neither harness is a production cleanup tool.

The negative-check harness is included as well:

```powershell
.\Test-COMCandidateNegative.ps1 -Server '<writable DC FQDN>' -SourceTemplate '<existing valid RSA KSP template>' | Format-List
```

It exports the existing source to temporary local JSON, checks validation/collision failures using WhatIf, and compares template/OID GUID-USN and CA publication snapshots. It never requests Commit. The source must be a supported schema 3 RSA KSP configuration; the lab used COMRC1RSA_R03. The valid control must succeed before rejection results are meaningful.

See [RELEASE-NOTES.md](RELEASE-NOTES.md) for this package's changes and [VALIDATION.md](VALIDATION.md) for evidence and limits.

# AD Certificate Template Export / Import — v1.2.0

Companion tools for the tested New-ADCertificateTemplate script. They do not
modify that script or existing templates. Unzip the entire folder: the shared
`ADCertificateTemplate.Portability.psm1` is required beside both scripts.

**Validation:** a same-forest RSA KSP schema 4 round trip was reported successful
in the Windows lab: export, WhatIf, Preserve import, UI settings and group
Read/Enroll permissions, manual CA publication, certificate enrollment, then
removal through certtmpl.msc with both template and OID registration confirmed
absent. The Kerberos RSA profile also passed export/import and enrollment after the
KDC OID correction; this does not establish every supported combination. Cross-forest and TargetBaseline still need
separate lab tests. The local PowerShell regression suite is included; it was
not executed in the build environment.

Version 1.1.0 includes the OID object-name correction in the importer.
JSON FormatVersion remains 1.0; existing 0.1.0 exports remain readable.
Keep all scripts and the module from this release together.

## What is transferred?

| Item | Export | Import |
|---|---|---|
| Cryptography, compatibility, key size, request hash | Exact underlying attributes | Preserved, not rebuilt from defaults |
| Validity and renewal periods | Exact eight-byte binary values encoded as Base64 | Original duration bytes restored |
| Subject/SAN flags, approval and key export | Integer flag values | Preserved |
| Application policies and EKUs | String arrays | Preserved independently; no extra purposes added |
| Providers and preference numbers | String arrays | Preserved |
| Source template name, OID, object GUID, forest and revisions | Metadata | Not used as the new template identity |
| New name / display name | Source values recorded | New Name required; DisplayName can be supplied |
| Template OID / OID registration | Original OID recorded for provenance | Fresh OID under the destination forest's base |
| Revision counters | Metadata | New template starts with revision 1 / minor 0 |
| DACL | Binary snapshot plus readable account/SID/rules | Explicit permission mode; see below |
| Owner and audit ACL | Not exported as transferable security | Not copied |
| AD system attributes | Not exported as configuration | Not restored |
| CA publication | Not exported | Optional local `-Publish`; never inherited from source |
| Private keys or issued certificates | Not exported | Not imported |
| Superseded-template references | Recorded if present | Omitted by default; optional explicit inclusion |

The original template remains intact. Import creates another template; it is
not disaster recovery or an update operation. Existing names cause a stop.

## Initial supported scope

- Custom schema version **2, 3 and 4 RSA** templates, especially the profiles
  created with our companion script.
- Legacy CSP and RSA KSP configuration, plus schema 3/4 ECDSA/ECDH
  profiles on P-256/P-384/P-521. KSP must explicitly declare a supported algorithm.
- Built-in version 1 templates must first be duplicated/configured as a custom
  template. This tool does not perform that version conversion.
- An explicit allowlist is used. Unknown populated PKI attributes stop export;
  unknown import attributes are rejected instead of being silently ignored.
- The internal-use `pKIEnrollmentAccess` field is not supported. Populated values
  cause export to stop. Extra schema fields need an intentional future extension.
- ECC support is limited to the exact family-specific profiles in
  ALGORITHMS.md; arbitrary mixed purposes/usages are rejected.

## Requirements

Use **Windows PowerShell 5.1 as Administrator**. AD permissions are still required;
local elevation does not grant them. Missing AD RSAT tools can be installed
automatically using the same approach as the existing script. No CA role is
installed and no machine is restarted automatically.

A writable DC is discovered automatically. `-Server` selects a DC, not a CA.
With `-Publish`, run on the local issuing enterprise CA. The publication helper
uses the tested forced `certutil -f -ADTemplate` discovery, publication and
issuance-list verification sequence. ADCSAdministration is not required.

`-WhatIf` performs reads and validation but does not install, create, write or
publish. Without installed AD tools, it reports that directory validation cannot
proceed. Development regression scripts are not included in this release archive.

## Step 1: export an existing lab template

Use an existing custom template such as the one validated earlier:

```powershell
.\Export-ADCertificateTemplate.ps1 `
    -TemplateName 'MWWebServerProd' `
    -Path '.\MWWebServerProd.json' `
    -WhatIf -Verbose

.\Export-ADCertificateTemplate.ps1 `
    -TemplateName 'MWWebServerProd' `
    -Path '.\MWWebServerProd.json' `
    -Verbose
```

The directory must exist. Existing JSON files are not overwritten without
`-Force`. No AD objects are changed by export (a missing local RSAT feature can
be installed before the read).

Open the JSON and inspect its sections:

- `Source`: provenance and the original identity.
- `SummaryForReview`: human-readable overview, not authoritative on import.
- `Attributes`: authoritative typed settings.
- `Permissions`: authoritative binary DACL for Preserve mode, plus readable
  SDDL and rules for review. The readable lists are not used to reconstruct it.

Do not change SummaryForReview to modify settings: import uses Attributes.
JSON is not signed. Read-back verification establishes that the input was applied,
not that the input file was trustworthy. The file contains account/SID metadata,
so handle it as configuration information even though it contains no private keys.

## Step 2: same-forest clone with the original DACL

Explicitly choose `Preserve` if the original permissions should be retained:

```powershell
$Import = @{
    Path = '.\MWWebServerProd.json'
    Name = 'MWWebServerImported01'
    DisplayName = 'MW Web Server Imported 01'
    PermissionMode = 'Preserve'
}

.\Import-ADCertificateTemplate.ps1 @Import -WhatIf -Verbose
.\Import-ADCertificateTemplate.ps1 @Import -Verbose
```

Expected: `Verified = True`, a **different** TemplateOID, PermissionMode Preserve,
and Published False. The JSON's ConfigurationSHA256 identifies the bytes consumed
by import. Defaults from New-ADCertificateTemplate are not reapplied here.

Review the two templates in `certtmpl.msc`: cryptography, compatibility, periods,
Subject Name, Issuance Requirements, Request Handling, Extensions and Security.

For an end-to-end import plus publication, use a NEW name and `-Publish` on the CA:

```powershell
$Import.Name = 'MWWebServerImported02'
$Import.DisplayName = 'MW Web Server Imported 02'
.\Import-ADCertificateTemplate.ps1 @Import -Publish -Verbose
```

Do not rerun creation with an existing name to publish it. Publish an existing
import separately using the known certutil command if needed.

## Permissions and cross-forest use

| PermissionMode | Behavior |
|---|---|
| TargetBaseline (default) | Read DACL/inheritance from a selected destination template; optionally add destination groups |
| Preserve | Copy the exported DACL; requires the same forest Configuration-object GUID |

Preserve uses the binary security descriptor to avoid ambiguities with
domain-relative SDDL aliases. It does not copy the owner/SACL. Source and
destination templates live in the forest's same template container.

Cross-forest permissions are intentionally **not** matched by account name or
silently reused. Use the destination baseline and destination groups:

```powershell
.\Import-ADCertificateTemplate.ps1 `
    -Path '.\MWWebServerProd.json' `
    -Name 'ProdWebImported01' `
    -DisplayName 'Production Web Imported 01' `
    -PermissionMode TargetBaseline `
    -PermissionTemplate WebServer `
    -EnrollmentGroup 'GG-PKI-WebServer-Enroll' `
    -EnrollmentPermission Enroll `
    -WhatIf -Verbose
```

Run in the destination domain context, or select a destination DC with `-Server`
using an account with the appropriate destination permissions. Remove WhatIf
only after reviewing the result. Cross-forest behavior still needs a two-forest
lab test; it is not claimed as validated yet.

Baseline permissions are retained, not restricted. Choosing User as a permission
baseline may bring broad enrollment rights with it. Additional groups are additive.
There is no automatic SID-to-group migration or principal mapping in v1.1.0.

## Dependencies beyond permissions

The new **template OID** is regenerated. Referenced **policy OIDs** retain their
meaning and are not rewritten into new arbitrary values. Standard and Microsoft
OIDs are accepted. Other referenced OIDs must already be registered in the target
forest; missing registrations stop import before template creation. This check
does not migrate CP/CPS, qualifiers, linked groups, or establish policy equivalence.

Superseded-template references are recorded but omitted on import unless
`-IncludeSupersededTemplates` is supplied. With that switch, all referenced names
must exist in the destination. Review them: name equality does not prove that a
destination template has the same purpose as the original dependency.

Providers must exist on enrollment clients. The tools do not install providers,
HSM software, smart-card middleware, GPOs, CA trust, or enrollment services.

## Failure handling

- Invalid JSON, unsupported attributes/types, unresolved groups, existing names,
  and missing dependencies stop the import before OID/template creation.
- Read-back verification compares every written attribute and the final DACL.
- Failure during creation/verification attempts to remove only the objects
  created by that invocation. Cleanup failure is explicitly reported.
- Optional publication is separate. A publication failure retains verified AD
  objects and returns PublicationStatus Failed plus the error. Callers must
  inspect that status; publication failure is a warning/result, not a terminating
  creation error.
- Deleting or importing templates does not revoke previously issued certificates.

## Algorithm validation and upgrade

Supported ECC profiles are listed in ALGORITHMS.md. ECDSA uses KeySpec 2,
Digital Signature certificate usage and CNG Signing 2. ECDH uses KeySpec 1,
Key Agreement certificate usage and CNG AllUsages 16777215. Curve sizes and
explicit SHA2 request hashes are validated; mixed profiles are rejected.

Earlier ECDH candidate exports with CNG value 4 are rejected. Correct the source
and re-export, or create a new template; imports do not silently rewrite the
configuration or its checksum. JSON FormatVersion remains 1.0.

KDC Authentication (1.3.6.1.5.2.3.5) is recognized as a standard policy without
requiring custom OID registration in AD. This exact exception does not apply
to child OIDs. Other custom policy dependencies must exist in the destination.

The lab validated same-forest Preserve imports through issuance and actual
key agreement for ECDH P-256/P-384/P-521. See README.md for other results and
limits. Development regression scripts and test plans are not included.

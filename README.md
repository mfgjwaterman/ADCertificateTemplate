# AD Certificate Template Tools 1.1.0

PowerShell tools to create RSA certificate templates and export/import their
configuration. This release combines the existing creator with the new
export/import tools and fixes the OID registration object names in both creation
paths. Release date: 26 October 2026.

## Upgrade from earlier versions

Use this release for new template creation and imports. Earlier releases used
a random GUID for the OID registration object's CN. The expected deterministic
name allows the Windows template management workflow to locate that registration
when removing a template. With the correction, removal through certtmpl.msc was
confirmed to remove both objects in the lab, for the creator and importer.

**Existing OID registrations are not automatically repaired.** Replacing the
scripts does not rename previously created objects. Do not change existing
template OID values or delete OID registrations as a blanket cleanup: this
release contains no migration or orphan-cleanup command. Review older objects
separately. Keep the previous configuration exports and scripts for reference.

The creator now has the stable filename `New-ADCertificateTemplate.ps1`.
Update shortcuts/automation that call `New-ADCertificateTemplate-v1.0.ps1`.
Creator parameter names are unchanged. Creator, exporter and importer report
version 1.1.0. JSON FormatVersion remains 1.0; exports from the previous 0.1.0
tools are still accepted.

## Package contents

| File | Purpose |
|---|---|
| New-ADCertificateTemplate.ps1 | Create a new template from a schema 1/2 RSA source, with configurable settings |
| Export-ADCertificateTemplate.ps1 | Export a custom schema 2/3/4 RSA template to typed JSON |
| Import-ADCertificateTemplate.ps1 | Import JSON as a new template with a new OID and explicit permission mode |
| ADCertificateTemplate.Portability.psm1 | Required shared module for export/import and their local tests |
| Test-ADCertificateTemplate.ps1 | One-at-a-time creator scenario runner; dry run by default |
| Test-ADTemplatePortability.ps1 | Local format, OID-name and DACL regression checks |
| CREATOR.md | Creator parameters, examples and original scenario record |
| EXPORT-IMPORT.md | Export/import examples, permission modes and constraints |
| CHANGELOG.md | Release changes, validation and upgrade notice |
| SHA256SUMS.txt | SHA256 checksums for the other files in this directory |

Extract the full archive and keep its files together. The creator is standalone;
export/import require the supplied module beside them. These are custom scripts,
not built-in Microsoft cmdlets.

## Requirements

Run Windows PowerShell 5.1 as Administrator. You still need the appropriate AD
permissions, and CA permissions when publishing. Writable DC discovery is
automatic; `-Server` on export/import is an optional DC override.
Missing AD PowerShell tools can be installed automatically; installation depends
on an available Windows component source. WhatIf does not install tools or write
configuration. No CA role is installed and no automatic reboot is performed.

With `-Publish`, run on the local issuing enterprise CA. Publication uses
certutil, including forced AD template discovery and issuance-list verification;
ADCSAdministration is not required. Publication can also remain a separate task.

## Create a template

Review the planned operation first, then create using a fresh unique name:

```powershell
$Settings = @{
    Name = 'ExampleWeb01'
    DisplayName = 'Example Web 01'
    SourceTemplate = 'WebServer'
    ProviderSelection = 'SelectedProviders'
    Provider = 'Microsoft Software Key Storage Provider'
    EnrollmentGroup = 'GG-PKI-WebServer-Enroll'
}

.\New-ADCertificateTemplate.ps1 @Settings -WhatIf -Verbose
.\New-ADCertificateTemplate.ps1 @Settings -Verbose
```

Use a group that exists in your environment. See CREATOR.md for all settings.

## Export and import

Use an existing custom RSA template and a new destination name:

```powershell
.\Export-ADCertificateTemplate.ps1 `
    -TemplateName 'ExampleWeb01' `
    -Path '.\ExampleWeb01.json' `
    -Verbose

$Import = @{
    Path = '.\ExampleWeb01.json'
    Name = 'ExampleWebImported01'
    DisplayName = 'Example Web Imported 01'
    PermissionMode = 'Preserve'
}

.\Import-ADCertificateTemplate.ps1 @Import -WhatIf -Verbose
.\Import-ADCertificateTemplate.ps1 @Import -Verbose
```

`Preserve` copies the exported DACL and inheritance state in the same forest.
Owner and audit ACL are not transferred. EnrollmentGroups in the import result
lists groups added by the command, not every group in the preserved DACL.

`TargetBaseline` is the default permission mode: it uses a destination baseline
(WebServer by default), optionally adding destination enrollment groups. It does
not restore the exported custom-group permissions. Preserve is rejected across
forests. TargetBaseline/cross-forest use still needs dedicated lab validation.

Import always creates a new identity; it is not an in-place update or an
identity-preserving disaster recovery restore. Inspect the JSON before import.
The file contains configuration/account metadata but no certificates or private
keys. Unknown populated PKI fields are rejected rather than silently dropped.

## Publication and verification

Creation/import does not publish unless `-Publish` is supplied. To publish an
already created template separately, run on the CA, substituting its identity:

```powershell
certutil -f -ADTemplate ExampleWebImported01
certutil -config 'CAHOST\CAName' -SetCATemplates '+ExampleWebImported01'
certutil -config 'CAHOST\CAName' -CATemplates ExampleWebImported01
```

A successful AD write is reported as Verified True after attribute/DACL
read-back. With -Publish, also check Published and PublicationStatus. Failed
publication retains the verified template and reports the error for a separate
retry. Existing names are never overwritten.

Verify the profile and permissions in certtmpl.msc, then test actual enrollment.
For a cleanup test, record the template/OID object GUIDs, remove the test template
from the CA issuance list, delete it through certtmpl.msc, and confirm both AD
objects are absent. Deleting templates does not revoke issued certificates.

## Validation and scope

The creator's ten original scenarios and two additional multi-SAN cases were
reported successful in the Windows lab. The forced-discovery publication fix was
also reported successful. For 1.1.0, the OID-name calculation matched a UI-created
custom template, and MMC removed both objects for a newly created template.

The new same-forest import test used a schema 4 RSA3072 Software KSP profile,
SHA256 request hash, one-year validity and six-week renewal, plus a custom group
with Read/Enroll. Export, WhatIf, Preserve import, UI settings/permissions, manual
publication, enrollment and MMC/OID cleanup were all reported successful.

The release build was syntax checked and its package/checksums verified. The
Windows PowerShell regression script is provided but was not executed in the
build environment. The live validation above used the implementation assembled
in this release, before the final version/filename changes; the packaged artifact
has not had a separate full live rerun.

Not yet validated: cross-forest/TargetBaseline import, every supported RSA import
profile, real renewal subject reuse, or original CSR hash inspection. ECC and
schema 1 export/import are outside this release's scope.

These tools write directly to AD; they have not been migrated to the CertEnroll
COM template API. The OID correction addresses the observed naming/cleanup bug.
It does not establish Microsoft support for direct AD template automation, and
lab success is not a vendor support statement.

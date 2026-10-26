# Changelog

## 1.1.0 - 2026-10-26

### Fixed

- Creator and importer now derive the OID registration CN as:
  `<final OID arc>.<uppercase hex MD5 of full OID encoded as UTF-16LE>`.
  No BOM or terminating NUL is hashed. Previous releases used a random GUID.
- Verified the calculation against a custom template created through
  certtmpl.msc. Confirmed that MMC removal deletes both the new template and
  its OID registration for both creation and import workflows.
- Added the captured UI example as a known-value regression assertion. MD5 is
  used only for object naming, not as a certificate/request signature algorithm.

### Added

- Export-ADCertificateTemplate.ps1: custom schema 2/3/4 RSA configuration export
  to typed JSON, preserving binary durations, flags, providers, policies and DACL.
- Import-ADCertificateTemplate.ps1: new-template import with a fresh OID,
  same-forest Preserve or destination TargetBaseline permissions, read-back
  verification, rollback attempt for failed creation, and optional local CA
  publication. Publication failure retains verified AD objects.
- Shared portability module, local regression checks and full usage guide.
- Package inventory and SHA256 checksums.

### Packaging

- All tools report release 1.1.0. JSON FormatVersion remains 1.0, compatible
  with exports produced by the earlier 0.1.0 package.
- Stable creator filename New-ADCertificateTemplate.ps1 replaces the versioned
  filename in this new package. Update invocation paths accordingly.
- Existing creation parameters and forced-discovery publication behavior retained.

### Validation

- Same-forest export/import with Preserve, settings/group permissions checked in
  the UI, separate CA publication, successful certificate enrollment and complete
  MMC/OID cleanup were reported successful in the lab.
- Cross-forest and TargetBaseline import have not yet been lab validated.
- The local PowerShell regression suite is included; it was not run in the build
  environment. Release assembly received static syntax/package checks, not a
  separate full Windows/AD rerun after final version/filename edits.

### Upgrade note

Existing GUID-named OID objects are not repaired by this update. Do not change
existing template OID values or perform bulk deletion of OID registrations.
Review older registrations separately before planning a controlled repair.
This release still uses direct AD writes; it is not a CertEnroll API migration
and does not make a Microsoft support claim.

### Suggested public update notice

Version 1.1.0 adds template configuration export/import and fixes how the
associated OID registration is named. Earlier versions used a GUID as the OID
object name, which can leave the registration behind when a template is deleted
through the Certificate Templates console. New templates and imports now use the
name verified against Windows-created templates; deletion of both objects has
been tested. Existing registrations are not automatically repaired. Please use
1.1.0 for new creation/import operations and review any templates created with
older versions separately.

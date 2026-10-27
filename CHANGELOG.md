# Changelog

## 1.2.0 - 2026-10-27

- Added ECDSA and ECDH on P-256/P-384/P-521, with family-specific purpose,
  certificate Key Usage and curve-derived key size/request hash defaults.
- ECDH uses CNG AllUsages 16777215, matching the successful UI control and
  resolving request-creation NTE_PERM from the earlier agreement-only profile.
- Export/import validates and preserves supported ECC profiles. Older ECDH
  candidate configurations with CNG value 4 are rejected with upgrade guidance.
  No silent configuration rewrite or existing-template migration is performed.
- Added Domain DNS name SAN support alongside host DNS, including Kerberos
  profiles with an empty subject or DNS common name.
- Recognized KDC Authentication's standard OID without requiring custom AD
  registration. Other custom policies still require dependency validation.
- Added parameter choices through Tab/Ctrl+Space, including local provider
  enumeration, policy names and source suggestions; manual values remain
  accepted where supported.
- Windows lab: 155 configuration/OID/ACL assertions and 30 completion assertions
  passed. All three ECDH curves passed fresh creation and same-forest Preserve
  export/import through issuance and actual private-key agreement. Prior ECDSA,
  Kerberos, RSA and OID cleanup validation is summarized in README.md.
- Final runtime logic retains tested rc7 behavior; version strings are 1.2.0.
  Internal test module invocation now uses the exact imported module object;
  that test-only adjustment is syntax checked, not Windows rerun.
- End-user download contains runtime scripts, shared module and documentation.
  Development tests, certificate test helpers and test plans are not included.
- JSON FormatVersion remains 1.0. Older supported RSA/ECDSA exports remain
  readable. Existing templates, OID registrations and certificates are unchanged
  by replacing these files. See README.md for scope and upgrade details.

## 1.1.0 - 2026-10-26

- Corrected deterministic OID registration object names in creation/import:
  last OID arc plus the MD5 of UTF-16LE OID bytes, without a terminator.
- Added typed JSON export/import with fresh destination OIDs, explicit permission
  modes, validation, read-back verification and cleanup on creation failure.
- Creator/importer MMC deletion tests confirmed removal of template and associated
  OID registration objects. Existing older registrations are not repaired.
- Retained forced certutil template discovery before optional CA publication.

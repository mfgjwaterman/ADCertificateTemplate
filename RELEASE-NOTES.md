# ADCertificateTemplate 2.0.0 — 1 November 2026

Scoped release of the COM implementation validated through rc1/rc2 integration runs and the final RC3 negative checks. This package is prepared for review/distribution. No repository tag, public GitHub release or blog/social publication has been created by this packaging step.

## Breaking changes from 1.2.0

- Schema 4 creation/import is rejected; no silent downgrade is performed.
- Retained modern compatibility defaults request schema 4. Existing calls that rely on those defaults must explicitly select the supported compatibility route.
- Unsupported serializer configurations fail before save, including archival, RA signatures and issuance policies. Review README.md before migrating.
- Keep version 1.2.0 available as the previous release; do not mix its module with 2.0.0 commands.

## Implementation changes

- New and Import use a shared in-memory XCEP -> native CertEnroll Commit path. Native COM generates fresh template OIDs.
- AD reads remain; direct template/OID creation, modification, DACL commits and deletion through AD write APIs are removed from this package. Optional CA publication remains a separate certutil operation.
- Export retains the original typed JSON format version 1.0. Import creates a new identity, validates supported settings and verifies saved configuration and permissions.
- Creator EnrollAndAutoenroll requests set flag 0x20 explicitly. Import rejects contradictory explicit Autoenroll ACEs and flags without changing the exported intent silently.
- Post-save verification failures trigger identity-guarded COM cleanup when ownership is established, followed by absence checks. Partial native Commit recovery is not guaranteed.

## Final validation

- Nine crypto/provider profiles: eighteen create/import results, controlled rollback and existing-template snapshot all passed in rc2 R03.
- Independent MachineDNS and MultiKSP AD feature checks passed, including explicit autoenrollment flags/permissions, provider priorities, supersedence and unchanged existing template/OID snapshots.
- Creator and importer publication sequences each resulted in an installed machine certificate with a functioning RSA3072 Software KSP private key (requests 109 and 110).
- Integrated RC3 negative checks: **20 passed, 0 failed**. Template/OID GUID-USN snapshots and CA publication snapshots remained unchanged. The test did not request directory writes or exercise Commit permissions.

## Release preparation

- Public release version: 2.0.0. The earlier COM 0.2.0 labels were development labels.
- The scripts in the release must report 2.0.0 consistently; these Markdown files do not modify script version metadata.
- Includes Test-COMCandidateNegative.ps1 and completed validation evidence.
- Updated documentation with completed validation results and the public 2.0.0 release number.
- Core COM module byte-identical to rc2/rc3. No intended runtime behavior changes; commands differ only in version labels/help from the tested implementation.
- Final-label packaging checks passed locally; a separate Windows execution of the final version label is not claimed.

## Scope limits

Schema 4 is blocked because of the reproduced native crypto-reset defect. Modern default compatibility selections are retained and therefore fail before writes; explicitly select supported pre-2012 compatibility. No silent downgrade or unsupported-field omission is performed. Private-key archival, RA signatures, issuance policies and other exclusions remain as documented in README.md.

This is not full feature parity with the original direct-AD scripts, a vendor support statement, or proof of every application/OS/provider combination. Keep the original working release separately. See VALIDATION.md for the evidence and its limits.

# ADCertificateTemplate 2.0.0 validation record — 1 November 2026

Candidate labels below record the implementation actually tested; they are historical evidence, not the current release version.

Evidence below comes from the user's Windows lab reports in this collaboration. Local packaging checks are separate from live execution. This is not an independent production certification.

## Lab

- Writable DC: lab-dc-01.corp.michaelwaterman.nl.
- Enterprise issuing CA: lab-srv-02.corp.michaelwaterman.nl / Corp-Enterprise-CA01.
- Management environment: Windows Server 2025, Windows PowerShell 5.1 x64.
- Enrollment client: LAB-WRK-01.

## Historical release-candidate results

| Test | Implementation / run | Observed result |
|---|---|---|
| Base create/export/import | rc1 / R01 | Four profiles, eight create/import records verified; controlled rollback and existing-template check passed |
| Extended profiles | rc1 / R02 | Nine profiles, eighteen create/import records verified; rollback and existing-template check passed |
| UserAD feature | rc1 / R01 | Created/imported objects read back with enrollment flags 41; subsequent harness failure was in MachineDNS, not this import |
| MachineDNS + MultiKSP features | rc2 / R01, selected cases | Four AD feature records verified; existing template and OID GUID/USN checks unchanged; all feature templates unpublished |
| Extended regression | rc2 / R03 | All eighteen create/import records, controlled rollback and existing-template check verified |
| Creator publication + machine enrollment | rc2 | Template COMRC2PubMachine_R01 issued request 109, installed with working machine private key |
| Import publication + machine enrollment | rc2 | Template COMRC2ImpPubMachine_R01 issued request 110, installed with working machine private key |
| Integrated negative checks | rc3 / 0.1.0-RC3Negative | 20 passed, 0 failed; expected messages matched; template/OID GUID-USN and CA publication snapshots unchanged |

The extended profiles are RSA3072, ECDSA P384, ECDH P384, legacy RSA3072, ECDSA P256/P521, ECDH P256/P521, and any-provider RSA4096. The main harness verifies pre-existing template GUID/USN snapshots and checks that regression destinations remain unpublished. Its rollback check compares OID GUID sets around the injected rollback. It does not claim a full pre-existing OID content snapshot for every extended run; the feature harness separately checks pre-existing OID GUID/USN snapshots.

MachineDNS create/import retained name flags 0x18000000, Software KSP, explicit Autoenroll ACEs and enrollment flags 32. TargetBaseline import had Domain Computers and Schema Admins enrollment groups. MultiKSP retained name flags 9 and both Software/Platform providers with their rank values; only its import referenced COMJsonMultiPolicy_S3_R01 in supersedence. Enumeration order of the multivalued AD attribute is not provider priority.

## Issued machine certificate evidence

| Field | Creator route | Import route |
|---|---|---|
| Request ID | 109 | 110 |
| Thumbprint | BAF19E463CC64D7E1D51E3ED7E538B13A979545D | 8EE32CD38DFB72D6FCC1CC394E44074DB5C10C57 |
| Template OID final arcs | 3.4481515.9206015 | 3.7956235.6539550 |
| Subject | CN=lab-wrk-01.corp.michaelwaterman.nl | Same |
| DNS SAN | lab-wrk-01.corp.michaelwaterman.nl | Same |
| Public key / provider | RSA3072 / Microsoft Software Key Storage Provider | Same |
| Context | Local Machine store / CRYPT_MACHINE_KEYSET | Same |
| EKU / Application Policy | Server Authentication | Same |
| Certificate Key Usage | Digital Signature, Key Encipherment | Same |
| CNG key usage | Decrypt + signing, value 3 | Same |
| Export | Not exportable | Same |
| Private-key check | Encryption test passed | Same |

Both dumps establish certificate issuance and functioning installed machine keys. They do not contain the script's publication-result object or autoenrollment event history. Attribution specifically to the scripted publication and pulse sequence depends on following the supplied procedure without manual publication/request steps.

## Earlier constrained probes

Standalone probes established original-format JSON import, same-forest Preserve and TargetBaseline, explicit ACL/supersedence read-back, actual RSA/ECDSA/ECDH key operation, user naming, manager approval, exportable PFX operation and automatic renewal. Earlier constrained negative validation had 23 passes; collision checks and a delegated access-denied test left no objects behind. Controlled rollback restored both template and OID snapshots.

The final RC3 negative run subsequently exercised the integrated importer and passed all 20 checks. It used WhatIf throughout; it did not repeat a real access-denied Commit or native partial-Commit test. Cross-forest import, native partial-Commit recovery, real TPM key use, supersedence-driven client replacement and every consuming application remain unproven by these tests.

## Release validation and limitations

- Integrated RC3 validation passed: one valid control, fourteen invalid configuration cases, two collisions and three unchanged-state snapshots. The autoenroll ACE/flag consistency guard rejected contradictory input as expected. DirectoryWritesRequested=False and CommitPermissionsTested=False.
- Schema 4 is blocked because of the reproduced native crypto-reset defect. The product-group question remains open; no vendor fix or support commitment is claimed.
- Other excluded serialization features are listed in README.md.
- RC3 validation executed in the user's Windows lab. The public release is numbered 2.0.0; the earlier 0.2.0 package was a development-labelled artifact. This documentation revision does not change PowerShell source or rerun Windows tests. No additional final-label Windows run is claimed.
- Local tree-sitter PowerShell syntax parsing of all seven PowerShell files, module byte comparison, code-change comparison, direct-AD-write scan, checksums and ZIP integrity passed. These are packaging checks, not Windows/AD runtime tests. The six core/regression files retain rc2 executable text except for version strings. The added negative harness matches the tested RC3 harness except for release-label guards and comment/version labels.

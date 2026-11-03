# Validation record — 2.1.0

Observed lab results on 2–3 November 2026. The 2.1.0 release retains the tested RC2 runtime with version/comment changes. Results describe the executed cases, not every parameter combination or a Microsoft support commitment.

## Environments

| Role | OS / PowerShell | Native DLL versions |
|---|---|---|
| Issuing CA / management host | Server 2025 Standard build 26100.33158; Windows PowerShell 5.1.26100.33158 | certca.dll and CertEnroll.dll 10.0.26100.32684 |
| Additional management host | Server 2022 Standard build 20348.4294; Windows PowerShell 5.1.20348.4294 | certca.dll and CertEnroll.dll 10.0.20348.4052 |
| Enrollment client | Domain-joined LAB-WRK-01 | Computer/SYSTEM context; client OS build not recorded in supplied evidence |

The Server 2022 test host did not require a CA role. Its template operations targeted the existing lab forest. Issuance in the integrated and workstation tests used the Server 2025 enterprise CA.

## Test results

| Area | Run / evidence | Observed result |
|---|---|---|
| Initial schema-4 matrix | R23, followed by RC2 checks | Eight creates and eight Preserve imports verified; unchanged existing objects. R23 exposed the separate OID cleanup requirement. |
| Native rollback, RC2 | R24 | Injected post-save verification failure; temporary template and OID removed; existing GUID/USN snapshots unchanged. |
| Schema-2/3 preparation | R25 | Nine creator WhatIf cases; no destinations and unchanged existing templates. |
| Schema-2/3 matrix | R26 | Nine creates and nine imports verified, COM rollback successful, existing templates unchanged and no publication. Includes legacy RSA, any-provider RSA and EC P521. |
| Schema-2/3 features | R27/R28 | Six create/import checks passed: user/machine subject/SAN, explicit group rights, Autoenroll flag/ACE, multi-KSP priorities, TargetBaseline and supersedence; unchanged existing template/OID snapshots and no publication. |
| Negative input/collisions | Source from R26 | 20 passed; template, OID and CA publication GUID/USN snapshots unchanged. No write requested. |
| Integrated schema-4 end-to-end | R30, JSON report reviewed | Eight imports verified and published; eight unique template GUIDs/OIDs and certificate thumbprints; Issued status, machine-store presence, expected subject/SAN/EKU/KU, six signing tests and two ECDH tests passed. Source templates unchanged; no reported errors. |
| Schema-4 features | R31/R32 | Three WhatIf profiles and six create/import feature checks passed: UserAD, MachineDNS, CustomPolicy. Validity/renewal 365/42 and 730/56 days; approval/exportability flags; RSA3072/SHA256 and RSA4096/SHA384; policies, Autoenroll permissions, TargetBaseline and supersedence; existing template/OID snapshots unchanged and no publication. |
| Workstation machine enrollment | Request 154 | SYSTEM request completed with exit 0; workstation DNS subject/SAN, RSA3072 Software KSP, machine private key, nonexportability and encryption test passed; Kerberos authentication recorded. |
| Workstation autoenrollment | Request 155, R33 template | New certificate installed; Lifecycle-System event 1006 ties exact template/OID and certificate thumbprint to taskhostw.exe, machine context, workstation computer account and Enroll action after the GPO/pulse test. |
| Server 2022 native smoke | R34/R35 | WhatIf followed by create/import and native rollback passed; existing objects unchanged. |
| Server 2022 native matrix | R36 | Eight creates and eight imports verified; template/OID rollback successful; existing GUID/USN snapshots unchanged and all templates unpublished. |
| Real denied AD writes | R37 | Both WhatIf controls prepared; real create/import attempts failed at Clone with 0x80070005 under a local administrator without AD template-management rights. Attempt completed; privileged verification confirmed exact PKI snapshots unchanged and zero destination templates. |
| Simulated publication failures | R39 | Creator and importer both retained Verified=True with Published=False and PublicationStatus=Failed; template/OID identities retained; existing PKI objects and CA publication state unchanged. Fault injection only, not a real CA authorization-denied test. |

## Crypto profiles

| Profile | Certificate KU | Key-use test |
|---|---|---|
| RSA3072/SHA256 | A0 | Signature verification and modified-input rejection |
| RSA4096/SHA256 | A0 | Signature verification and modified-input rejection |
| RSA4096/SHA384 | A0 | Signature verification and modified-input rejection |
| RSA3072/SHA512 | A0 | Signature verification and modified-input rejection |
| ECDSA P256/SHA256 | 80 | Signature verification and modified-input rejection |
| ECDSA P384/SHA384 | 80 | Signature verification and modified-input rejection |
| ECDH P256 | 08 | Matching derived keys using Hash(SHA256); certificate/public-key match |
| ECDH P384 | 08 | Matching derived keys using Hash(SHA256); certificate/public-key match |

The signing hash in these tests is selected by the test operation; it does not independently establish the CSR signature hash. The CA's certificate signature hash is also a separate setting.

## Investigation and test-harness corrections

The original COM path preserved schema-3 crypto but reset schema-4 crypto on both examined server versions. Debugger traces isolated a late default-KSP reset during private-key flag handling, after COM's crypto setters. A controlled diagnostic skip helped establish causality; the release uses no debugger skip or binary patch.

RC1 native rollback removed the template but left its OID registration. RC2 introduced separate guarded native OID deletion and passed both server-version rollback tests. Test-only corrections decoded exported Type/Value records before comparisons and flattened PowerShell warning records to strings before JSON serialization. The denied-write harness additionally checkpoints progress and does not count null lookup results as destination objects.

## Final package checks

PowerShell parsing and C# compilation are performed in PowerShell 7.4.6 on Linux, plus the 26 portable checks in Test-RCOffline.ps1. These are build checks, not Windows runtime claims. Release preparation also compares production runtime tokens against the tested RC2 snapshot, preserves the native C# bytes, verifies all manifest hashes and checks the archive. No separate full Windows rerun under the final 2.1.0 version label is claimed.

## Limits

- Native API support confirmation from Microsoft PG is pending.
- Observed Server 2022 coverage is management-host creation/import/rollback, not a Server 2022 issuing-CA/key-use matrix.
- Actual CA authorization-denied publication, manager-approval issuance/rejection, PFX export and renewal workflows were not exercised. The corresponding stored flags/intervals were checked where described.
- Cross-forest imports, arbitrary KSPs, schema-4 P521/legacy providers, all OS/build combinations and full TLS/EFS behavior are not established.
- Tests do not establish CSR hash correctness, full trust/revocation behavior, broad effective-permission/deny/inheritance semantics or race-free transactions.
- A failed native operation can leave partial objects before ownership capture; no blanket orphan-cleanup guarantee is made. Successful lab objects normally remain.

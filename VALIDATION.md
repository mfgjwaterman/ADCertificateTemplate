# Validation evidence — 2.2.0

Evidence supplied from Michael Waterman's lab on 3 November 2026. These are executed scenarios, not a claim that all parameter/provider/OS combinations work.

| Run | Environment / result |
|---|---|
| R41 | Platform-only RSA2048 create/import/rollback passed; existing objects unchanged. |
| R42 / R43 | Platform→Software and Software→Platform create/import/rollback passed. |
| R41–R43 enrollment | LAB-WRK-01: Platform-only and each preferred provider selected as expected; RSA2048 signing verified, modified data rejected, nonexportable. |
| Fallback | LAB-SRV-08 without TPM: Platform→Software template selected Software KSP; signing/tamper detection/nonexportability passed. |
| R44 | Eight original Software KSP profiles created/imported; rollback and existing-object snapshots passed. An earlier attempt stopped because of a test harness default-argument error, subsequently corrected. |
| R46 / R47 | Embedded C# build on Windows PowerShell 5.1: eight original profiles and mixed list create/import/rollback passed. |
| R48–R50 | PowerShell 7.6.9 x64, Windows build 26100: single profile, eight-profile matrix and mixed providers passed, including rollback. |
| R51 / R52 | PowerShell 7.6.9: schema-2/3 COM WhatIf, nine create/import cases and rollback passed; existing templates unchanged. |
| R53 / R54 | PowerShell 7.6.9 on CA: preparation followed by eight schema-4 imports/publications/enrollments with certificate checks and RSA/ECDSA signing or ECDH agreement, all passed. |
| R55 | PowerShell 7.6.9: schema-3 COM import/publication/enrollment and RSA3072 key use passed. |
| R56 | PowerShell 7.6.9: mixed-provider schema-4 import/publication/enrollment and RSA2048 key use passed; ActualProvider was Microsoft Software Key Storage Provider. |

Windows PowerShell lab hosts: Server 2025 build 26100.33158 / PS5.1.26100.33158 / CertEnroll+certca 10.0.26100.32684; Server 2022 build 20348.4294 / PS5.1.20348.4294 / DLLs 10.0.20348.4052. PowerShell 7 output reported 7.6.9, Win32NT, Windows build 26100, 64-bit, ActiveDirectory module 1.0.1.0. Windows APIs can report the NT platform as Windows 10 even on Server 2025.

The workstation Platform key reported a TPM12 provider policy and RSA maximum 2048. Larger Platform key sizes, Platform ECC, attestation, third-party HSMs and other PS7 releases were not validated. Earlier 2.1.0 tests also covered denied writes and simulated publication failure; those specific failure tests were not repeated under PS7. Automatic management-tool installation under PS7 was not tested.

Local build checks use PowerShell 7.4.6 on Linux for parsing, embedded C# compilation and portable checks only. They make no Windows native runtime claim. Final packaging verifies manifests and archive contents. The final-label platform guards require Windows/x64 and either Desktop≥5.1 or Core≥7; the Windows test copies previously had the Desktop-only guards manually disabled. Final-label native C# and remaining runtime logic are compared with the tested embedded probe, excluding version/help text and the two guard replacements. No separate final-label Windows rerun is claimed.

Microsoft product-group support/API confirmation remains pending.

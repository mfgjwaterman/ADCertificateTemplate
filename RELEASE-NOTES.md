# ADCertificateTemplate 2.1.0 — 3 November 2026

Adds a scoped schema-4 KSP creation/import route to the existing schema-2/3 CertEnroll COM implementation. Based on repository main commit `dfe95e8` and the tested 2.1.0 RC2 runtime. JSON configuration FormatVersion remains **1.0**.

## Changes from 2.0.0

- Schema 4 KSP uses native certca clone/configure/save. The provider transition runs before final crypto setters, avoiding the late default reset observed in the investigated COM path.
- New required companion: `ADCertificateTemplate.Native.cs`. Keep it beside the module and commands.
- Schema-4 scope: Software KSP; RSA3072/4096; ECDSA/ECDH P256/P384; SHA2. Other providers, any-provider, P521 and schema-4 legacy CSP remain rejected. Existing schema-2/3 scope is retained.
- Shared configuration, original-format portability, DACL verification, collision/dependency checks, WhatIf and optional post-verification publication are retained. Results expose the backend.
- Native rollback separately removes the owned template and OID registration, guarding identities, USNs, type, template references and publication state. Partial failures before ownership capture remain for inspection.
- Added native profile/feature tests, integrated publication/enrollment/key-use tests, denied-write tests and isolated publication fault-injection tests.

## Upgrade

Extract into a separate folder and start a fresh elevated Windows PowerShell 5.1 x64 session. Replace the complete package together, including native C#. The old AnyAvailable provider default is unchanged: select Microsoft Software KSP explicitly with SelectedProviders for schema 4. No automatic downgrade or provider substitution is performed.

Existing templates, certificates and OID registrations are not migrated or repaired by replacing scripts. Successful lab objects and any previously retained partial objects are not automatically removed.

## Validation

Create/import, rollback, schema-4 features, schema-2/3 regressions, negative inputs, integrated enrollment/private-key operation, workstation autoenrollment, denied AD writes and injected publication-failure handling were exercised as described in VALIDATION.md. Native creation/import/rollback was tested from Server 2022 and Server 2025; integrated issuing-CA/key-use tests used Server 2025.

The final 2.1.0 runtime is unchanged from tested RC2 apart from version strings/comments. Test version guards and documentation are updated. The final package receives parsing, C# compilation, offline checks, runtime-freeze comparison and archive/checksum validation; no separate full Windows rerun under the final 2.1.0 label is claimed.

## Support and remaining scope

Microsoft PG confirmation of the native API support status remains pending. Lab success is not a Microsoft support statement. Actual CA authorization refusal was not tested: publication-failure testing used isolated fault injection in both creator and importer. Approval workflow, PFX export, renewal, cross-forest imports and protocol/trust/revocation behavior remain open, as documented in VALIDATION.md.

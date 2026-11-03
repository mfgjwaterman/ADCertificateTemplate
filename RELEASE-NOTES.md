# 2.2.0 — 3 November 2026

- Embed native C# in the portability module; runtime package reduced to four files.
- Pass explicit ranked provider selections into the schema-4 native backend instead of a hardcoded Software KSP.
- Add scoped Microsoft Platform Crypto Provider and Software/Platform priority lists; reject duplicate/noncontiguous priorities and unapproved providers.
- Platform-containing lists require nonexportable RSA; RSA2048 additionally allowed for these lists. Hardware capabilities still apply.
- Permit Windows PowerShell 5.1 and PowerShell 7 on 64-bit Windows. PowerShell 7 lab testing used 7.6.9 specifically.
- Correct the native test harness's default Provider argument.

Native sequence, ownership/readback checks and rollback remain based on the tested implementation. Internal managed type names retain the embedded-probe identity to avoid unnecessary code changes. No separate .cs companion, PQC support, third-party provider support or key attestation is included.

Final-label preparation changes version/help text and replaces the two Desktop-only guards with Windows/x64/edition/version checks. The final 2.2.0 label has not received a separate full Windows regression rerun. See VALIDATION.md for executed evidence and packaging checks.

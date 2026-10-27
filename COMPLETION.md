# Parameter choices with Tab and Ctrl+Space - 1.2.0

Keep using the generator's normal parameters. There is no wizard, mandatory
session initializer, profile edit or change to AD creation behavior. The script
contains its completion metadata, so it does not need to be run or dot-sourced
before completion can work. This candidate needs Windows completion testing.

## Console use

Open Windows PowerShell 5.1 in the extracted directory. Type this line, leave
the cursor after the final space, and press **Ctrl+Space** (do not execute it):

```text
.\New-ADCertificateTemplate.ps1 -Name MWCompletion01 -DisplayName 'MW Completion 01' -Algorithm 
```

Expected menu values: RSA; ECDSA_P256/P384/P521; ECDH_P256/P384/P521. Tab cycles forward,
Shift+Tab cycles backward, and Ctrl+Space presents a menu in consoles using the
corresponding PSReadLine binding. Select with arrow keys and Enter. Hosts such
as ISE manage their own completion UI; PSReadLine keybindings apply to consoles.

Fixed-choice parameters already use ValidateSet:

| Parameter | Choices |
|---|---|
| Algorithm | RSA; ECDSA_P256/P384/P521; ECDH_P256/P384/P521 |
| CACompatibility / RecipientCompatibility | Supported Windows version labels |
| ProviderCategory | Legacy CSP or KSP |
| ProviderSelection | AnyAvailable or SelectedProviders |
| MinimumKeySize | Supported RSA and ECC sizes |
| RequestHash | SHA1, SHA256, SHA384, SHA512 |
| SubjectNameMode | SupplyInRequest or ActiveDirectory |
| SubjectNameFormat | None, Common name, Fully distinguished name, DNS name, E-mail name |
| SubjectAlternativeName | DNS name, Domain DNS name, E-mail name, UPN, SPN, Directory GUID |
| EnrollmentPermission | Enroll or EnrollAndAutoenroll |

The finite lists show allowed values per parameter, not every valid combination.
For example, MinimumKeySize includes both RSA and ECC sizes. The existing runtime
validation still rejects P-256 with size 3072, ECC with legacy CSP, and SHA1 for
ECDSA. Omit size/hash to retain the algorithm-specific defaults already tested.

Free-form names, domain controller names, group identities and numeric durations
have no finite value list and retain their existing input/validation behavior.

## Provider choices

Type this line and press Ctrl+Space after `-Provider `:

```text
.\New-ADCertificateTemplate.ps1 -Name MWCompletion01 -DisplayName 'MW Completion 01' -ProviderCategory 'Key Storage Provider' -ProviderSelection SelectedProviders -Provider 
```

The list contains locally installed KSP names from CertEnroll provider metadata.
It does not open keys, enroll, query AD, install anything, or change provider
configuration. Specify ProviderCategory before Provider to make the selected
category clear while editing. If omitted/unresolved, KSP is the default.

Choose Microsoft Software Key Storage Provider for the previously tested
RSA/ECDSA lab profiles. Names with spaces are inserted inside single quotes.
Typing a prefix such as an opening quote followed by `Microsoft Sof` narrows the
list. Prefix matching is literal and case-insensitive.

Use legacy CSP to see that category's provider names:

```text
.\New-ADCertificateTemplate.ps1 -Name MWCompletion01 -DisplayName 'MW Completion 01' -ProviderCategory 'Legacy Cryptographic Service Provider' -ProviderSelection SelectedProviders -Provider 
```

This is a **local name inventory**, not a capability test. Provider presence and
algorithm/hardware support on enrollment clients are separate requirements.
Providers available only on those clients may still be typed manually.
Smart-card/HSM/TPM providers appearing in the list are not a recommendation or
proof that they work for a particular template purpose or algorithm.

If COM discovery is unavailable or yields no names for the category, completion
shows common Windows examples, explicitly labeled as such in the tooltip. That
fallback is not a claim that those names were discovered locally. The completion
test reports LocalEnumeration or FallbackExamples separately for each category.

## Application policies and source templates

Ctrl+Space after ApplicationPolicy lists Client Authentication, Server
Authentication, Code Signing, Secure Email, Time Stamping and OCSP Signing.
Custom numeric OIDs remain accepted; these suggestions do not change policies
or imply application compatibility with the chosen algorithm.

SourceTemplate suggests WebServer, User and KerberosAuthentication, the three
lab-tested RSA baselines. It does not query AD or enumerate all custom templates.
Other valid schema 1/2 source names can still be typed manually. Each selected
friendly policy/source name is quoted automatically where appropriate.

For array parameters, select a value, type a comma and complete the next value.
The generator's existing duplication and combination checks remain in effect.

## Hashtable splatting

Completion is intended for direct command-line parameters such as `-Algorithm`
and `-Provider`. In Windows PowerShell 5.1, an ordinary hashtable like
`$Settings = @{ Algorithm = ... }` is not automatically associated with the
script's parameter metadata. Do not expect these menus inside that hashtable.
Existing hashtable/splatting invocations still run unchanged.

## If the console menu does not open

In a PowerShell console that uses PSReadLine, optionally configure only the
current session (the generator does not do this automatically):

```powershell
Import-Module PSReadLine
Set-PSReadLineKeyHandler -Chord 'Ctrl+Spacebar' -Function MenuComplete
```

No profile file is changed. The development completion suite passed 30
assertions on Windows PowerShell 5.1, with local KSP and CSP enumeration.
The visual menu was also confirmed in the lab. Keybindings may differ by host;
use -WhatIf to review a selected configuration before creation.

References:
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_functions_argument_completion?view=powershell-5.1
- https://learn.microsoft.com/en-us/powershell/scripting/learn/shell/using-keyhandlers
- https://learn.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-icspinformations-addavailablecsps

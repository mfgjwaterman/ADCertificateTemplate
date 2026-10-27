# Algorithm profiles - 1.2.0

The generator accepts the following explicit algorithm choices. RSA is the
default. ECC requires Key Storage Provider and schema 3/4. Existing source
application policies are retained; pick policies appropriate to the application.

| Algorithm | Bits | Default request hash | Purpose | Certificate Key Usage | CNG usage | KeySpec |
|---|---:|---|---|---|---:|---:|
| RSA | 3072 default | SHA256 for KSP | Source settings | Source settings | 3 for KSP | Source settings |
| ECDSA_P256 | 256 | SHA256 | Signature | Digital Signature (0x80) | 2 | 2 |
| ECDSA_P384 | 384 | SHA384 | Signature | Digital Signature (0x80) | 2 | 2 |
| ECDSA_P521 | 521 | SHA512 | Signature | Digital Signature (0x80) | 2 | 2 |
| ECDH_P256 | 256 | SHA256 | Encryption | Key Agreement (0x08) | 16777215 | 1 |
| ECDH_P384 | 384 | SHA384 | Encryption | Key Agreement (0x08) | 16777215 | 1 |
| ECDH_P521 | 521 | SHA512 | Encryption | Key Agreement (0x08) | 16777215 | 1 |

CNG values: 2 = Signing, 3 = Decrypt + Signing, 16777215 = AllUsages. CNG private
key permissions are distinct from the certificate Key Usage extension. Using
AllUsages does not enable private-key export or add signing to the certificate.
ECDH's previous CNG agreement-only value 4 caused request-creation NTE_PERM in
the lab; changing it to the UI's AllUsages value resolved the issue.

Omit MinimumKeySize and RequestHash to use curve defaults. An explicit ECC size
must match the curve; P-521 is 521 bits, not 512. ECC accepts SHA256/SHA384/SHA512,
not SHA1. Legacy CSP and EC private-key archival profiles are rejected.

| Curve | Named-curve OID |
|---|---|
| P-256 | 1.2.840.10045.3.1.7 |
| P-384 | 1.3.132.0.34 |
| P-521 | 1.3.132.0.35 |

ECDSA signs messages; ECDH establishes a shared secret. ECDH does not directly
encrypt arbitrary payloads and is not a drop-in signing or TLS certificate.
Applications select a KDF and symmetric encryption according to their protocol.
Request hash, the issuer's certificate signature and the agreement KDF hash are
independent settings. A certificate with an ECC public key may be signed by an
RSA CA; sha256RSA as the outer signature is not an ECC configuration failure.

## Example: ECDSA

```powershell
$Signature = @{
    SourceTemplate    = 'WebServer'
    Name              = 'ExampleECDSA384'
    DisplayName       = 'Example ECDSA P384'
    Algorithm         = 'ECDSA_P384'
    ProviderCategory  = 'Key Storage Provider'
    ProviderSelection = 'SelectedProviders'
    Provider          = 'Microsoft Software Key Storage Provider'
}
.\New-ADCertificateTemplate.ps1 @Signature -WhatIf -Verbose
.\New-ADCertificateTemplate.ps1 @Signature -Verbose
```

## Example: ECDH

This mirrors the User-source profile used in the successful ECDH lab tests.
User policies are retained; review them for the intended application. The
example itself does not configure EFS or establish application compatibility.

```powershell
$Agreement = @{
    SourceTemplate    = 'User'
    Name              = 'ExampleECDH521'
    DisplayName       = 'Example ECDH P521'
    Algorithm         = 'ECDH_P521'
    ProviderCategory  = 'Key Storage Provider'
    ProviderSelection = 'SelectedProviders'
    Provider          = 'Microsoft Software Key Storage Provider'
}
.\New-ADCertificateTemplate.ps1 @Agreement -WhatIf -Verbose
.\New-ADCertificateTemplate.ps1 @Agreement -Verbose
```

Publication is separate unless requested with -Publish on the local CA. Review
source DACLs and enroll using the appropriate user or machine identity/store.
Provider completion enumerates the local machine and cannot prove that the
chosen provider/algorithm is available on the eventual enrollment client.

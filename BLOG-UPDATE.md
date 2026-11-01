# Suggested update for the existing blog post

Target: https://michaelwaterman.nl/2026/10/26/creating-ad-cs-certificate-templates-with-powershell/

Draft for publication after the version 2.0.0 package is uploaded to the repository. The download location has not yet been published. Insert this above the earlier dated updates; retain them as release history.

## Update — 1 November 2026: version 2.0.0

After the first release, I wanted to see how far I could take template creation through the native CertEnroll COM interfaces. The result is version 2.0.0 of the tools. The major version reflects a change in supported configurations as well as the move to COM.

The main change is how templates are saved. The scripts prepare the configuration in memory and let CertEnroll create the new template and its OID registration. They then read the result back from AD and compare the settings and permissions. Export and import still use the existing JSON format, so supported configurations can make the same round trip.

Testing covered RSA, legacy CSPs and ECDSA/ECDH on P-256, P-384 and P-521, along with provider selection, permissions, AD-derived subject names and supersedence references. I also tested the complete creation and import sequences through publication and machine enrollment. Both produced certificates with the expected settings and working private keys. The final negative checks passed all 20 cases, including unchanged template, OID and CA publication snapshots.

There is one significant limitation: **schema version 4 is blocked in this COM edition**. During testing, I reproduced native COM behavior that reset the cryptographic configuration on that route. The scripts stop rather than save different settings or silently lower the schema. For the supported route, explicitly select the pre-2012 compatibility values documented in the README. The retained modern defaults request schema 4 and will therefore be rejected.

Some other features, including private-key archival, RA signatures and issuance policies, are also outside this edition's scope. The README lists the exclusions. This is not full feature parity with the original scripts or a Microsoft support statement.

**Version 2.0.0 succeeds 1.2.0.** It is a major release because schema 4 and some previously available configuration paths are no longer supported. Version 1.2.0 remains the previous direct-AD release. Keep the releases in separate folders and use the matching companion module.

As always, try it in your lab first. I hope the tools save you some time, and if you find a scenario that needs attention, let me know. Community feedback has already helped improve this project considerably.

## Suggested corrections to the existing article

The body still contains statements from the first release. Review these together with the new update so readers do not apply the COM scope to the original implementation.

Replace the sentence beginning “This version supports RSA” with:

> The original 1.2.0 release supports RSA and ECDSA/ECDH on P-256, P-384 and P-521. Version 2.0.0 uses native COM and supports these algorithm families within the schema and configuration limits described in its README.

Replace the paragraph beginning “Note! The scripts manage certificate template objects directly” with:

> The original release manages certificate template objects directly in Active Directory. Version 2.0.0 prepares the configuration in memory and uses native CertEnroll to save new templates and their OID registrations. The implementations have different supported scopes; keep each edition's scripts and companion module together. Lab validation does not constitute a Microsoft support statement.

The older examples remain examples for the original release. For COM examples, link readers to its README and explicit compatibility settings. Do not change the old examples' compatibility values without also identifying which edition they demonstrate.

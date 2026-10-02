# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report them privately through GitHub's [private vulnerability reporting](https://github.com/its-aditya-singhal/secure-verified-exchange/security/advisories/new) for this repository. Include:

- the affected component (spec, `svx-format`, `svx-crypto`, `svx-core`, `svx-cli`, or a later service or client);
- a description and its impact;
- steps or a proof-of-concept `.svx` file to reproduce the issue. Use only test keys and fictional data.

We aim to acknowledge reports within 3 business days and to agree a disclosure timeline with you. The default is 90 days or less after a fix is available. Credit is given unless you ask otherwise.

## Scope

In scope:

- **Format and parser.** Memory safety, denial of service, any input that is accepted when it should be rejected.
- **Cryptographic profile.** Construction flaws, missing bindings, downgrade, key-commitment issues.
- **Reference implementation.** Key or plaintext leaks, failure to fail closed.
- **Later phases.** Authorization bypass, tenant isolation, key-release protocol.

Out of scope (see the [threat model](threat-model/THREAT_MODEL.md), Non-goals):

- plaintext exposure on an authorized endpoint after decryption;
- traffic analysis that reveals the opaque routing identifiers or the approximate size;
- reports that depend on the published test-only keys.

## Status

SVX has **not yet** had an independent security review. Until it has, it must not be used to protect real data, and no strong security claims are made.

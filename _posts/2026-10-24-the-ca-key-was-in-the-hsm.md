---
layout: post
title: "The CA Key Was in the HSM. The Trust Was Already Broken."
date: 2026-10-24
categories:
  - security
tags:
  - PKI
  - TLS
  - eMudhra
  - Certificate Authorities
  - Cryptography
description: "A technical analysis of the eMudhra intermediate-CA key compromise, the weak P-384 keys behind it, and why certificate trust, key custody, and traffic interception are different security boundaries."
---

# The CA Key Was in the HSM. The Trust Was Already Broken.

A certificate authority does not need to lose a hardware security module for its trust to fail. It only needs to issue a certificate whose private key was never unpredictable in the first place.

That is the uncomfortable technical center of the [eMudhra incident tracked in Mozilla Bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449). Eight intermediate CA certificates were found to have private keys that researchers could recover independently. The public investigation describes a key-generation ceremony, an unexpected second key pair, similar key labels, and a wrap/unwrap test that departed from the normal process.

The important detail is not simply that the keys were weak. It is how a key that was supposed to be generated inside a hardware security module (HSM) became a key that outsiders could reconstruct from a tiny search space.

This is an analysis of the cryptographic failure and its consequences, not a retelling of the public incident timeline. The core distinction throughout is between **recovering a CA private key**, **getting a relying party to accept a certificate**, and **actually reaching a victim's connection**. Those are three separate steps.

## The curve was not the problem

The affected TLS intermediates used ECDSA over NIST P-384. That sounds reassuring: P-384 is a widely used elliptic curve with a private scalar drawn from a very large range. Exhaustively searching a correctly generated private key is not a realistic attack.

But the security of an elliptic-curve key does not come from the curve name printed in the certificate. It comes from the unpredictability of the private scalar.

For a curve with base point \(G\) and group order \(n\), a private key is a scalar \(d\), and the public key is:

\[
Q = dG
\]

A valid private scalar is selected from the permitted range, normally with cryptographically secure randomness. The public key \(Q\) is safe to publish because recovering \(d\) from \(Q\) is computationally infeasible when the scalar was chosen correctly.

Mozilla's investigation reported that each of the eight affected P-384 private scalars was less than 256. In effect, the private key had only a single byte's worth of possible values, rather than the enormous search space expected for P-384.

An attacker does not need to break the elliptic-curve discrete-log problem to recover such a key. They can test the tiny candidate set:

1. Choose a candidate scalar \(d\) from the small range.
2. Compute \(Q' = dG\).
3. Compare \(Q'\) with the public key in the certificate.
4. Stop when the points match.

The same idea can be implemented by trying the first 256 candidate keys. This is not a sophisticated cryptanalytic breakthrough. It is a failure to generate the secret the algorithm depends on.

**The algorithm remained strong; the secret was not secret in any meaningful computational sense.**

The underlying lesson applies beyond elliptic curves. RSA can use a large modulus and still fail if its primes are predictable or shared. A token can be 256 bits long and still be guessable if it is generated from a small counter. Key length describes the intended space; entropy and correct key handling determine whether the key actually occupies it.

Technical detail and the reported recovery are documented in [Mozilla Bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449).

## How the wrong key became the CA's key

The explanation published by eMudhra in the bug discussion is particularly important because it points beyond a generic claim of weak randomness.

According to eMudhra's account, the April 30, 2025 key-generation ceremony created an expected set of ECC keys. An approved deviation was introduced to test a wrap/unwrap operation for keys intended for export. A flaw in the ceremony code then created a second, weaker key pair on the HSM. Because the key labels were similar, the weaker pair was selected when generating the certificate signing request (CSR). The root CA signed that CSR, and the resulting intermediate certificates therefore bound the CA identity to the weak public keys.

That chain matters:

```text
Normal key-generation ceremony
          |
          v
Expected ECC key pair created
          |
          +---- wrap/unwrap test deviation
                         |
                         v
              Second, weak key pair created
                         |
                         v
              Similar labels obscure the difference
                         |
                         v
              CSR uses the weak public key
                         |
                         v
              Root signs the intermediate certificate
                         |
                         v
              A trusted CA certificate now points
              to a private key outsiders can recover
```

The failure was not a forged signature on an otherwise correct certificate. The root could have signed the CSR correctly, using its own legitimate key, and the result would still be unsafe. The signature proved that the root signed the certificate contents. It did not prove that the subordinate private key had been generated with sufficient entropy or that it was the intended key from the ceremony.

This is a crucial distinction in PKI reviews: **a valid certificate signature can faithfully authenticate a bad key-management outcome.**

The HSM was not necessarily mathematically broken. eMudhra said the devices were Utimaco HSMs and that its preliminary investigation pointed to a flaw in the key-generation ceremony script and human errors in the lifecycle process. A hardware boundary cannot compensate for a workflow that creates an unintended key object and then selects it for certification.

The right question is therefore not just, "Was the key generated in an HSM?" It is, "Can the organization demonstrate that the public key being certified is the one produced by the approved ceremony, under the intended parameters, and that no unintended key object was substituted?"

That requires more than a ceremony checklist. It requires verifiable binding between the ceremony record, HSM object identity, public-key fingerprint, CSR, signed CA certificate, and the key later used for CA operations.

## The earlier CRL problem was a key-identity problem too

The same intermediates had an earlier issue documented in [Mozilla Bug 1970728](https://bugzilla.mozilla.org/show_bug.cgi?id=1970728): CRLs produced for the affected CA certificates had signature-validation problems and were later re-signed.

In its later explanation, eMudhra said the CRLs had initially been signed with the original keys generated during the ceremony, while the issued CA certificates corresponded to the second, weaker keys. The original signatures therefore did not validate against the public keys in those certificates. The CRLs were then signed with the keys corresponding to the issued certificates.

That is more than a routine configuration mistake. It is a signal that the relationship between a CA certificate and the key operators believed they were using had broken down.

A CRL is not just a file to publish. Its signature is how relying parties establish that the revocation information came from the authority named in the certificate. If a CA team discovers that the key it is using does not match the certified public key, the immediate task should not be limited to producing a file that verifies. The mismatch is evidence that key identity and lifecycle controls may have failed.

The incident raises a difficult process question: when that mismatch appeared in 2025, did the investigation establish why two key pairs existed, which one the ceremony intended to certify, and whether the certified key was the intended one? In hindsight, the weak-key discovery makes those questions central. The public bug discussion contains eMudhra's account; the full implementation-level root cause depends on the ceremony script, HSM logs, and audit evidence.

This is why key-management incidents need forensic preservation. A valid replacement CRL can restore one function while leaving the underlying key provenance question unanswered.

## Recovering the key is not the same as intercepting TLS

Suppose an attacker recovers the private key for an intermediate CA that clients trust for TLS server authentication. The attacker can now sign certificates within that intermediate's authority, subject to the constraints in its certificate and the validation rules of the client.

For example, a certificate could name `www.example.com` in its Subject Alternative Name (SAN) while carrying a public key controlled by the attacker. The CA signature can validate. But that alone does not make a browser connect to the attacker's server.

TLS server authentication happens after a client has already established a connection to some endpoint. The certificate does not choose the destination IP address. DNS resolution, routing, proxies, and the client's network path determine where the connection goes.

A successful website impersonation therefore needs at least three distinct conditions:

1. **Issuance capability:** the attacker can produce a certificate for the target name using a key that chains to a trusted authority.
2. **Traffic delivery:** the victim's connection for that name reaches the attacker, for example through control of DNS, a routing position, a compromised proxy, or an on-path network position.
3. **Client acceptance:** the client accepts the chain and hostname after applying its trust-store, certificate-transparency, revocation, pinning, and other applicable policies.

The recovered CA key supplies the first condition. It does not automatically supply the second or third.

This distinction is easy to lose in incident summaries. A certificate for a major website is not a credential to log in to that website's servers. It does not reveal the website's own TLS private key. It does not decrypt previously recorded TLS sessions. In TLS 1.3, the server proves possession of its own private key during the handshake, while ephemeral key exchange protects session secrets. A CA key signs certificates; it is not a universal TLS decryption key. See [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) for certificate and path-validation semantics and [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) for TLS 1.3.

This is not an argument that the compromise is low impact. It is a way to identify exactly which additional control an attacker would need to defeat next.

## Why browser distrust is different from revoking a leaf certificate

A compromised issuing CA creates a problem that is difficult to solve by enumerating bad certificates.

If an attacker can sign certificates with a recovered intermediate key, they can generate new certificates with new serial numbers. Defenders may discover some of them through Certificate Transparency (CT), but they cannot reliably revoke every fraudulent certificate they have not yet identified. Revoking the intermediate itself, or otherwise removing trust in the relevant authority, is the stronger containment action.

Mozilla reported that the affected intermediates were blocked through OneCRL, and the incident escalated into a request to stop issuance under the broader `emSign ECC Root CA - G3` hierarchy. The public discussion also records Chrome's move toward a similar distrust decision. The distinction matters: removing an intermediate blocks chains through that certificate, while distrusting a root affects every chain that relies on it in a given trust store.

Cross-signing complicates this picture. A CA certificate can appear in more than one chain, with different issuer certificates and different trust paths. Blocking one representation is not enough if another cross-signed certificate remains accepted by a trust store. Incident response has to inventory the certificate identities and chain variants, not just the friendly CA name.

This is also why browser trust is not a single global switch. Browsers, operating systems, Java runtimes, containers, appliances, embedded clients, and application-specific trust stores may update on different schedules or use different revocation mechanisms. A distrust decision has to propagate through the actual relying-party ecosystem.

Useful primary references are the [Mozilla incident post](https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/) and the [Mozilla bug discussion](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449). They document the response; client behavior still depends on each platform's trust and revocation implementation.

## The blast radius depends on what the CA is trusted to do

The affected set included six TLS intermediates and two code-signing intermediates, according to Mozilla's report. That difference changes the attack path.

For a TLS issuing CA, the obvious risk is fraudulent server authentication. The attacker still needs a way to deliver a forged certificate to a client in a context where it will be accepted.

For a code-signing CA, the relying party may be the system that receives and evaluates an attacker-supplied signed artifact. The attacker does not necessarily need to redirect an existing victim connection. They still need a delivery path and a victim or system willing to execute or trust the artifact, and platform policy can limit what the signature permits. But the required network capability is different.

Enterprise PKI can be more direct still. If a compromised CA is trusted for client authentication, an attacker may be able to present a forged client certificate to a reachable service that maps certificate identities to accounts. A compromised Active Directory Certificate Services CA can have consequences for certificate-based domain authentication, depending on the CA's authority and environment. See [Certified Pre-Owned by SpecterOps](https://specterops.io/blog/2021/06/17/certified-pre-owned/) for the separate mechanics of AD CS abuse.

The lesson is to classify a CA key by its relying parties and permitted purposes, not just by whether it is called a "TLS CA" or "enterprise CA." The certificate's constraints, the trust store's policy, and the application that consumes the certificate all affect the real blast radius.

## What a strong key ceremony should prove

A ceremony should produce evidence that survives outside the room where the key was generated. The eMudhra case suggests several controls worth testing directly:

- **Bind identities cryptographically.** Record the public-key fingerprint produced by the HSM, the CSR fingerprint, and the public key in the issued CA certificate. Fail the ceremony if they do not match.
- **Treat key labels as hints, not identities.** Labels can help operators navigate an HSM, but automation should verify key attributes and cryptographic fingerprints before use. Similar names must never be sufficient to select a signing key.
- **Make deviations fail closed.** A wrap/unwrap test or export-specific path should be isolated from production key generation. Any deviation should require a separate approval, explicit object identifiers, and an independent check that the intended key—not a newly created or imported object—is being certified.
- **Verify the key pair before certification.** Confirm that the public key corresponds to the private key the ceremony intends to retain, and test the expected cryptographic operation. A CSR proves possession of the private key used to sign the request; it does not prove that the key was generated correctly.
- **Test randomness and key provenance.** A ceremony review should cover the generation mechanism, entropy source, HSM state and configuration, imported or unwrapped material, and the code path that created each key object. "Generated in an HSM" is not a complete answer.
- **Reconcile later operations against the certificate.** CRL signing, OCSP signing, and any CA signing operation should use the key whose public key is bound into the corresponding CA certificate. A mismatch should trigger an incident investigation, not just a retry with another key.
- **Keep auditable ceremony artifacts.** Preserve the script version, approved deviations, witness records, HSM logs, key-object mapping, and signed outputs. These records should make it possible to reconstruct exactly which key was created and which one was certified.

Hardware security modules remain important: they can protect private keys from extraction and enforce cryptographic operations. But they cannot guarantee that the correct key object was selected, that an unsafe code path did not create a weak key, or that a root signed the intended public key. Those are system properties spanning hardware, software, process, and review.

The relevant standards and policy are the [CA/Browser Forum Baseline Requirements](https://cabforum.org/working-groups/server/baseline-requirements/documents/) and the [Mozilla Root Store Policy](https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/). They are useful starting points, but the critical question in a real review is what the ceremony actually did, backed by evidence.

## The uncomfortable conclusion

The eMudhra incident is not evidence that P-384 is broken. It is evidence that a certificate authority can use a strong algorithm, a compliant HSM, and a correctly signed certificate while still failing at the point where key material becomes trust.

The most important failure happened before a browser saw a fraudulent website certificate. A weak private key was bound into an intermediate CA certificate that relying parties had been taught to trust. Once the private key could be reconstructed, the certificate's cryptographic legitimacy became an attacker capability.

That capability is serious on its own: it invalidates confidence that the CA approved every certificate signed by the key. But it should not be confused with automatic traffic interception. For TLS, an attacker still needs a path to the victim and a client that accepts the forged chain. For client-authentication and signing systems, the path can be different and sometimes more direct.

A trustworthy CA needs more than secret keys. It needs evidence that the right keys were generated, the right keys were certified, the right keys were used, and that any mismatch stops the process before it becomes part of the trust infrastructure.

## Further reading

- [Mozilla Bug 2083449: eMudhra intermediate private-key compromise](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)
- [Mozilla Bug 1970728: earlier CRL-signature issue](https://bugzilla.mozilla.org/show_bug.cgi?id=1970728)
- [Mozilla Security Blog: response to the eMudhra intermediate compromise](https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/)
- [RFC 5280: Internet X.509 Public Key Infrastructure Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280)
- [RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [CA/Browser Forum Baseline Requirements](https://cabforum.org/working-groups/server/baseline-requirements/documents/)

---
layout: post
title: "HEIF Heist at OpenAI: From Image Upload to Repository Access"
date: 2026-10-26
categories:
  - security
tags:
  - Memory Safety
  - libheif
  - ImageMagick
  - SSO
  - GitHub
description: "How a HEIF parser heap overflow, an OpenAI SSO flaw, and an existing Codex integration combined into an internal repository action."
---

On July 25, 2026, Hacktron chained a `libheif` heap overflow in OpenAI's community forum with a separate OpenAI SSO misconfiguration. The compromised identity had an existing Codex–GitHub connection, which the researchers used to open a pull request in `openai/openai`. [Hacktron's report](https://www.hacktron.ai/blog/hacking-openai) details the chain.

## Attack path

![Flow diagram showing a crafted HEIF upload leading through libheif heap corruption, forum code execution, an OpenAI SSO flaw, employee Codex impersonation, and an authorized GitHub integration to an internal pull request.](/assets/heif-heist-attack-flow.svg?v=20261026-2)

## 1. HEIF upload to native code execution

Discourse used FastImage for normal upload inspection, but HEIF/HEIC files followed a separate processing path:

1. **Upload:** Discourse receives the image.
2. **Processing:** ImageMagick invokes [libheif](https://github.com/strukturag/libheif) to decode it.
3. **Vulnerability:** The malformed image triggers a heap overflow in `libheif`.

Hacktron reported that the Debian 12-based Discourse environment used `libheif` 1.19.7. An upstream change intended to correct overlay-overlap calculations had not been identified as a security fix, so the downstream package did not include it. The researchers traced the issue to signed overlay offsets being handled in unsigned arithmetic in [`HeifPixelImage::overlay()`](https://github.com/strukturag/libheif/blob/d506eac82a2e0359b6b6bc5b156fb8bd99d8f205/libheif/pixelimage.cc). A negative offset could wrap when converted to `uint32_t`, leaving an invalid width for the blend loop and causing out-of-bounds access.

This is distinct from [CVE-2026-32882](https://github.com/strukturag/libheif/security/advisories/GHSA-hg7q-rjr2-8x46), a separate alpha-stride out-of-bounds-read issue. The [Discourse advisory](https://github.com/discourse/discourse/security/advisories/GHSA-vhm9-85gw-x335) discusses the affected image-processing path.

Hacktron first developed code execution with ASLR disabled, then adapted the exploit to the x86-64 and `jemalloc` environment with ASLR enabled. The resulting upload achieved code execution in the forum environment; it did not directly compromise ChatGPT, Codex, or GitHub.

## 2. SSO crossed the identity boundary

The forum supported **Sign in with OpenAI** through `auth.openai.com`. Hacktron reports that a separate SSO flaw let control of an SSO-connected relying party become impersonation of active members' ChatGPT and Codex accounts.

The OpenAI-side flaw was an SSO misconfiguration: tokens issued through Community sign-in carried excessive permissions, including access to the associated users' ChatGPT and Codex APIs. OpenAI said it narrowed those permissions and revoked affected tokens and sessions ([SecurityWeek](https://www.securityweek.com/AI-BUILT-EXPLOIT-AND-SIGN-IN-FLAW-OPENED-PATH-TO-INTERNAL-OPENAI-CODE/)).

The key bridge was not simply that the token had broad permissions. According to a [secondary technical analysis by Threadlinqs](https://intel.threadlinqs.com/threat/TL-2026-2568), the researchers used their forum RCE foothold to obtain an authenticated employee forum session, then converted that session into a live ChatGPT/Codex API credential. The public write-ups do not document the underlying token exchange or protocol-level validation in enough detail to reconstruct it independently. OpenAI confirmed that Community sign-in tokens had excessive permissions and said it narrowed those permissions and revoked affected tokens and sessions ([SecurityWeek](https://www.securityweek.com/AI-BUILT-EXPLOIT-AND-SIGN-IN-FLAW-OPENED-PATH-TO-INTERNAL-OPENAI-CODE/)).

The likely chain, based on the reporting, is:

1. **Forum RCE:** The researchers gained code execution in Discourse.
2. **Employee forum session:** They used that foothold to obtain an authenticated employee session, according to Threadlinqs' analysis.
3. **SSO/API credential:** The Community sign-in flow allowed that session to be turned into a credential accepted by ChatGPT/Codex APIs, with permissions far broader than forum access required. The exact exchange and validation flaw have not been publicly detailed.
4. **GitHub access:** The employee's existing Codex–GitHub integration then enabled a pull request in OpenAI's internal repository.

This is the best-supported public reconstruction, but the exact implementation-level SSO failure remains undisclosed.  SecurityWeek reported that OpenAI's review found limited reads of private-repository metadata and commits, and that the submitted PR changed a README; OpenAI said access to Slack messages was not verified.

## Security implications

Each stage added a capability that the previous stage did not provide on its own:

- **Parser flaw:** attacker-controlled image data reached a vulnerable native decoder.
- **Forum RCE:** the decoder compromise became code execution in the Discourse environment.
- **SSO permission flaw:** The forum session was reportedly converted into a ChatGPT/Codex API credential with excessive permissions; the exact token exchange and validation flaw remain undisclosed.
- **Existing integration:** the compromised identity's authorized Codex connection enabled a repository action.

The final impact depended on the composition of these boundaries, not on `libheif` alone.

## Mitigations

- **Patch native dependencies.** Track OS-level libraries used by image-processing tools, including fixes that were not initially assigned a CVE.
- **Sandbox image conversion.** Run decoders with a clean environment, restricted filesystem access, no unnecessary network access, and resource limits. Discourse later introduced [sandboxing for ImageMagick calls](https://github.com/discourse/discourse/commit/a07188016987de1613c961277e2e928aaa7c37ec).
- **Scope Community sign-in tokens.** Forum-login tokens should authenticate users to the forum, not grant access to ChatGPT/Codex APIs. OpenAI said it narrowed these permissions and revoked affected tokens and sessions.
- **Restrict Codex's GitHub authority.** The employee's existing Codex connection could create a pull request in `openai/openai`. Limit connected-agent GitHub permissions to the repositories and operations required; protect internal branches with required review so an agent-authored PR cannot be merged solely on the strength of the compromised employee session.
- **Rebuild affected deployments.** Discourse's [security advisory](https://github.com/discourse/discourse/security/advisories/GHSA-vhm9-85gw-x335) instructs self-hosted deployments to rebuild the container so patched OS packages are installed.

## Further reading

- [Hacktron: Hacking OpenAI](https://www.hacktron.ai/blog/hacking-openai)
- [SecurityWeek: AI-Built Exploit and Sign-In Flaw Opened Path to Internal OpenAI Code](https://www.securityweek.com/AI-BUILT-EXPLOIT-AND-SIGN-IN-FLAW-OPENED-PATH-TO-INTERNAL-OPENAI-CODE/)
- [libheif overlay calculation change](https://github.com/strukturag/libheif/commit/85e21ad44eba931314337300a2376b8d28f085ae)
- [Discourse security advisory](https://github.com/discourse/discourse/security/advisories/GHSA-vhm9-85gw-x335)
- [libheif CVE-2026-32882 advisory](https://github.com/strukturag/libheif/security/advisories/GHSA-hg7q-rjr2-8x46)
- [Discourse ImageMagick sandboxing change](https://github.com/discourse/discourse/commit/a07188016987de1613c961277e2e928aaa7c37ec)

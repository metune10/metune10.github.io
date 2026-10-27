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

On July 25, 2026, [Hacktron](https://www.hacktron.ai/blog/hacking-openai) reported a path from an image upload on OpenAI's community forum to a pull request in the internal `openai/openai` repository. The chain required **two independent vulnerabilities** and an existing GitHub authorization.

## Attack path

![Flow diagram showing a crafted HEIF upload leading through libheif heap corruption, forum code execution, an OpenAI SSO flaw, employee Codex impersonation, and an authorized GitHub integration to an internal pull request.](/assets/heif-heist-attack-flow.svg?v=20261026-2)

## 1. HEIF upload to native code execution

Discourse normally inspected uploads with FastImage, which does not support HEIF. HEIC/HEIF uploads followed a separate path through ImageMagick to [libheif](https://github.com/strukturag/libheif):

```text
attacker-controlled HEIF
  → Discourse upload handler
  → ImageMagick magick
  → libheif native decoder
```

Hacktron reported that the Debian 12-based Discourse environment used `libheif` 1.19.7. An upstream change intended to correct overlay-overlap calculations had not been identified as a security fix, so the downstream package did not include it. The researchers traced the issue to signed overlay offsets being handled in unsigned arithmetic in [`HeifPixelImage::overlay()`](https://github.com/strukturag/libheif/blob/d506eac82a2e0359b6b6bc5b156fb8bd99d8f205/libheif/pixelimage.cc). A negative offset could wrap when converted to `uint32_t`, leaving an invalid width for the blend loop and causing out-of-bounds access.

This is distinct from [CVE-2026-32882](https://github.com/strukturag/libheif/security/advisories/GHSA-hg7q-rjr2-8x46), a separate alpha-stride out-of-bounds-read issue. The [Discourse advisory](https://github.com/discourse/discourse/security/advisories/GHSA-vhm9-85gw-x335) discusses the affected image-processing path.

Hacktron first developed code execution with ASLR disabled, then adapted the exploit to the x86-64 and `jemalloc` environment with ASLR enabled. The resulting upload achieved code execution in the forum environment; it did not directly compromise ChatGPT, Codex, or GitHub.

## 2. SSO crossed the identity boundary

The forum supported **Sign in with OpenAI** through `auth.openai.com`. Hacktron reports that a separate SSO flaw let control of an SSO-connected relying party become impersonation of active members' ChatGPT and Codex accounts.

The public report does not disclose the exact SSO exploit, so the mechanism below is a **plausible interpretation, not a confirmed reconstruction**.

If the compromised forum could influence the OpenAI sign-in flow, the separate flaw may have allowed tokens issued for Community sign-in—or the authorization associated with them—to reach beyond forum authentication. Reporting says those tokens had permissions that reached the users' ChatGPT and Codex APIs. The missing detail is how the researchers turned control of the forum into usable access to those tokens or permissions; the public write-up does not establish that step.

```text
forum code execution
  → possible abuse of the Community SSO flow
  → separate token / authorization flaw
  → employee ChatGPT/Codex account access
```

This is an inference from the reported token-permission issue, not proof that RCE directly exposed a token. The employee's Codex account already had authorized access to OpenAI's GitHub organization. Hacktron used that existing integration to have Codex open a harmless pull request in `openai/openai`. The researchers say they stopped at proof of access and did not read or dump private source code.

## Security implications

Each stage added a capability that the previous stage did not provide on its own:

- **Parser flaw:** attacker-controlled image data reached a vulnerable native decoder.
- **Forum RCE:** the decoder compromise became code execution in the Discourse environment.
- **SSO flaw:** control of the relying party crossed into employee identity.
- **Existing integration:** the compromised identity's authorized Codex connection enabled a repository action.

The final impact depended on the composition of these boundaries, not on `libheif` alone.

## Mitigations

- **Patch native dependencies.** Track OS-level libraries used by image-processing tools, including fixes that were not initially assigned a CVE.
- **Sandbox image conversion.** Run decoders with a clean environment, restricted filesystem access, no unnecessary network access, and resource limits. Discourse later introduced [sandboxing for ImageMagick calls](https://github.com/discourse/discourse/commit/a07188016987de1613c961277e2e928aaa7c37ec).
- **Scope Community sign-in tokens.** Reporting says Community sign-in tokens carried permissions reaching ChatGPT and Codex APIs. Keep forum-login tokens limited to forum authentication. OpenAI said it narrowed the permissions and revoked affected tokens and sessions; the public report does not fully explain how RCE was connected to token abuse.
- **Restrict Codex's GitHub authority.** The employee's existing Codex connection could create a pull request in `openai/openai`. Limit connected-agent GitHub permissions to the repositories and operations required; protect internal branches with required review so an agent-authored PR cannot be merged solely on the strength of the compromised employee session.
- **Rebuild affected deployments.** Discourse's [security advisory](https://github.com/discourse/discourse/security/advisories/GHSA-vhm9-85gw-x335) instructs self-hosted deployments to rebuild the container so patched OS packages are installed.

## Further reading

- [Hacktron: Hacking OpenAI](https://www.hacktron.ai/blog/hacking-openai)
- [libheif overlay calculation change](https://github.com/strukturag/libheif/commit/85e21ad44eba931314337300a2376b8d28f085ae)
- [Discourse security advisory](https://github.com/discourse/discourse/security/advisories/GHSA-vhm9-85gw-x335)
- [libheif CVE-2026-32882 advisory](https://github.com/strukturag/libheif/security/advisories/GHSA-hg7q-rjr2-8x46)
- [Discourse ImageMagick sandboxing change](https://github.com/discourse/discourse/commit/a07188016987de1613c961277e2e928aaa7c37ec)

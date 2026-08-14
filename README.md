# iOS Reverse Engineering Toolkit

A comprehensive toolkit and skill for extracting, analyzing, and auditing iOS applications — IPAs, `.app` bundles, Mach-O binaries, dynamic libraries, and frameworks. It automates class dumping, API endpoint extraction, call-flow tracing, secret/credential scanning, LLM-assisted binary reversing (Ghidra headless), SDK fingerprinting with CVE cross-referencing, anti-tampering detection, and a static vulnerability audit. Works with both Swift and Objective-C applications on macOS and Linux.

## Features

- **IPA / .app extraction** — Unpacks archives, locates the main Mach-O, runs class dumps, extracts `Info.plist`, entitlements, embedded frameworks, privacy manifests, and Mach-O header flags (PIE / hardened runtime).
- **API endpoint extraction** — Detects HTTP APIs across URLSession, Alamofire, AFNetworking, Moya, GraphQL, and WebSocket, with deduplication and Markdown report generation.
- **Call-flow tracing** — Guides analysis from `AppDelegate` / entry points down to the network layer through ViewControllers, ViewModels, repositories, and API clients.
- **Deep secret & credential scanning** — Validates cloud credentials (Firebase, AWS, GCP, Azure, Stripe, GitHub, GitLab, web3, and more) with false-positive filtering, entropy checks, placeholder allowlists, and `client-safe` tagging.
- **LLM-assisted binary reversing** — radare2/rizin and Ghidra headless analysis with decompilation, cross-references, call graphs, crypto usage, secret hunting, and string xrefs.
- **SDK fingerprinting** — Identifies third-party SDKs, detects versions, and cross-references known CVEs.
- **Anti-tampering detection** — Obfuscation, anti-debugging, dylib injection prevention, integrity checks, jailbreak detection, and FairPlay DRM, with a protection score (0–20).
- **Static vulnerability audit** — Storage, WebView/JS-bridge, deeplink hijack, weak crypto/RNG, insecure deserialization, XXE / Zip Slip, ATS / cert-pinning misconfig, privacy, and Mach-O hardening checks.
- **Cross-platform** — Fully functional on macOS and Linux (falls back to `ipsw`, `plistutil`, and Python where Apple's developer tools are unavailable).

## Prerequisites

| Tool | Purpose | Required |
|------|---------|----------|
| [ipsw](https://github.com/blacktop/ipsw) | Class dumping, Mach-O analysis, entitlements, thinning | Yes |
| Xcode Command Line Tools (`otool`, `strings`, `plutil`, `codesign`, `lipo`) | Native analysis on macOS | macOS only |
| [radare2](https://github.com/radareorg/radare2) / [rizin](https://github.com/rizinorg/rizin) | Deep binary analysis | Recommended |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | Headless decompilation (Java scripts included) | Optional |
| [jtool2](https://github.com/blacktop/ipsw) / frida | Deeper dynamic analysis | Optional |

## Installation

Clone the repository and run the dependency checker:

```bash
git clone https://github.com/saudgl/ios-reverse-engineering-skills.git
cd ios-reverse-engineering-skills

bash scripts/check-deps.sh
```

If required dependencies are missing, install them automatically:

```bash
bash scripts/install-dep.sh ipsw
# or manually, e.g. with Homebrew:
# brew install blacktop/tap/ipsw
```

## Quick Start

```bash
# 1. Extract and analyze an IPA
bash scripts/extract-ipa.sh App.ipa -o App-analysis

# 2. Find API endpoints and generate a report
bash scripts/find-api-calls.sh App-analysis/ --context 3 --dedup --report api-report.md

# 3. Deep-scan for cloud credentials
bash scripts/deep-secret-scan.sh App-analysis/ --report secrets-report.md

# 4. Fingerprint embedded SDKs with CVE checks
bash scripts/detect-sdks.sh App-analysis/ --check-cves --report sdks-report.md

# 5. Detect anti-tampering protections
bash scripts/detect-protections.sh App-analysis/ --report protections-report.md

# 6. Audit for iOS vulnerability classes
bash scripts/audit-vulnerabilities.sh App-analysis/ --all --report vuln-report.md

# 7. Deep binary reversing with Ghidra headless (optional)
bash scripts/reversing-analyze.sh --tool ghidra App-analysis/Payload/App.app/App -o App-analysis/reversing
```

## Scripts Overview

| Script | Description |
|--------|-------------|
| `check-deps.sh` | Verifies required and optional tooling; prints machine-readable install instructions |
| `install-dep.sh` | Installs a dependency via Homebrew or GitHub releases |
| `extract-ipa.sh` | Extracts IPA / `.app` / Mach-O / `.dylib` / `.framework` artifacts into an analysis directory |
| `find-api-calls.sh` | Searches for URLSession, Alamofire, AFNetworking, GraphQL, WebSocket, auth, and security patterns |
| `deep-secret-scan.sh` | Validates cloud-provider credentials with FP filtering and severity rating |
| `reversing-analyze.sh` | Runs radare2/rizin or Ghidra headless analysis (secrets, network, crypto, auth, entropy, callgraphs) |
| `detect-sdks.sh` | Fingerprints third-party SDKs with version detection and CVE cross-referencing |
| `detect-protections.sh` | Detects obfuscation, anti-debug, injection prevention, integrity checks, jailbreak detection |
| `audit-vulnerabilities.sh` | Static audit of iOS vulnerability classes with severity / confidence / FP-likelihood |
| `scripts/ghidra/*.java` | Ghidra headless scripts for decompilation, secrets, API calls, crypto usage, and string xrefs |

## Workflow

1. **Verify dependencies** — `check-deps.sh`, install anything missing.
2. **Extract & dump classes** — `extract-ipa.sh` produces class dumps, plists, entitlements, frameworks, and Mach-O metadata.
3. **Analyze structure** — Review `Info.plist`, entitlements, class-dump output, and embedded frameworks to map the architecture (MVC / MVVM / VIPER / Coordinator).
4. **Trace call flows** — Follow entry points → ViewModels → repositories → API clients.
5. **Extract & document APIs** — `find-api-calls.sh` plus per-endpoint documentation of method, path, params, headers, and call chain.
6. **Security analysis** — ATS exceptions, cert pinning, exposed secrets, jailbreak detection, weak crypto, keychain misuse, debug artifacts.
7. **Deep secret & credential analysis** — `deep-secret-scan.sh` with LLM triage (classify, assess blast radius, validate, remediate).
8. **Deep binary reversing** — radare2/rizin or Ghidra headless with LLM review of decompiled functions, xrefs, and crypto usage.
9. **SDK fingerprinting** — detect versions and cross-reference CVEs; assess attack surface and data flows.
10. **Anti-tampering detection** — obfuscation, anti-debug, injection prevention, integrity, jailbreak; compute protection score.
11. **Static vulnerability audit** — `audit-vulnerabilities.sh` across storage, WebView, deeplink, crypto, deserialization, parsing, ATS, privacy, and hardening.

## Reports

The scripts generate structured Markdown reports automatically via `--report`:

- `api-report.md` — Discovered endpoints with call flows
- `secrets-report.md` — Validated credentials with FP-likelihood and client-safe tags
- `sdks-report.md` — SDK inventory with versions and CVE matches
- `protections-report.md` — Protection mechanisms and protection score
- `vuln-report.md` — Vulnerability findings with severity / confidence / evidence

## Project Structure

```
ios-reverse-engineering/
├── SKILL.md                    # Full skill definition and workflow
├── scripts/                    # Analysis scripts (shell)
│   ├── check-deps.sh
│   ├── install-dep.sh
│   ├── extract-ipa.sh
│   ├── find-api-calls.sh
│   ├── deep-secret-scan.sh
│   ├── reversing-analyze.sh
│   ├── detect-sdks.sh
│   ├── detect-protections.sh
│   ├── audit-vulnerabilities.sh
│   └── ghidra/                 # Ghidra headless Java scripts
└── references/                 # Detailed reference guides
```

## AI Assistant & Model Compatibility

This project is designed to be loaded as a **skill** by AI coding assistants. The skill itself is **model-agnostic** — it is a set of instructions plus shell/Ghidra scripts, so it runs under any LLM that can execute commands and read files. It has been verified with:

| Assistant | Model | Skill directory |
|-----------|-------|-----------------|
| **opencode** | **DeepSeek** (and any model configured) | `~/.config/opencode/skills/` |
| **Claude Code** | **Claude** (Anthropic) | `~/.claude/skills/` |
| Any other agent tool | Any LLM | `~/.agents/skills/` or your tool's skill path |

Point your assistant's skill directory at this repository (or symlink it) so the workflow, phase-by-phase guidance, and helper scripts are available during iOS analysis sessions. The `SKILL.md` frontmatter (`compatibility: opencode`) enables automatic loading in opencode; for Claude Code, place the folder under `~/.claude/skills/`.

## Security & Ethics

This toolkit is intended for **authorized security assessments** — analyzing apps you own or have explicit permission to test. Always comply with applicable laws and the target application's terms of service. Use responsibly.

## References

Detailed reference guides live in `references/`:

- `setup-guide.md` — Installing ipsw, jtool2, frida, and optional tools
- `class-dump-usage.md` — ipsw class-dump CLI options and Mach-O analysis
- `api-extraction-patterns.md` — Library-specific search patterns and documentation template
- `call-flow-analysis.md` — Techniques for tracing call flows
- `cloud-secrets-patterns.md` — Cloud credential patterns and FP minimization
- `reversing-tools-guide.md` — radare2, rizin, and Ghidra headless reference
- `sdk-fingerprinting.md` — SDK fingerprint database and CVE reference
- `anti-tampering-patterns.md` — Obfuscation, anti-debug, and injection prevention patterns
- `vulnerability-patterns.md` — iOS vulnerability classes with FP notes and remediation

## Author & Credits

Maintained by **SaudGL** — [https://github.com/saudgl](https://github.com/saudgl)

This skill was originally derived from the **iOS Reverse Engineering Claude Skill** by **incogbyte**. We gratefully acknowledge the original author's work:

- **incogbyte/iOS-reverse-engineering-claude-skill** — [https://github.com/incogbyte/iOS-reverse-engineering-claude-skill](https://github.com/incogbyte/iOS-reverse-engineering-claude-skill)

This fork ports the original Claude Code skill to opencode/DeepSeek while keeping it fully compatible with Claude Code and any other LLM-powered assistant.

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2026 SaudGL

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

# HexHawk Role Fitness Evaluation

Generated: 20260708-222743
Status: evaluation-only; no code/source changes; no public release claim
## Executive summary
HexHawk currently fits best for defensive/static reverse-engineering roles that need reproducible file identity, strings/imports, disassembly/CFG, STRIKE headless JSON, and custody-style reports. In this pass, 27 realistic roles were evaluated: 6 strong fits, 14 partial fits, 6 weak fits, and 1 refusal-boundary/not-appropriate workflows. The strongest current users are DFIR, malware analysts, threat intel analysts, EDR/signature reviewers, CTF/crackme lab users, and other authorized static-analysis users. The weakest or out-of-scope areas are firmware/ROM/game/TAS/chiptune workflows requiring specialized formats, or misuse-prone roles that must stay in refusal-boundary mode.
## Current build/custody baseline
- HEAD: `a58258c5cb5eedcf0ff30a0dd0eebc65896f8818`
- origin/main: `a58258c5cb5eedcf0ff30a0dd0eebc65896f8818`
- CI run 28969901106: success (`https://github.com/Zielmenosza/hexhawk/actions/runs/28969901106`)
- Installer smoke: previously passed with `all_ok: true` per committed custody report.
- Installed challenge smoke: previously passed on DESKTOP-0F2PCGU per committed custody report.
- Signing/public status: unsigned / NotSigned; not public-release-ready; no Microsoft verified claim.
- Git status at start:

```text
## main...origin/main
?? docs/aetherframe-runs/installer-smoke-plan-20260708-194641.md
?? docs/aetherframe-runs/worktree-custody-20260701-201449.md
?? work/
```
## Evidence used
### Files and fixtures
- pwn109 ELF challenge: `D:\Project\HexHawk\Challenges\pwn109-1644300507645.pwn109`
- pwn110 ELF challenge: `D:\Project\HexHawk\Challenges\pwn110-1644300525386.pwn110`
- crackme_shroud PE challenge: `D:\Project\HexHawk\Challenges\crackme_shroud.exe`
- project_chimera Python loader: `D:\Project\HexHawk\Challenges\2 - project_chimera\project_chimera.py`
- FlareAuthenticator GUI PE: `D:\Project\HexHawk\Challenges\8 - FlareAuthenticator\FlareAuthenticator.exe`
- recreated safe challenge-family harness: `D:\Project\HexHawk\work\recreate_challenges\bin\challenge_family_safe_stub.exe`
- challenge-derived STRIKE scenarios: `D:\Project\HexHawk\HexHawk\scripts\strike-benchmarks\challenge-derived-scenarios.json`

### Test methods
- Documentation/workflow fit review: README, App.tsx workspace copy, installed challenge custody reports.
- CLI/static capability: `identify`, `inspect`, `strings`, `disassemble`, `cfg`, `strike --headless`.
- Evidence/export review: STRIKE headless JSON schema and committed custody reports.
- Safety-boundary review: role interpretation against hard rules; no challenge binaries executed.

CLI command summary: 35/35 commands exited 0 without timeout.

Raw command outputs: `D:\Project\HexHawk\work\role_fitness_evaluation_20260708-222743`

### STRIKE headless report keys observed
- `D:\Project\HexHawk\work\role_fitness_evaluation_20260708-222743\crackme_shroud-PE-challenge-strike-report.json` keys=['file', 'verdict', 'imports', 'strings', 'il_summary', 'signals', 'generated_at'] verdict={'classification': 'unknown', 'confidence': 'low'} sha256=36bfae11c18fb5fa214110d7f17cdc92026bce53e28e9a1965b4193e59c1a6a1
- `D:\Project\HexHawk\work\role_fitness_evaluation_20260708-222743\FlareAuthenticator-GUI-PE-strike-report.json` keys=['file', 'verdict', 'imports', 'strings', 'il_summary', 'signals', 'generated_at'] verdict={'classification': 'unknown', 'confidence': 'low'} sha256=d5030be9d1ec0edecebc822b7168c210d4e40cff2f4e37cbd14b0f9dbd1d497b
- `D:\Project\HexHawk\work\role_fitness_evaluation_20260708-222743\project_chimera-Python-loader-strike-report.json` keys=['file', 'verdict', 'imports', 'strings', 'il_summary', 'signals', 'generated_at'] verdict={'classification': 'unknown', 'confidence': 'low'} sha256=5e32e763c36670a846140401a27dd8feab2e1b0c76df090e6994249f2206b9c5
- `D:\Project\HexHawk\work\role_fitness_evaluation_20260708-222743\pwn109-ELF-challenge-strike-report.json` keys=['file', 'verdict', 'imports', 'strings', 'il_summary', 'signals', 'generated_at'] verdict={'classification': 'unknown', 'confidence': 'low'} sha256=584437fee0634094beee89eb6b6b35b8844c292b2c634c983467511dc175a66a
- `D:\Project\HexHawk\work\role_fitness_evaluation_20260708-222743\pwn110-ELF-challenge-strike-report.json` keys=['file', 'verdict', 'imports', 'strings', 'il_summary', 'signals', 'generated_at'] verdict={'classification': 'unknown', 'confidence': 'low'} sha256=66d0f50fdd3176ebe4775c73437d57f8e48b9aa1a3a8fe8327689586cdeeed6b
- `D:\Project\HexHawk\work\role_fitness_evaluation_20260708-222743\recreated-safe-challenge-family-harness-strike-report.json` keys=['file', 'verdict', 'imports', 'strings', 'il_summary', 'signals', 'generated_at'] verdict={'classification': 'unknown', 'confidence': 'low'} sha256=e631aefef457d77b8f28a1a2824d3976cc1d13bc0a5128caa356c3c4dc38fdd3

## Role matrix

### A. Technical & Engineering Roles

#### Compiler Engineers
- Legitimate user goal: Understand codegen/ABI artifacts and compare disassembly/CFG for small binaries.
- HexHawk task to test: pwn109/pwn110/recreated harness via inspect, disassemble, cfg, strings
- Allowed test inputs: Challenge ELFs/PE safe harness; no execution
- Forbidden actions: Execute unknown binaries or infer compiler intent beyond evidence
- Expected HexHawk evidence output: file identity, strings, disassembly/CFG blocks, il_summary
- Relevant HexHawk component: TALON, NEST, Function Notebook/export, NEXUS/UI
- Success criteria: Can inspect file facts and CFG without overclaiming source semantics
- Current gap: Partial CLI support; stronger source-map/ABI annotations needed
- Priority: later
- Safety classification: safe
- Result: **partial fit**
- Recommended improvement: Partial CLI support; stronger source-map/ABI annotations needed

#### Firmware Engineers
- Legitimate user goal: Triage firmware-like binaries for strings, sections, architecture, endpoints.
- HexHawk task to test: metadata/strings on safe binaries and scenarios JSON; role workflow review
- Allowed test inputs: Local challenge binaries as generic opaque blobs; existing static fixture reports
- Forbidden actions: Emulation, device bypass, key extraction, cloud bypass
- Expected HexHawk evidence output: hashes, strings, imports/sections where format-supported, limitations
- Relevant HexHawk component: NEST, TALON, STRIKE, Function Notebook/export
- Success criteria: Reports clearly show format support/unsupported paths
- Current gap: Dedicated firmware container formats and memory maps absent
- Priority: later
- Safety classification: dual-use bounded
- Result: **partial fit**
- Recommended improvement: Dedicated firmware container formats and memory maps absent

#### Operating System Developers
- Legitimate user goal: Inspect low-level binary structure, imports, branch flow, runtime evidence boundaries.
- HexHawk task to test: disassemble/cfg/inspect on selected binaries
- Allowed test inputs: pwn109/pwn110/recreated harness
- Forbidden actions: Kernel debugging, driver loading, privileged execution
- Expected HexHawk evidence output: disassembly/CFG, exact file hashes, report export
- Relevant HexHawk component: TALON, STRIKE, Function Notebook/export
- Success criteria: Static code map works and runtime claims stay bounded
- Current gap: No OS kernel/module-specific workflow
- Priority: later
- Safety classification: safe
- Result: **partial fit**
- Recommended improvement: No OS kernel/module-specific workflow

### B. Cybersecurity & Defense Roles

#### Antivirus & EDR Signers
- Legitimate user goal: Validate static signals and evidence packages for defensive classification review.
- HexHawk task to test: strike --headless on selected challenge files; report keys review
- Allowed test inputs: Challenge samples as lab fixtures; committed smoke reports
- Forbidden actions: Signing, production detections, malware execution
- Expected HexHawk evidence output: file/verdict/imports/strings/il_summary/signals/generated_at
- Relevant HexHawk component: GYRE, STRIKE, NEST, Function Notebook/export
- Success criteria: Report schema supports evidence handoff; GYRE authority preserved
- Current gap: Rule export / signer workflow not present
- Priority: now
- Safety classification: dual-use bounded
- Result: **strong fit**
- Recommended improvement: Rule export / signer workflow not present

#### Digital Forensics & Incident Responders
- Legitimate user goal: Produce defensible file triage evidence with hashes and provenance.
- HexHawk task to test: inspect, strings, strike headless; custody report review
- Allowed test inputs: Selected local challenge files and installed smoke reports
- Forbidden actions: Modify evidence originals, execute unknown files, claim runtime behavior not observed
- Expected HexHawk evidence output: hashes, strings/imports, signal list, generated_at, limitations
- Relevant HexHawk component: NEST, GYRE, STRIKE, export
- Success criteria: Static evidence is reproducible and exported
- Current gap: Chain-of-custody UX could be more explicit
- Priority: now
- Safety classification: safe
- Result: **strong fit**
- Recommended improvement: Chain-of-custody UX could be more explicit

#### Exploit Developers / authorized vulnerability researchers
- Legitimate user goal: Find vulnerability-relevant metadata and unsafe APIs under authorized lab framing.
- HexHawk task to test: pwn109/pwn110 strings/disassembly/CFG only
- Allowed test inputs: pwn lab binaries, no execution
- Forbidden actions: Weaponized PoCs, offsets-to-exploit instructions, payloads
- Expected HexHawk evidence output: unsafe input clues, CFG/disassembly, advisory notes
- Relevant HexHawk component: TALON, STRIKE, NEST, NEXUS/UI
- Success criteria: Supports authorized analysis without payload generation
- Current gap: Needs explicit UI refusal text for exploit construction
- Priority: later
- Safety classification: restricted / refusal-boundary only
- Result: **partial fit**
- Recommended improvement: Needs explicit UI refusal text for exploit construction

#### Malware Analysts
- Legitimate user goal: Defensive static analysis of suspicious samples without detonation.
- HexHawk task to test: strings/imports/strike headless for crackme/FlareAuthenticator; no execution
- Allowed test inputs: Lab challenge samples only
- Forbidden actions: Malware execution, persistence, evasion, operational guidance
- Expected HexHawk evidence output: static indicators, imports, strings, signals, unknown/low-confidence verdict when appropriate
- Relevant HexHawk component: GYRE, STRIKE, NEST, TALON, export
- Success criteria: Processes risky-looking samples without crash/execution
- Current gap: Needs clearer malware-analysis mode and rule-export path
- Priority: now
- Safety classification: dual-use bounded
- Result: **strong fit**
- Recommended improvement: Needs clearer malware-analysis mode and rule-export path

#### Military & Defense Contractors
- Legitimate user goal: Evidence packaging for authorized defensive binary assurance.
- HexHawk task to test: role workflow/custody docs + CLI static reports
- Allowed test inputs: Local fixtures and reports
- Forbidden actions: Operational target exploitation or classified handling claims
- Expected HexHawk evidence output: provenance, hashes, limitations, unsigned status
- Relevant HexHawk component: NEST, GYRE, Function Notebook/export
- Success criteria: Authority boundaries and custody docs are explicit
- Current gap: Compliance templates and airgap workflow need productization
- Priority: later
- Safety classification: dual-use bounded
- Result: **partial fit**
- Recommended improvement: Compliance templates and airgap workflow need productization

#### Threat Intelligence Analysts
- Legitimate user goal: Extract indicators and summarize suspicious static features for reporting.
- HexHawk task to test: strings/strike reports on challenge PE and Python loader
- Allowed test inputs: Challenge files, scenarios JSON
- Forbidden actions: Attribution claims without evidence, malware execution
- Expected HexHawk evidence output: strings/imports/signals/report JSON
- Relevant HexHawk component: STRIKE, NEST, GYRE, export
- Success criteria: Useful static indicators and report fields present
- Current gap: Needs IOC export formats/STIX/YARA mapping
- Priority: now
- Safety classification: dual-use bounded
- Result: **strong fit**
- Recommended improvement: Needs IOC export formats/STIX/YARA mapping

#### Vulnerability Researchers & Pentesters
- Legitimate user goal: Authorized software assessment and evidence capture.
- HexHawk task to test: inspect/disassemble/cfg on pwn fixtures; safety boundary review
- Allowed test inputs: CTF/lab binaries only
- Forbidden actions: Exploitation against third-party systems, payloads
- Expected HexHawk evidence output: CFG, disassembly, unsafe hints, limitations
- Relevant HexHawk component: TALON, STRIKE, NEST, Function Notebook
- Success criteria: Can support analysis and reporting without executing targets
- Current gap: Needs authorization workflow/checklist in UI
- Priority: later
- Safety classification: dual-use bounded
- Result: **partial fit**
- Recommended improvement: Needs authorization workflow/checklist in UI

### C. Legal, Academic, & Regulatory Roles

#### Academic Researchers
- Legitimate user goal: Reproducible static binary-analysis experiments and citations.
- HexHawk task to test: CLI reports + docs review for methodology/reproducibility
- Allowed test inputs: Local lab fixtures, committed custody reports
- Forbidden actions: Claims beyond dataset; unlicensed corpus distribution
- Expected HexHawk evidence output: commands, hashes, report schema, limitations
- Relevant HexHawk component: NEST, export, AETHERFRAME
- Success criteria: Reproducible evidence paths exist
- Current gap: Needs stable benchmark corpus docs/API
- Priority: later
- Safety classification: safe
- Result: **partial fit**
- Recommended improvement: Needs stable benchmark corpus docs/API

#### Cryptanalysts
- Legitimate user goal: Locate crypto-related imports/strings and analyze routines at high level.
- HexHawk task to test: strings/imports/strike on crackme/FlareAuthenticator/project_chimera
- Allowed test inputs: Challenge samples
- Forbidden actions: Key recovery from real services, credential extraction
- Expected HexHawk evidence output: crypto strings/imports/signals, disassembly where supported
- Relevant HexHawk component: TALON, STRIKE, NEST
- Success criteria: Can surface crypto indicators
- Current gap: No cryptographic algorithm workbench or symbolic routines
- Priority: later
- Safety classification: dual-use bounded
- Result: **weak fit**
- Recommended improvement: No cryptographic algorithm workbench or symbolic routines

#### Intellectual Property Attorneys
- Legitimate user goal: Document file identity and high-level evidence for authorized review.
- HexHawk task to test: inspect/report export/custody docs review
- Allowed test inputs: Local reports and static metadata
- Forbidden actions: Circumvent DRM, extract proprietary secrets, legal conclusions
- Expected HexHawk evidence output: hashes, metadata, strings excerpts, provenance, limitations
- Relevant HexHawk component: NEST, export, NEXUS/UI
- Success criteria: Can create evidence package without overclaiming
- Current gap: Needs legal-friendly redaction/export templates
- Priority: later
- Safety classification: safe
- Result: **partial fit**
- Recommended improvement: Needs legal-friendly redaction/export templates

### D. Hardware Modders & Repair Enthusiasts

#### Automotive Engineers
- Legitimate user goal: Authorized firmware/software component triage for owned systems.
- HexHawk task to test: firmware-like workflow fit review; static strings on opaque fixtures
- Allowed test inputs: Local opaque binaries only
- Forbidden actions: Vehicle bypass/tampering instructions, safety-critical modification guidance
- Expected HexHawk evidence output: file metadata/strings and unsupported-format limitations
- Relevant HexHawk component: NEST, TALON, export
- Success criteria: Can triage files as data
- Current gap: No automotive firmware formats/safety workflow
- Priority: later
- Safety classification: restricted / refusal-boundary only
- Result: **weak fit**
- Recommended improvement: No automotive firmware formats/safety workflow

#### Hardware & IoT Security Auditors
- Legitimate user goal: Owned/authorized device firmware privacy/security audit.
- HexHawk task to test: strings/inspect role workflow review
- Allowed test inputs: Safe local binaries as stand-ins
- Forbidden actions: Credential extraction/use, cloud bypass, unauthorized device access
- Expected HexHawk evidence output: endpoint/string clues, file hashes, limitations
- Relevant HexHawk component: NEST, STRIKE, export
- Success criteria: Static evidence workflow transferable
- Current gap: Firmware unpacking and secrets redaction absent
- Priority: later
- Safety classification: dual-use bounded
- Result: **partial fit**
- Recommended improvement: Firmware unpacking and secrets redaction absent

#### Jailbreakers & Custom Firmware Creators / owned-device firmware researchers
- Legitimate user goal: Understand owned-device firmware behavior without bypass instructions.
- HexHawk task to test: refusal-boundary workflow review + static metadata only
- Allowed test inputs: Synthetic/local fixtures only
- Forbidden actions: Bypass real access controls, signing bypass, exploit chains
- Expected HexHawk evidence output: metadata, strings, limitations, refusal boundary
- Relevant HexHawk component: NEXUS/UI, NEST, export
- Success criteria: Supports benign understanding; must refuse bypass workflows
- Current gap: Needs explicit owned-device/bypass safety copy
- Priority: later
- Safety classification: restricted / refusal-boundary only
- Result: **weak fit**
- Recommended improvement: Needs explicit owned-device/bypass safety copy

#### Right-to-Repair Enthusiasts
- Legitimate user goal: Inspect owned-device binaries for interoperability clues.
- HexHawk task to test: strings/metadata review
- Allowed test inputs: Local fixtures as analogs
- Forbidden actions: DRM circumvention or proprietary secret extraction
- Expected HexHawk evidence output: strings/hashes/provenance, no secret use
- Relevant HexHawk component: NEST, export, NEXUS/UI
- Success criteria: Can preserve evidence and limitations
- Current gap: Needs right-to-repair templates and redaction
- Priority: later
- Safety classification: dual-use bounded
- Result: **partial fit**
- Recommended improvement: Needs right-to-repair templates and redaction

#### Smart Home Hackers / owned-device privacy auditors
- Legitimate user goal: Find hardcoded endpoints/permissions in owned-device artifacts.
- HexHawk task to test: strings and report review
- Allowed test inputs: Local fixture strings only
- Forbidden actions: Credential use, cloud bypass, unauthorized access
- Expected HexHawk evidence output: endpoint-like strings if present, file identity
- Relevant HexHawk component: STRIKE, NEST, export
- Success criteria: Static string workflow fits privacy audit
- Current gap: IoT firmware extraction not built in
- Priority: later
- Safety classification: dual-use bounded
- Result: **partial fit**
- Recommended improvement: IoT firmware extraction not built in

### E. Gaming, Retro, & Creative Hobbyists

#### Anti-Cheat Breakers & Cheaters / anti-cheat abuse-risk researchers
- Legitimate user goal: Assess abuse-risk patterns and enforce refusal for cheat creation.
- HexHawk task to test: safety-boundary review; no memory tampering
- Allowed test inputs: No game processes; local fixtures only
- Forbidden actions: Cheat development, injection, bypasses, address tables
- Expected HexHawk evidence output: tamper/injection pattern evidence at high level, refusal boundary
- Relevant HexHawk component: NEXUS/UI, STRIKE, GYRE
- Success criteria: Can discuss defensive abuse-risk; should refuse offense
- Current gap: Needs explicit anti-cheat misuse refusal UX
- Priority: later
- Safety classification: restricted / refusal-boundary only
- Result: **not appropriate / refusal-boundary**
- Recommended improvement: Needs explicit anti-cheat misuse refusal UX

#### Chiptune Musicians
- Legitimate user goal: Analyze old executable/audio assets for preservation/inspiration.
- HexHawk task to test: strings/metadata on safe binaries; workflow review
- Allowed test inputs: Local challenge fixtures only
- Forbidden actions: Copyright circumvention, ripping protected assets unlawfully
- Expected HexHawk evidence output: metadata/strings/export
- Relevant HexHawk component: NEST, export, NEXUS/UI
- Success criteria: Basic binary exploration possible
- Current gap: No audio/chiptune-specific extraction features
- Priority: out-of-scope
- Safety classification: safe
- Result: **weak fit**
- Recommended improvement: No audio/chiptune-specific extraction features

#### Digital Preservationists
- Legitimate user goal: Catalog and preserve file identity/evidence for old software.
- HexHawk task to test: inspect/hash/report workflow
- Allowed test inputs: Local fixtures and custody reports
- Forbidden actions: Circumvent access controls or distribute copyrighted binaries
- Expected HexHawk evidence output: hashes, metadata, provenance, limitations
- Relevant HexHawk component: NEST, export
- Success criteria: Good hash/provenance baseline
- Current gap: Needs preservation manifest/export formats
- Priority: later
- Safety classification: safe
- Result: **partial fit**
- Recommended improvement: Needs preservation manifest/export formats

#### Game Preservationists
- Legitimate user goal: Understand legacy game binaries under lawful preservation.
- HexHawk task to test: inspect/strings/disassembly where allowed
- Allowed test inputs: Local fixtures only
- Forbidden actions: DRM bypass or distributing copyrighted game files
- Expected HexHawk evidence output: metadata, strings, CFG/disassembly, limitations
- Relevant HexHawk component: TALON, NEST, export
- Success criteria: Technical analysis path works
- Current gap: Needs legal boundary guidance and asset workflows
- Priority: later
- Safety classification: dual-use bounded
- Result: **partial fit**
- Recommended improvement: Needs legal boundary guidance and asset workflows

#### ROM Hackers & Retro Gamers
- Legitimate user goal: Explore owned ROMs/homebrew for learning and patch planning.
- HexHawk task to test: workflow review; binary static analysis as analog
- Allowed test inputs: Safe local binaries only
- Forbidden actions: Bypass DRM, distribute ROMs, cheat services
- Expected HexHawk evidence output: offset/strings/disassembly evidence and limitations
- Relevant HexHawk component: TALON, NEST, Function Notebook
- Success criteria: Hex/CFG mindset transferable
- Current gap: No ROM console format support/patch tooling
- Priority: later
- Safety classification: dual-use bounded
- Result: **weak fit**
- Recommended improvement: No ROM console format support/patch tooling

#### Speedrunners & TAS Creators
- Legitimate user goal: Study deterministic behavior of owned games/emulators at high level.
- HexHawk task to test: workflow review only
- Allowed test inputs: No game execution; safe fixtures only
- Forbidden actions: Cheating online, anti-cheat bypass, memory manipulation guides
- Expected HexHawk evidence output: static evidence only; limitations
- Relevant HexHawk component: NEXUS/UI, NEST
- Success criteria: Not the right primary tool today
- Current gap: Needs emulator/TAS integrations; mostly out of scope
- Priority: out-of-scope
- Safety classification: safe
- Result: **weak fit**
- Recommended improvement: Needs emulator/TAS integrations; mostly out of scope

### F. Students & Competitive Problem Solvers

#### CTF Competitors
- Legitimate user goal: Learn static RE workflow on authorized challenge binaries.
- HexHawk task to test: pwn/crackme/project_chimera static CLI tests
- Allowed test inputs: Local Challenges folder, recreated safe harness
- Forbidden actions: Attack real targets, malware execution outside lab
- Expected HexHawk evidence output: strings/disassembly/CFG/headless reports
- Relevant HexHawk component: TALON, STRIKE, NEST, export
- Success criteria: Strong for lab static triage and evidence exports
- Current gap: Needs beginner walkthrough mode
- Priority: now
- Safety classification: dual-use bounded
- Result: **strong fit**
- Recommended improvement: Needs beginner walkthrough mode

#### Crackme Solvers / authorized lab only
- Legitimate user goal: Analyze crackmes as authorized exercises.
- HexHawk task to test: crackme_shroud static strings/disassembly/CFG/strike
- Allowed test inputs: Local crackme challenge only
- Forbidden actions: Bypassing commercial trial locks or DRM
- Expected HexHawk evidence output: strings/imports/disassembly, report warnings
- Relevant HexHawk component: TALON, STRIKE, NEST
- Success criteria: Works for lab/crackme static path
- Current gap: Needs explicit commercial-DRM refusal boundary
- Priority: now
- Safety classification: dual-use bounded
- Result: **strong fit**
- Recommended improvement: Needs explicit commercial-DRM refusal boundary

#### Students & Hobbyists
- Legitimate user goal: Learn how binary analysis evidence fits together safely.
- HexHawk task to test: read UI docs + CLI help + simple fixtures
- Allowed test inputs: pwn109/pwn110/project_chimera safe static analysis
- Forbidden actions: Executing unknown samples or overclaiming verdicts
- Expected HexHawk evidence output: plain-language UI guidance, report outputs
- Relevant HexHawk component: NEXUS/UI, NEST, GYRE, TALON, STRIKE
- Success criteria: Good concepts but CLI is expert-oriented
- Current gap: Needs guided tutorial and role-safe examples
- Priority: now
- Safety classification: safe
- Result: **partial fit**
- Recommended improvement: Needs guided tutorial and role-safe examples

## Cross-role patterns
### HexHawk already serves well
- Static evidence triage of local binaries and challenge/lab files.
- Reproducible report/export fields with hashes and generated_at.
- Authority-boundary language in README/UI: GYRE remains verdict authority; TALON/STRIKE/NEST are evidence/advisory layers.
- Defensive workflows where execution is not required.
- CTF/crackme authorized-lab analysis without executing samples.

### HexHawk does not yet serve well
- Specialized firmware, ROM, automotive, IoT, chiptune, and TAS workflows.
- Legal/IP-ready redacted report templates.
- Installed CLI decompile/TALON export; currently CLI exposes disassemble/CFG but not a direct decompile command.
- Safe role-presets and beginner guided workflows.
- Production EDR/signature pipeline exports.

### Repeated missing features
- Role-specific report profiles.
- Better provenance/chain-of-custody manifests.
- Explicit refusal-boundary copy for misuse-prone workflows.
- Guided tutorial workflows using safe challenge fixtures.
- Specialized parsers/importers for firmware/ROM/container formats.

## Safety/refusal findings
- Exploit development is supported only as authorized vulnerability research; payload construction and weaponized PoCs remain forbidden.
- Anti-cheat breaker/cheater workflows should be reframed to defensive anti-cheat abuse-risk research; cheat creation, bypasses, memory injection, and address tables are refusal-boundary items.
- Crackme solving is appropriate only for authorized labs; commercial trial lock bypass remains forbidden.
- Jailbreak/custom firmware work is appropriate only for owned-device firmware research; bypassing real access controls remains forbidden.
- Right-to-repair/smart-home analysis should support owned-device privacy/security audits without credential extraction or cloud bypass.
- Malware analyst/EDR workflows are defensive/static only in this pass; no malware execution occurred.

## Top 10 improvements ranked by impact and feasibility
1. **Add role-based workflow presets/onboarding** — High impact, medium effort. Repeated gap for students, DFIR, malware, CTF, firmware, legal.
2. **Expose a safe installed CLI decompile/TALON advisory command or export** — High impact, medium effort. CLI currently exposes disassemble/cfg but not decompile/TALON; many roles need reviewable pseudocode.
3. **Add explicit misuse/refusal boundary copy for exploit, anti-cheat, jailbreak, DRM, credential extraction roles** — High impact, low effort. Safety-critical and product-positioning gap.
4. **Add report/export profiles: DFIR, threat intel, legal/IP, academic, CTF learning** — High impact, medium effort. Same evidence needs different packaging.
5. **Add chain-of-custody/provenance manifest generation** — High impact, low-medium effort. Needed by DFIR, legal, defense, academic.
6. **Add IOC/YARA/STIX-style defensive export helpers** — Medium-high impact, medium effort. Threat intel/EDR workflows lack downstream format support.
7. **Add firmware/container/ROM format triage adapters** — Medium impact, high effort. Needed for firmware, IoT, repair, preservation, ROM roles.
8. **Add beginner-safe tutorial mode using pwn109/pwn110/crackme labs without execution** — Medium impact, low-medium effort. Students/CTF/crackme users need guided learning.
9. **Clarify unsupported formats and low-confidence verdict next steps in reports** — Medium impact, low effort. Many roles benefit from limitation visibility.
10. **Add role-safe challenge corpus documentation and expected outputs** — Medium impact, low effort. Improves repeatability without unsafe execution.

## No-release-claim reminder
This evaluation does not create a public release claim. The tested build remains unsigned, not Microsoft verified, not public/world-ready, and not approved for package delivery.

## Appendix: UI/docs evidence snippets
### README / custody snippets
```text
README.md:5:It combines local static analysis, disassembly, decompiler assistance, debugger/trace evidence, signature correlation, NEST evidence convergence, GYRE verdict synthesis, and CREST-style reporting in one analyst workflow.
README.md:9:HexHawk is currently a validated source candidate on `feature/re-workbench-core-next` after the v1.30 Function Intelligence integration and v1.31 byte_counter clippy fix. It is not yet a freshly packaged unsigned deployment candidate from this source state, not a publicly trusted signed release, not updater-ready, and not enterprise/procurement-ready distribution.
README.md:28:- v1.21.0 TALON pseudocode IR artefact cleanup.
README.md:32:- v1.25-v1.30 Function Intelligence model, static/runtime correlation, JSON/Markdown export, Function Notebook UI, workflow wiring, and regression coverage.
README.md:34:Function Intelligence and Function Notebook are advisory evidence surfaces. GYRE remains the sole verdict/classification authority. NEST organizes evidence; TALON/decompiler output is advisory reconstruction; STRIKE/debugger output is runtime evidence only.
README.md:38:Older June 20/21 release evidence remains useful provenance, but it does not prove the current v1.30/v1.31 source state as a packaged candidate unless a fresh release worktree rebuild, artifact hashes, signing checks, installer smoke, and Function Notebook/export smoke are completed for the exact artifacts.
README.md:40:## Engine Stack and Authority Boundaries
README.md:42:- GYRE: sole verdict authority for classification and base confidence.
README.md:43:- NEST: evidence orchestrator/convergence layer; selects and packages GYRE-linked evidence but does not replace GYRE.
README.md:44:- AETHERFRAME/Forge: optional bounded confidence uplift, refinement, and lineage metadata; never changes GYRE classification. Standalone AetherFrame core is product-agnostic and adapter-driven; HexHawk is one adapter/proving ground, not the conceptual owner.
README.md:45:- TALON: decompiler and structured pseudocode/evidence surface.
README.md:46:- STRIKE: debugger/trace timeline intelligence and behavioral deltas.
README.md:48:- CREST: report packaging/export surface.
README.md:56:- Function Intelligence model and Function Notebook UI for selected-function imports, calls, pseudocode, runtime observations, limits, and JSON/Markdown export.
README.md:57:- NEST evidence bundle validation with GYRE sole-verdict-source checks.
README.md:59:- Stable native GUI selectors and export-parity probes for workflow validation.
README.md:63:- TALON/decompiler hardening for CFG/disassembly range alignment, fallback block partitioning, cross-block argument recovery, first-pass semantic naming heuristics, and IR artefact cleanup.
README.md:71:- Unsigned-build caution: expect Windows security warnings until an organization-trusted signing path is configured and verified.
README.md:97:Packaging, signing, installer smoke, and Function Notebook export smoke are still separate release-gate checks for the current source state.
README.md:104:- Public release candidate: NO.
docs/aetherframe-runs/installed-challenges-test-20260708-211221.md:11:- No arbitrary challenge binaries were executed. Static analysis/metadata/disassembly/STRIKE headless reports only.
docs/aetherframe-runs/installed-challenges-test-20260708-211221.md:71:## STRIKE/NEST-style report exports created
docs/aetherframe-runs/installed-challenges-test-20260708-211221.md:79:## TALON/decompiler note
docs/aetherframe-runs/installed-challenges-test-20260708-211221.md:81:The installed `nest_cli.exe --help` exposes `disassemble` and `cfg` commands, but no installed CLI decompile/TALON command. Advisory disassembly/CFG outputs were produced for binary selected samples where supported. GUI TALON/decompiler was not manually driven against the challenge folder in this run.
docs/aetherframe-runs/installed-challenges-test-20260708-211221.md:83:## Function Notebook/export note
docs/aetherframe-runs/installed-challenges-test-20260708-211221.md:85:No installed CLI Function Notebook export command was exposed by `nest_cli.exe --help`; STRIKE headless JSON reports were used as the available installed export path.
```
### App.tsx workspace copy snippets
```text
86:// TALON � Reasoning-Aware Decompiler
92:// STRIKE � Runtime Intelligence Debugger
292:  { id: 'function-notebook', label: 'Function details', eyebrow: 'notebook' },
295:  { id: 'talon', label: 'Code reasoning', eyebrow: 'TALON' },
296:  { id: 'nest', label: 'Evidence loop', eyebrow: 'NEST' },
303:  title: string;
304:  plainName: string;
305:  does: string;
307:  expect: string;
312:    title: 'Open a file for local analysis',
313:    plainName: 'Start here',
314:    does: 'Selects the file HexHawk will inspect. Nothing is classified yet; this only chooses the analysis target.',
316:    expect: 'The file name appears in the left rail and the next recommended step becomes available.',
319:    title: 'File summary and identity',
320:    plainName: 'What is this file?',
321:    does: 'Shows file type, architecture, size, hashes, sections, imports, and exports so every later finding ties back to the exact file.',
323:    expect: 'A compact identity card, not a verdict. Suspicious-looking facts still need corroboration.',
326:    title: 'Inspect File',
327:    plainName: 'Safe first pass',
328:    does: 'Reads basic structure and identity without trying to decide everything at once.',
330:    expect: 'File facts, sections, imports, exports, and hashes. This prepares evidence for later analysis.',
333:    title: 'Raw bytes / Hex Viewer',
334:    plainName: 'Exact file bytes',
335:    does: 'Shows the file as byte values and printable characters so you can verify exact offsets and copy byte ranges.',
337:    expect: 'Low-level evidence. Useful for verification, patch planning, and exact offset review.',
340:    title: 'Readable strings',
341:    plainName: 'Text clues inside the file',
342:    does: 'Extracts readable text that may reveal URLs, domains, registry keys, file paths, commands, APIs, or embedded markers.',
344:    expect: 'Clues, not proof by themselves. Stronger conclusions come from matching strings with imports, code, and verdict evidence.',
347:    title: 'Code map / Disassembly',
348:    plainName: 'Instructions and references',
349:    does: 'Turns machine-code bytes into instruction rows, cross-references, suspicious patterns, and patch suggestions.',
351:    expect: 'A bounded window into code. It helps explain behavior but may not cover the whole file at once.',
354:    title: 'Branch map / Control-flow graph',
355:    plainName: 'How code can move',
356:    does: 'Draws basic blocks and edges so branches, exits, loops, and decision points are easier to follow.',
358:    expect: 'A map of the analyzed range, not a guarantee that every possible runtime path was executed.',
361:    title: 'Function details notebook',
362:    plainName: 'One function, all evidence',
363:    does: 'Combines imports, callers, callees, pseudocode, runtime observations, and known limits for the selected function.',
364:    how: ['Select a function in the Code map or Branch map.', 'Press F or choose Function details from the right-click menu.', 'Export JSON or Markdown when you need a reviewable function evidence package.'],
365:    expect: 'Advisory function evidence only. GYRE remains the sole verdict authority.',
368:    title: 'Pseudocode view',
369:    plainName: 'Best-effort readable code summary',
370:    does: 'Summarizes instructions into more readable structured logic where possible.',
372:    expect: 'Helpful approximation with limitations, especially around types, indirect calls, and optimized code.',
375:    title: 'TALON structured reasoning',
376:    plainName: 'Code explanation helper',
377:    does: 'Adds structured analysis over functions, instructions, and control flow to help explain what code appears to do.',
379:    expect: 'Explanations and maturity notes, not final security truth.',
382:    title: 'STRIKE API reference',
383:    plainName: 'Scriptable advisory helpers',
384:    does: 'Documents STRIKE query helpers for IL matching, xrefs, constants, hooks, and Function Intelligence exports.',
385:    how: ['Search for a method by name or purpose.', 'Copy the method signature or example.', 'Remember all STRIKE outputs are advisory evidence, not GYRE verdict authority.'],
386:    expect: 'Discoverable scripting/query surface with explicit authority boundaries.',
389:    title: 'Verdict',
390:    plainName: 'Main classification answer',
391:    does: 'Shows the GYRE classification, confidence, supporting signals, reductions, contradictions, and next review areas.',
393:    expect: 'GYRE remains the verdict authority. Other systems can add evidence or metadata but must not silently replace the classification.',
396:    title: 'Signals / why HexHawk flagged things',
397:    plainName: 'Evidence drivers',
398:    does: 'Shows suspicious patterns, imports, strings, instruction categories, and other signal groups that influence analysis.',
400:    expect: 'A breakdown of reasons and weights. Signals explain the verdict but do not override GYRE by themselves.',
403:    title: 'Report export',
404:    plainName: 'Shareable analysis record',
405:    does: 'Packages file identity, verdict, evidence, and optional report metadata into JSON or Markdown for review.',
407:    expect: 'A record of observed evidence and analysis status, not a claim that every behavior was proven at runtime.',
410:    title: 'Snapshot history',
411:    plainName: 'Previous analysis states',
412:    does: 'Stores and displays earlier analysis snapshots so you can compare work across time.',
414:    expect: 'Historical context. Current file state may differ from older snapshots.',
417:    title: 'NEST evidence review loop',
418:    plainName: 'Repeat evidence organizer',
419:    does: 'Runs iterative evidence passes and organizes convergence around GYRE-linked outputs.',
421:    expect: 'Better-organized evidence and possible confidence refinement. NEST does not become verdict authority.',
424:    title: 'Activity log',
425:    plainName: 'What happened in this session',
426:    does: 'Lists actions, warnings, errors, and important UI/backend events so you can retrace the workflow.',
428:    expect: 'Operational history, not analysis evidence by itself.',
431:    title: 'Patch planning',
432:    plainName: 'Review binary edits before applying',
433:    does: 'Queues possible byte edits such as branch inversion or NOP ranges for analyst review.',
435:    expect: 'A planned edit list. Applying patches changes copies/artifacts and should be handled carefully.',
438:    title: 'Constraint solver',
439:    plainName: 'Input and check logic helper',
440:    does: 'Looks for comparisons, tainted values, and candidate checks that may explain accepted inputs or gate conditions.',
442:    expect: 'Candidate logic explanations, not guaranteed keys, passwords, or exploit proof.',
445:    title: 'Sandbox / scripted checks',
446:    plainName: 'Controlled helper execution',
447:    does: 'Runs supported helper scripts or controlled checks where configured.',
448:    how: ['Read the panel output before drawing conclusions.', 'Do not assume this detonates malware or proves runtime behavior unless the workflow says so explicitly.'],
449:    expect: 'Supplemental evidence from configured checks. It supports review but does not replace static evidence or GYRE.',
452:    title: 'Debugger / runtime trace review',
453:    plainName: 'Runtime evidence when available',
454:    does: 'Reviews debugger sessions, imported traces, or runtime deltas when those artifacts are available.',
456:    expect: 'Supporting runtime evidence. It does not bypass protections or become final verdict authority.',
459:    title: 'Binary Diff',
460:    plainName: 'Compare two files',
461:    does: 'Compares identity, strings, instructions, CFG blocks, and verdict changes between a base file and another file.',
463:    expect: 'A change map. Differences explain what changed, not automatically whether the change is malicious.',
466:    title: 'REPL / interactive commands',
467:    plainName: 'Advanced command workspace',
468:    does: 'Provides an interactive place for supported inspection commands tied to the current file.',
470:    expect: 'Advanced helper output that should be cross-checked with main evidence panels.',
473:    title: 'Agent Gate',
474:    plainName: 'Review AI suggestions as notes',
475:    does: 'Shows suggestions from external AI/agent workflows. Approving adds an analyst note only; it does not affect GYRE verdicts or analysis signals.',
477:    expect: 'Approved suggestions appear as advisory analyst notes with provenance labels.',
480:    title: 'Plugin Manager',
481:    plainName: 'Extra approved tools',
482:    does: 'Runs built-in or user-approved plugin checks and shows summaries for the current file.',
484:    expect: 'Additional observations from plugins, with success/failure status and summary output.',
494:      <p><strong>What it does:</strong> {guide.does}</p>
501:      <p><strong>What to expect:</strong> {guide.expect}</p>
510:  { id: 'function-notebook', label: 'Function details', detail: 'imports, calls, pseudocode, and evidence' },
2081:  // NEST-enriched verdict � set when a NEST session completes; cleared on new file load
2136:    hasStrike: false, // extended when STRIKE session is active
2319:        title: observation.kind === 'likely-purpose' ? `${observation.title}?` : `Review ${observation.title.toLowerCase()}?`,
3303:      // F: Open Function details for the focused/selected function
4131:        label: 'Function details',
4560:                    <div><strong>F</strong> → Function details for selected function</div>
5126:            {/* ── TALON ────────────────────────────────────────────────────── */}
5127:            {activeView === 'talon' && gateTab('talon', 'TALON', (
5160:                        <span>NEST-enriched verdict - {nestEnrichedVerdict.signals.length} signals, {nestEnrichedVerdict.confidence ?? nestEnrichedVerdict.threatScore}% confidence</span>
5257:            {/* ── NEST ──────────────────────────────────────────────────────── */}
5258:            {activeView === 'nest' && gateTab('nest', 'NEST', (
5261:                  <h3>NEST evidence loop (browser simulation)</h3>
5262:                  <p>This simulated mode shows how NEST repeats evidence review passes. It organizes evidence around the GYRE verdict; it does not replace GYRE as the classification authority.</p>
5266:                      addLog('Started NEST simulation session in browser mode.', 'info');
5270:                        summary: 'NEST simulation elevated confidence after iterative passes.',
5272:                      setMessage('NEST simulation completed. Verdict enriched.');
5562:                    <p>Use <strong>Strings</strong>, <strong>Code map</strong>, <strong>CFG</strong>, and <strong>NEST</strong> to connect readable clues, instructions, branches, and scored signals.</p>
5603:                  <li><strong>NEST</strong> organizes and converges evidence; it does not replace GYRE as verdict authority.</li>
5605:                  <li><strong>STRIKE, TALON, ECHO, and CFG views</strong> are analyst evidence surfaces. Treat them as places to inspect and corroborate, not as magic proof.</li>
5657:                  <li><strong>NEST</strong> organizes and converges evidence around that verdict.</li>
```

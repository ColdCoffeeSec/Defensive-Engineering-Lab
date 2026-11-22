# Analysis: LummaC2 (Lumma Stealer)

**Status:** desk analysis from public reports only. No sample was obtained, unpacked or executed for this file. **[ASSUMED]** (`ENVIRONMENT_ASSUMPTIONS.md` section 3: no live samples are handled in this repository, dynamic analysis is out of scope.)

Tags are defined in `CTI_CONTEXT.md` ("Tag legend"): **[V: source]** checked on 2026-11-22, **[U]** unverified, **[A]** analyst-derived, **[ASSUMED]** from the environment file. The same caveat applies: V tags come from a subagent's reading of the pages, and truncated page tails are not trusted.

## 1. Sample inventory

| SHA-256 | Source | Family version | Handled by this repo? |
|---|---|---|---|
| none recorded yet | | | No |

- No hash is listed because none has been read yet. AA25-141B Table 6 lists 15 executable hashes (MD5, SHA-1, TLSH, SHA-256) and Table 7 lists two DLL names, `iphlpapi.dll` and `winhttp.dll`. **[V: CISA]** The hashes were **not** read in this step. Step 5 adds them to `iocs.csv`, keyed by SHA-256, with source and retrieval date.
- A hash here means "this file was named in a source". It does not mean the file was obtained, and no file is linked.
- Findings in sections 2-4 are therefore **reported findings**, not our own static results. Nothing in this repo has been confirmed in offline analysis. **[U]** until someone with authority and an isolated VM confirms it.

## 2. Reported static findings

| Finding | Source |
|---|---|
| The core binary is heavily obfuscated: LLVM-based obfuscation, control-flow flattening, custom stack-based string decryption, dead code. | **[V: Microsoft]** |
| Critical APIs are called through low-level syscalls and Heaven's Gate. | **[V: Microsoft]** |
| The loader "may use process hollowing" into `msbuild.exe`, `regasm.exe`, `regsvcs.exe` or `explorer.exe`. S1213 names `BitLockerToGo.exe` as a hollowing target. | **[V: Microsoft; MITRE]** |
| C2 list and Telegram fallback are protected with ChaCha20. The Steam fallback URL uses a custom stack-based algorithm that can change between versions. | **[V: Microsoft]** |
| In the version Elastic analysed, the sample sets up its cryptographic context **after loading `WinHTTP.dll`**, and reuses that context for every ChaCha20 decryption call without reinitialising it. An internal counter changes with each use, so decryption order matters. | **[V: Elastic 2025-10-14]**. Applies to the sample Elastic analysed. No numbered Lumma version is given. |
| Elastic also reports XOR-ROL applied to the ChaCha20 constant during context setup. | **[V: Elastic]** |
| The Steam dead-drop page is read with a "simple Caesar cipher (ROT11)". | **[V: ESET]** |
| Config protection changed over time (see section 3.2). | **[V: ESET]** |

## 3. Config structure

### 3.1 What is published

eSentire TRU, January 23, 2025: the sample uses "a structure containing the ChaCha20 magic (16 bytes), 32-byte key, 8-byte nonce". The structure also holds the encrypted C2 data and its size. The nonce "is padded with four null bytes". Key and nonce "differ from sample to sample". Figure 4 of the page shows "C2 and Build ID extracted". **[V: eSentire]**

**Not published on that page:** the content of the 16-byte magic, the byte order, the offsets of each field, the width and endianness of the size field, and whether the structure is on disk or only in memory. **[V: absent]** The eSentire extraction script on GitHub names a layout, but it was not read here.

ESET describes the March 2025 form as ChaCha20 "where the key and nonce were prepended to the encrypted configuration". **[V: ESET]**

Elastic's own sample code describes a 0x40-byte in-memory context: key at 0x10-0x30, counter at 0x30, nonce at 0x38-0x40, with the counter starting at 2 because the decryption function has already run once. **[V: Elastic, via subagent]** That is a *memory* context, not the eSentire structure, and it is not used as a layout source.

### 3.2 Reported evolution of config protection (ESET)

| Period | Reported protection | Source |
|---|---|---|
| until January 2025 | 32-byte XOR key plus base64 for the C2 list | **[V: ESET]** |
| until March 2025 | 32-byte XOR plus base64 for the dynamic config | **[V: ESET]** |
| March 2025 | ChaCha20, key and nonce prepended to the encrypted config | **[V: ESET]** |
| April 2025 | 8-byte XOR for JSON values | **[V: ESET]** |
| January 2025 | ChaCha20 observed for the C2 config (eSentire date) | **[V: eSentire]** |

The January and March dates differ. They may describe different configs or samples. **[U]** Not reconciled.

### 3.3 Schema this repo uses for synthetic blobs

`tools/config_extract.py` (step 6) needs a byte layout. The published sources give sizes only, so the following layout is **ours**:

| Offset | Size | Field | Basis |
|---|---|---|---|
| 0 | 16 | magic | Size **[V: eSentire]**. Value: a fixed, test-only 16-byte string **[A]** |
| 16 | 32 | key | Size **[V: eSentire]** |
| 48 | 8 | nonce | Size **[V: eSentire]** |
| 56 | 4 | ciphertext length, little-endian | Field and width **[A]** |
| 60 | n | ChaCha20 ciphertext | Cipher **[V: eSentire; Microsoft; ESET]** |

Rules for this schema:

- **It is a test format, not a claim about Lumma's real layout.** Ordering, the length field and the magic value are **[A]**. A parser that passes the synthetic round-trip proves the parser matches *this table*. It says nothing about real Lumma blobs. `TESTING.md` repeats this limit.
- **The nonce is 8 bytes, padded with four null bytes to 12** for implementations that want a 12-byte nonce. **[V: eSentire]** (padding) **[A]** (how the chosen library consumes it. To be checked when the library is pinned in step 6).
- **Test keys are generated inside the test run**, from a fixed seed, and are never committed or reused. The plaintext is synthetic and uses reserved-range names only (RFC 5737 addresses, `.example` domains, per `ENVIRONMENT_ASSUMPTIONS.md` section 6).
- The extractor is run **only** on blobs the tests generate. It is never pointed at a file from outside the repo.

## 4. Behaviours as telemetry

What each reported behaviour would look like in the reference environment, and whether a rule can claim it.

| Behaviour | Source | Telemetry in reference env | Can a rule claim it? |
|---|---|---|---|
| User opens Run dialog, pastes a command, runs `powershell` with a Base64 command or `mshta` | **[V: CISA; Microsoft]** | Sysmon 1 (parent, child, command line); PowerShell 4104 `[ASSUMED]` | **Yes.** Planned rule 001. Caveat: truncated command lines in Sysmon 1 **[A]**; obfuscation defeats text match on 4104 **[A]** |
| Run dialog history written to the registry by `explorer.exe` | Microsoft hunting query **[U]** | Sysmon 13 `[ASSUMED]` | **Candidate only.** Which key and value are involved was not read. Not in the three planned rules. **[U]** |
| `mshta` fetches remote JavaScript, which starts PowerShell, which starts a Lumma executable | **[V: Microsoft]** | Sysmon 1 process chain; Sysmon 3 for the fetch `[ASSUMED]` | **Partly.** Covered by rule 001 if `mshta` is in its scope. Decision for step 3. |
| Reads of browser credential or cookie stores by a non-browser process | **[V: MITRE; Microsoft]** | Needs Security 4663 + SACL. **Not enabled** `[ASSUMED]`. Sysmon 11 does not record reads **[A]** | **Not in the reference environment.** Rule 002 can be written but cannot fire here. Needs a user decision at step 3. |
| HTTPS POST to C2 with form fields | **[V: Microsoft]** | Proxy or DNS logs with method, URI, User-Agent "where available" `[ASSUMED]`; Sysmon 3, 22 | **Weak.** Bodies and often URIs are encrypted **[A]**. No C2 User-Agent was published. **[V: absent]** ESET gives two config-request User-Agent variants (Chrome/119 and Chrome/109) from its own analysis, which this module does **not** use as a detection key. **[A]** |
| Cloudflare fronting | **[V: Microsoft]** | Destination IPs shared with legitimate sites | **No.** Not usable as a signal. **[A]** |
| Steam / Telegram dead-drop lookup | **[V: Microsoft; ESET]** | Ordinary HTTPS to common sites | **No.** Not distinguishable from normal use here. **[A]** |
| HKCU Run key persistence | **[V: MITRE]** | Sysmon 13 `[ASSUMED]` | **Out of this module's three-rule plan.** Candidate for later. **[A]** |
| Process hollowing, reflective loading, syscall stubs | **[V: Microsoft; MITRE]** | Memory telemetry **not assumed** `[ASSUMED]` | **No.** Documented gap. |
| Registry or sandbox checks, debugger checks, AMSI string patching | **[V: MITRE]** | None assumed | **No.** Documented gap. |
| Staging under `%USERPROFILE%\AppData\Roaming` | **[V: MITRE]** | Sysmon 11 `[ASSUMED]` | **Not claimed.** Too generic to be a rule on its own. **[A]** |

## 5. Questions an analyst with sample access and authority could answer

These are **not** done here. They are listed so the limits are visible.

1. What is the real byte layout of the config structure for each version, and does it match section 3.3? **[U]**
2. Which versions use the `WinHTTP.dll`-then-context pattern Elastic describes, and are the byte patterns for context setup stable enough for a YARA rule? **[U]** (Step 4 writes YARA from published descriptions only, not from analysis, and says so.)
3. What User-Agent strings do current builds send? **[U]**
4. Do the T-IDs in `CTI_CONTEXT.md` section 3 hold in v17? **[U]**

## 6. Constraints that apply to every later step

- No sample, payload, real key or real hostname enters the repo. Hashes and defanged, sourced indicators only (`iocs.csv`, step 5).
- Public YARA text is not copied. Our patterns are written independently and labelled analyst-derived. **[A]**
- Any rule, test or playbook step that needs a value missing from `ENVIRONMENT_ASSUMPTIONS.md` stops and asks.

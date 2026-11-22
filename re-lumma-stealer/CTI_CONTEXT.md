# CTI Context: LummaC2 (Lumma Stealer) Infostealer

| | |
|---|---|
| **Classification** | TLP:CLEAR (portfolio / lab material) |
| **Date** | 2026-11-22 |
| **Author** | [name / team] |
| **Family** | Lumma Stealer / LummaC2, MITRE ATT&CK software S1213 |
| **ATT&CK version pinned** | v17 `[ASSUMED]` (`ENVIRONMENT_ASSUMPTIONS.md` section 5), the version AA25-141B uses |
| **Linked artifacts** | `ANALYSIS.md`, `IR_PLAYBOOK.md` (step 5), `detection_rules/` (steps 3-4), `ENVIRONMENT_ASSUMPTIONS.md` |

> **Scope note.** This brief is built from public reporting only. No sample was downloaded, executed or unpacked for it (`ENVIRONMENT_ASSUMPTIONS.md` section 3). ATT&CK mappings are the analyst's own reading of public sources, not vendor-assigned, unless a row says otherwise. Nothing here describes a real organization.

## Tag legend

| Tag | Meaning |
|---|---|
| **[V: source]** | Checked against the named public page on 2026-11-22. |
| **[U]** | Unverified. Not found on a page read this session, or not read at all. Not used as a basis for a rule. |
| **[A]** | Analyst-derived inference. Needs confirmation before production use. |
| **[ASSUMED]** | A value from `ENVIRONMENT_ASSUMPTIONS.md`. Not a fact about any real environment. |

**How the V tags were produced.** On 2026-11-22 each of the seven pages in section 8 was downloaded as raw HTML with `curl` (HTTP 200; sizes in section 8) and kept outside the repo. A claim is tagged **V** only if its wording (a quote, a number, an ID or a date) was found by exact string search in that page's text, after stripping HTML tags and normalising whitespace, entities and curly quotes. A claim whose wording was not found is tagged **U**. An earlier pass relied on a subagent's summary of the pages. That pass is not trusted, and every V tag was re-checked against the raw text. Quotation marks in this file mean the quoted words were found verbatim. Paraphrases are not in quotation marks. Hunting-query and IOC contents from the sources are **not copied** into the repo. Page text can still be wrong or change: the tags say what the page said on that date.

## 1. Corrections to the earlier blueprint

`BLUEPRINT.md` (outside this repo, not edited) was checked against the sources on 2026-11-22. Differences:

| Blueprint statement | Finding this session | Effect |
|---|---|---|
| "394,000 infected Windows computers between March 16 and May 16, 2025" [V] | The string "394,000" does not occur in the downloaded Microsoft Security Blog page (May 21, 2025). The figure may come from a different Microsoft page that was not read. | Downgraded to **[U]**. Not used. |
| Steam and Telegram dead-drop claim [U] | **Found.** Microsoft: "fallback C2s hosted as Steam profiles and Telegram channels", Telegram checked first, Steam only when hardcoded C2s are inactive. ESET: backup C2 read from "a dummy Steam profile web page acting as a dead-drop resolver", protected by "a simple Caesar cipher (ROT11)"; Telegram dead-drop as primary from February 2025. | Upgraded to **[V: Microsoft 2025-05-21; ESET 2025-05-21]**. Still **not used in any rule** here: the reference environment has no telemetry that distinguishes it from normal browsing. |
| "No source for XOR, then ChaCha20" [U] | **Partly sourced, in a different form.** ESET: "up until January 2025, the C&C domains in the samples were protected by an XOR function and base64 encoding", where the first 32 bytes of the decoded string are the XOR key. In January 2025 the C&C list moved to ChaCha20 "with a single hardcoded key and nonce". The dynamic configuration was protected by a "32-byte XOR function and base64 encoding" until March 2025, when it "changed to ChaCha20, where the key and nonce were prepended to the encrypted configuration". From April 2025 JSON values use "an 8-byte XOR function". None of the seven pages contains the words single-byte, one-byte or 1-byte XOR. Elastic describes XOR-ROL applied to parts of the ChaCha20 *constant* during context setup, which is something else. | The XOR-to-ChaCha20 progression is **[V: ESET 2025-05-21]** for the multi-byte forms only. A single-byte XOR stage stays **[U]**. No rule or test depends on it. |
| "The developers said they were operating again" [V] | Source is **Check Point Research (May 29, 2025)**, quoting developer messages relayed by threat actors. The ESET page does not say this. | Re-attributed. **[V: Check Point 2025-05-29]**, with the caveat that the claim is the developer's own. |
| ~2,300 domains seized [V] | Confirmed for Microsoft: "approximately 2,300 malicious domains". Check Point quotes the developer as saying "almost 2,500". The two figures are not reconciled. | **[V: Microsoft]** for 2,300. The 2,500 figure is **[U]**, a developer claim. |
| ChaCha20 finding credited to eSentire, January 2025 [V] | Confirmed. eSentire TRU page dated January 23, 2025, says the change was identified January 21, 2025. ESET dates the move of the C&C list to ChaCha20 to January 2025 (the same month) and the dynamic configuration to March 2025. The dates are consistent. | **[V: eSentire; ESET]**. |
| ESET analysed "tens of thousands of samples" [V] | Confirmed: ESET's systems "processed tens of thousands of Lumma Stealer samples". No exact number is given. | **[V: ESET]** |

## 2. Bottom line up front

1. **The highest-value Tier 1 detection point is the delivery step, not the stealer.** The public reporting agrees on a ClickFix chain: a fake CAPTCHA page puts a command on the clipboard, the user opens the Run dialog (Windows key + R), pastes and presses Enter, and the command runs Base64-encoded PowerShell or `mshta` that fetches further code. **[V: CISA AA25-141B; Microsoft 2025-05-21]**. This leaves process-creation and script-block telemetry that the reference environment collects. **[ASSUMED]**
2. **The stealing stage is mostly invisible in the reference environment.** Reads of browser credential stores need Security 4663 with a SACL, which the reference environment does not enable. Sysmon 11 records creation, not reads. **[ASSUMED]** **[A]** Memory-level behaviour (process hollowing, reflective loading) needs telemetry the reference EDR is not assumed to provide. **[ASSUMED]** These are documented gaps, not covered behaviours.
3. **C2 traffic is encrypted HTTPS POST behind Cloudflare.** "All traffic is encrypted by HTTPS", with parameters sent as form data in the POST body. **[V: Microsoft]** Method, destination and User-Agent are visible at a proxy. URI paths and bodies are not, unless TLS is inspected, and the reference environment does not say it is. **[A]** Microsoft gave no User-Agent string for C2 requests. **[V: absent]** ESET lists two User-Agent strings (Chrome/119.0.0.0 and Chrome/109.0.0.0 builds) for dynamic-configuration requests. **[V: ESET]**
4. **Treat the family as active and changing.** The developers said they restored service within days of the May 2025 disruption. **[V: Check Point 2025-05-29]** ESET describes repeated changes to config protection through 2024-2025. **[V: ESET]** Every rule needs scheduled revalidation (`TESTING.md`, step 8).

## 3. MITRE ATT&CK mapping

**Version caveat.** The pinned version is v17 `[ASSUMED]`. AA25-141B uses v17. **[V: CISA]** The MITRE S1213 page, read on 2026-11-22, shows "ATT&CK content v20.1" in its footer, entry "Version : 1.0", created and last modified 22 March 2025. **[V: MITRE]** Technique IDs on a v20.1 page are not proof the same IDs exist in v17. S1213 lists T1685 and T1622 for example, and this analyst did not check those IDs against v17. **[U]** Therefore each row is tagged for both: whether S1213 lists the technique, and whether the v17 advisory does.

| Stage | Technique | Procedure in this module | S1213 (v20.1 page) | AA25-141B (v17) |
|---|---|---|---|---|
| Delivery | **T1204** User Execution (sub-technique **T1204.002** Malicious File is also listed) | ClickFix paste-and-run. S1213 puts the fake-CAPTCHA, Windows Run window and Base64 PowerShell text on the **parent row T1204**. Its T1204.002 row describes malicious executables in zip archives, not ClickFix. | **[V]** T1204 and T1204.002 both listed | **[U]** neither is in the tables. The ClickFix text is in the body. **[V]** |
| Delivery | T1566.001 / T1566.002 Phishing | Email attachment or link | **[V]** | **[V]** both |
| Execution | **T1059.001** PowerShell | Base64 PowerShell from the Run dialog | **[V]** | **[U]** not in tables |
| Execution | **T1218.005** System Binary Proxy Execution: Mshta | `mshta` fetches JavaScript or other code | **[V]** | **[U]** not in tables. Microsoft describes `mshta` in two campaigns. **[V: Microsoft]** |
| Credential access | **T1555.003** Credentials from Web Browsers | Browser credential store reads | **[V]** | **[U]** not in tables. Table lists T1217 Browser Information Discovery **[V]** |
| Credential access | **T1539** Steal Web Session Cookie | Browser cookie reads | **[V]** | **[U]** |
| Command and control | **T1071.001** Web Protocols | HTTPS POST C2 | **[V]** | **[V]** ("to attempt POST requests") |
| Command and control | T1573.002 Asymmetric Cryptography | HTTPS C2 | **[V]** | **[U]** |
| Exfiltration | **T1041** Exfiltration Over C2 Channel | `send_message` in chunks **[V: Microsoft]** | **[V]** | **[U]**. AA25-141B lists the tactic TA0010 only. **[V]** |
| Persistence | T1547.001 Registry Run Keys | HKCU Run key | **[V]** | **[U]** |
| Defense evasion | T1055.012 Process Hollowing | Hollowing into `msbuild.exe`, `regasm.exe`, `regsvcs.exe`, `explorer.exe` **[V: Microsoft]** (S1213 names `BitLockerToGo.exe`) | **[V]** | **[U]** |

**Not covered by any rule in this module:** persistence, process hollowing, anti-analysis, screen capture, document and wallet collection. The reference telemetry does not support them, or they are out of scope. See `ANALYSIS.md` section 4.

## 4. Cited cases (public reporting)

| Case | What was reported | Source |
|---|---|---|
| ClickFix campaign 1, early April 2025 | User clicks "I'm not a robot", a command is copied to the clipboard, the user pastes it into the Run prompt. The command uses `mshta` to fetch further code from a domain named on the page. Microsoft describes the page technique as EtherHiding. | **[V: Microsoft 2025-05-21]** |
| ClickFix campaign 2, April 7, 2025, targeting Canada | Emails contained URLs leading to the Prometheus traffic direction system (TDS) on compromised sites, which redirected to a site hosting ClickFix. An `mshta` command fetches JavaScript from an IP address. The JavaScript runs PowerShell, which downloads more PowerShell, which launches a Lumma executable. Microsoft says Xworm was bundled in it. | **[V: Microsoft 2025-05-21]** |
| Delivery via spoofed software | LummaC2 embedded in fake popular software. S1213 also lists cracked-software downloads and executables in zip or MSI in RAR. | **[V: CISA; MITRE]** |
| Coordinated disruption, May 2025 | Microsoft DCU acted against about 2,300 domains. ESET provided technical analysis and statistics, with Microsoft, BitSight, Lumen, Cloudflare, CleanDNS and GMO Registry. | **[V: Microsoft; ESET]** |
| Resumption | Developer messages claimed "everything has been restored". Check Point notes C2 servers registered in Russia were not disabled and a log-selling Telegram bot listed 95 logs two days after and 406 by May 29. | **[V: Check Point 2025-05-29]**, developer claims relayed second-hand |

## 5. Threat intelligence brief

### 5.1 Typical sequence

1. **Lure.** Phishing email, spoofed or cracked software, or a fake CAPTCHA page. **[V: CISA; Microsoft]**
2. **User-run command.** ClickFix pastes into the Run dialog. The command is Base64 PowerShell, or `mshta` that leads to PowerShell. **[V]**
3. **Loader.** Further PowerShell or JavaScript loads the stealer, which Microsoft says is run "directly in memory", and may hollow `msbuild.exe`, `regasm.exe`, `regsvcs.exe` or `explorer.exe`. **[V: Microsoft]**
4. **Collection.** Chromium and Gecko browser passwords, session cookies and autofill; crypto wallets and extensions (MetaMask, Electrum, Exodus); VPN `.ovpn` files, email and FTP clients, Telegram data; `.pdf`, `.docx`, `.rtf` documents; system metadata. **[V: Microsoft]**
5. **C2.** HTTPS POST with form fields. Commands carried in `act`: `life`, `receive_message` (config), `send_message` (exfiltration in chunks), `get_message` (second config, usually empty). Other fields: `ver` (always 4.0), `lid` or `uid`, `j` or `cid`, `hwid`, `pid`. Fallback C2 from Telegram channels and Steam profiles. Up to six versions identified. All C2 servers sat behind Cloudflare. **[V: Microsoft]**
6. **Follow-on.** Stolen credentials and cookies are sold or used for account takeover. This follow-on is out of scope for detection here. **[A]**

### 5.2 Defender guidance in the sources

CISA gives no signatures or hunting queries; it recommends allowlisting, phishing-resistant MFA, least privilege, logging of registry and access, and testing controls against the listed techniques. **[V: CISA]** Microsoft recommends tamper protection, network protection, EDR in block mode, attack surface reduction rules and MFA, and names Defender detections ("Behavior:Win32/LummaStealer", "Possible Lumma Stealer activity"). **[V: Microsoft]** Microsoft also lists Defender detections and Defender for Endpoint alerts, including "Suspicious command in RunMRU registry" and "Suspicious DPAPI Activity". Its "Hunting queries" section gives two Defender XDR queries: "Identify ClickFix commands execution", which looks at registry value sets made by `explorer.exe` under the `RunMRU` key, and "Identify DPAPI decryption activity originating from AutoIT scripts .NET Framework processes". **[V: Microsoft]** Their logic was read for this check and **was not copied**. Any similar rule in this module is written independently and tagged **[A]**.

## 6. Diamond Model

| Vertex | Content |
|---|---|
| **Adversary** | A malware-as-a-service operator ("developers") and many customer affiliates. Developer messages were relayed from Telegram. **[V: Check Point]** No attribution to named individuals is made here. |
| **Capability** | ClickFix and other lures; Base64 PowerShell and `mshta` loaders; a heavily obfuscated stealer core (LLVM-based obfuscation, control-flow flattening, syscalls, Heaven's Gate); ChaCha20-protected config in recent versions. **[V: Microsoft; eSentire; ESET]** |
| **Infrastructure** | Cloudflare-fronted C2, thousands of domains (ESET reports 3,353 unique C&C domains between June 17, 2024 and May 1, 2025 **[V: ESET]**), Telegram and Steam fallback resolvers, traffic-direction systems for lures. |
| **Victim** | Windows users whose browsers hold credentials, cookies and wallets. Reference-lab scope is Windows 10/11 endpoints only. **[ASSUMED]** |

Meta-features: the commodity model means indicators age fast. Hashes and domains in `iocs.csv` (step 5) are for scoping and retro-hunting, not durable detection. **[A]**

## 7. Open items and limits

- **S1213 IDs against ATT&CK v17.** The IDs in section 3 are confirmed as listed on the S1213 page (footer v20.1) and, for the CISA rows, in AA25-141B (v17). They are not checked against the v17 matrix itself. Rows tagged [U] stay [U] until someone does. **[U]**
- **The 394,000 infected-computer figure.** Not on the Microsoft page that was downloaded. Needs the correct source. **[U]**
- **The eSentire config structure:** only sizes are published (see `ANALYSIS.md` section 3), not offsets. Anything beyond sizes is **[A]**.
- **AA25-141B IOC tables.** Table 6 (15 rows: 9 SHA-256, 3 MD5, 2 SHA-1, 1 TLSH) and Table 7 (two DLL names) are on the page. **[V: CISA]** `iocs.csv` holds only the 9 SHA-256 values, each matched exactly. The advisory's domain list is not copied, because `ENVIRONMENT_ASSUMPTIONS.md` section 6 forbids real hostnames in the repo.
- **Single-byte XOR before ChaCha20.** Not found in any of the seven pages. Stays **[U]**.
- No source in this brief gives a detection rate or false-positive rate for any rule. Metric targets are set only after a baseline (`TESTING.md`, step 8).

## 8. Sources

| Ref | Source | Read |
|---|---|---|
| MITRE | https://attack.mitre.org/software/S1213/ (96,242 bytes) | 2026-11-22 |
| CISA | https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-141b (AA25-141B, May 21, 2025; 99,454 bytes) | 2026-11-22 |
| Microsoft | https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/ (333,362 bytes) | 2026-11-22 |
| eSentire | https://www.esentire.com/blog/lumma-stealer-malware-updated-to-use-chacha20-cipher-for-config-decryption (January 23, 2025; 171,531 bytes) | 2026-11-22 |
| Elastic | https://www.elastic.co/security-labs/nightmare-on-0xelm-street (October 14, 2025; 1,237,844 bytes) | 2026-11-22 |
| ESET | https://www.welivesecurity.com/en/eset-research/eset-takes-part-global-operation-disrupt-lumma-stealer/ (21 May 2025; 150,174 bytes) | 2026-11-22 |
| Check Point | https://blog.checkpoint.com/security/lumma-infostealer-down-but-not-out/ (May 29, 2025; 123,654 bytes) | 2026-11-22 |

Referenced by name only, **not read, not copied**: the abuse.ch YARAhub rule `Lumma_ChaCha20_KeyStub_v2`; the eSentire extraction script on GitHub (its link is on the eSentire page); the CISA STIX files.

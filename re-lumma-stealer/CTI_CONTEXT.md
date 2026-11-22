# CTI Context: LummaC2 (Lumma Stealer) Infostealer

| | |
|---|---|
| **Classification** | TLP:CLEAR (portfolio / lab material) |
| **Date** | 2026-11-22 |
| **Author** | ColdCoffeeSec |
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

**How the V tags were produced.** On 2026-11-22 each of the seven source pages in the first seven rows of section 8 was downloaded as raw HTML with `curl` (HTTP 200; sizes in section 8) and kept outside the repo. A claim is tagged **V** only if its wording (a quote, a number, an ID or a date) was found by exact string search in that page's text, after stripping HTML tags and normalising whitespace, entities and curly quotes. A claim whose wording was not found is tagged **U**. An earlier pass relied on a subagent's summary of the pages. That pass is not trusted, and every V tag was re-checked against the raw text. Quotation marks in this file mean the quoted words were found verbatim. Paraphrases are not in quotation marks. Hunting-query and IOC contents from the sources are **not copied** into the repo. The MITRE technique pages in the last row of section 8 were downloaded and matched the same way for the crosswalk in section 3.1. Page text can still be wrong or change: the tags say what the page said on that date.

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

**Version caveat.** The pinned version is v17 `[ASSUMED]`. AA25-141B uses v17. **[V: CISA]** The MITRE S1213 page, read on 2026-11-22, shows "ATT&CK content v20.1" in its footer, entry "Version : 1.0", created and last modified 22 March 2025. **[V: MITRE]** Technique IDs on a v20.1 page are not proof the same IDs exist in v17, so on 2026-11-22 every ID used in this module was also fetched from its versioned v17 page and from the current page (section 3.1). The result: 15 of the 16 IDs named anywhere in this module exist in v17 under the same name as in v20.1 **[V: MITRE v17]**, including T1622, which this section names as an example from the S1213 page. **T1685**, the other example, which the v20.1 S1213 page lists, is **not found in v17** (HTTP 404 on its versioned URL). It appears only in this paragraph, and in no rule tag, fixture, test or playbook. In the table below, the S1213 column is the v20.1 page and the AA25-141B column is the v17 advisory. The **[U]** cells in the AA25-141B column say that the advisory's tables do not list the technique. This check does not settle that question, because it looked at MITRE pages, not at the advisory.

| Stage | Technique | Procedure in this module | S1213 (v20.1 page) | AA25-141B (v17) |
|---|---|---|---|---|
| Delivery | **T1204** User Execution (sub-technique **T1204.002** Malicious File is also listed) | ClickFix paste-and-run. S1213 puts the fake-CAPTCHA, Windows Run window and Base64 PowerShell text on the **parent row T1204**. Its T1204.002 row describes malicious executables in zip archives, not ClickFix. | **[V]** T1204 and T1204.002 both listed | **[U]** neither is in the tables. The ClickFix text is in the body. **[V]** |
| Delivery | T1566.001 / T1566.002 Phishing: Spearphishing Attachment / Spearphishing Link | Email attachment or link | **[V]** | **[V]** both |
| Execution | **T1059.001** PowerShell | Base64 PowerShell from the Run dialog | **[V]** | **[U]** not in tables |
| Execution | **T1218.005** System Binary Proxy Execution: Mshta | `mshta` fetches JavaScript or other code | **[V]** | **[U]** not in tables. Microsoft describes `mshta` in two campaigns. **[V: Microsoft]** |
| Credential access | **T1555.003** Credentials from Web Browsers | Browser credential store reads | **[V]** | **[U]** not in tables. Table lists T1217 Browser Information Discovery **[V]** |
| Credential access | **T1539** Steal Web Session Cookie | Browser cookie reads | **[V]** | **[U]** |
| Command and control | **T1071.001** Web Protocols | HTTPS POST C2 | **[V]** | **[V]** ("to attempt POST requests") |
| Command and control | T1573.002 Asymmetric Cryptography | HTTPS C2 | **[V]** | **[U]** |
| Exfiltration | **T1041** Exfiltration Over C2 Channel | `send_message` in chunks **[V: Microsoft]** | **[V]** | **[U]**. AA25-141B lists the tactic TA0010 only. **[V]** |
| Persistence | T1547.001 Registry Run Keys / Startup Folder | HKCU Run key | **[V]** | **[U]** |
| Defense evasion | T1055.012 Process Hollowing | Hollowing into `msbuild.exe`, `regasm.exe`, `regsvcs.exe`, `explorer.exe` **[V: Microsoft]** (S1213 names `BitLockerToGo.exe`) | **[V]** | **[U]** |

**Not covered by any rule in this module:** persistence, process hollowing, anti-analysis, screen capture, document and wallet collection. The reference telemetry does not support them, or they are out of scope. See `ANALYSIS.md` section 4.

### 3.1 ATT&CK v17 crosswalk (checked 2026-11-22)

**What this table is.** One row per ATT&CK ID that appears anywhere in this module. It records whether the ID has a page in ATT&CK v17 and in the current version, and the name each page prints. **It checks IDs and names only. It does not check whether each technique really describes Lumma behaviour**; that mapping stays the analyst's reading **[A]** (see the scope note at the top).

**Method.** For each ID, two pages were downloaded with `curl` into a scratch directory outside the repo, with no subagent summary involved: the versioned page (`https://attack.mitre.org/versions/v17/techniques/T1204/002/` for T1204.002) and the current page (the same path without `/versions/v17`). The software pages for S1213 were fetched the same way. All 34 pages were read from their raw HTML by exact string match. A page counts as "found" only if (a) the HTTP status was 200, (b) its title read `<name>, Technique <ID> - Enterprise` or `<name>, Sub-technique <ID> - Enterprise` with the exact ID, and (c) the visible text contained `ID: <ID>` and the printed name. The version of each page is the "ATT&CK content" text in the footer tooltip: `v17.1` for every versioned page that returned 200, `v20.1` for every current page. A page is "revoked or deprecated" if its visible text contains the word stem `revok` or `deprecat`. No page used for this table contains either. To check that this test can fire, the current page of T1064 (not an ID used here, so not in the table) was run through the same code. It prints "Deprecation Warning This technique has been deprecated" and was flagged. Nothing was substituted: where a page was absent, the row says so.

**Used in** (key): CTI = `CTI_CONTEXT.md`; TESTING = `TESTING.md` case tables; IR = `IR_PLAYBOOK.md` header; R001, R002, R003 = the `attack.t...` tag in the Sigma rule of that number; FIX1, FIX2, FIX3 = the `technique` label in `tests/fixtures/logs/rule00N_cases.jsonl`, generated by `tests/fixtures/build_cases.py`.

| ID | Name as printed on the v17 page | In v17 | In current (v20.1) | Used in | Tag |
|---|---|---|---|---|---|
| T1041 | Exfiltration Over C2 Channel | yes | yes, same name | CTI | **[V: MITRE v17]** |
| T1055.012 | Process Injection: Process Hollowing | yes | yes, same name | CTI | **[V: MITRE v17]** |
| T1059.001 | Command and Scripting Interpreter: PowerShell | yes | yes, same name | CTI, TESTING, IR, R001, FIX1 | **[V: MITRE v17]** |
| T1071.001 | Application Layer Protocol: Web Protocols | yes | yes, same name | CTI, TESTING, R003, FIX3 | **[V: MITRE v17]** |
| T1204 | User Execution | yes | yes, same name | CTI, TESTING, IR, R001, FIX1 | **[V: MITRE v17]** |
| T1204.002 | User Execution: Malicious File | yes | yes, same name | CTI | **[V: MITRE v17]** |
| T1217 | Browser Information Discovery | yes | yes, same name | CTI | **[V: MITRE v17]** |
| T1218.005 | System Binary Proxy Execution: Mshta | yes | yes, same name | CTI, TESTING, IR, R001, FIX1 | **[V: MITRE v17]** |
| T1539 | Steal Web Session Cookie | yes | yes, same name | CTI, TESTING, IR, R002, FIX2 | **[V: MITRE v17]** |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | yes | yes, same name | CTI | **[V: MITRE v17]** |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | yes | yes, same name | CTI, TESTING, IR, R002, FIX2 | **[V: MITRE v17]** |
| T1566.001 | Phishing: Spearphishing Attachment | yes | yes, same name | CTI | **[V: MITRE v17]** |
| T1566.002 | Phishing: Spearphishing Link | yes | yes, same name | CTI | **[V: MITRE v17]** |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | yes | yes, same name | CTI | **[V: MITRE v17]** |
| T1622 | Debugger Evasion | yes | yes, same name | CTI (section 3 caveat only) | **[V: MITRE v17]** |
| T1685 | not found in v17 | **no** (HTTP 404; the 404 page does not contain the ID) | yes, printed name "Disable or Modify Tools" | CTI (section 3 caveat only) | **[U]**: an absence is not an exact-string find. The versioned URL returned 404 on 2026-11-22 and the v17 S1213 page does not link it. One 404 does not show what any other release contained. |

Result: no ID in the table is marked revoked or deprecated in v17 or in v20.1, and no name differs between the two versions. Every ID used in a rule tag, a fixture label, a test table or the playbook (T1059.001, T1071.001, T1204, T1218.005, T1539, T1555.003) exists in v17. The only ID missing from v17 is T1685, and nothing but this file's caveat mentions it.

**S1213 in v17.** The versioned S1213 page also exists (HTTP 200, footer `v17.1`, "Version : 1.0", created and last modified 22 March 2025, the same dates as the v20.1 page). It links 15 of the 16 IDs, all but T1685. The v20.1 page links all 16. These listings were read from link targets such as `/versions/v17/techniques/T1059/001`, because S1213 prints a sub-technique as a parent-ID cell plus a `.001` cell, so the full string `T1059.001` is not in its text. **Observation, not a mapping:** the v17 S1213 page links T1562 and T1562.001, and the v20.1 page does not link either but links T1685. The v20.1 page for T1685 does not mention T1562. No relationship between the two is claimed or used.

**Agreement with the S1213 column.** The v20.1 S1213 page, fetched again on 2026-11-22, links all 16 IDs, which agrees with the **[V]** cells in the S1213 column of the section 3 table. Only the listing was compared, not the procedure text in each row.

**Not settled by this table:** whether the techniques describe Lumma behaviour, and whether AA25-141B lists each ID (the **[U]** cells in the AA25-141B column). The downloaded pages are copies of what MITRE served on 2026-11-22. They are not committed.

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

- **ATT&CK IDs against v17: done for existence and names, on 2026-11-22.** Section 3.1 shows that 15 of the 16 IDs named in this module exist in v17 with the same names as in v20.1. **T1685 is not found in v17** and is named only in the section 3 caveat. **[V: MITRE v17]** for the 15, **[U]** for the absence of T1685 (a 404 is not an exact-string find). Still open and still **[U]**: whether each technique describes Lumma behaviour (analyst mapping **[A]**), and whether AA25-141B lists the IDs its column marks **[U]**.
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
| MITRE ATT&CK technique pages | 32 pages, v17 and current for each of the 16 IDs in section 3.1, at `https://attack.mitre.org/versions/v17/techniques/<ID>/` and `https://attack.mitre.org/techniques/<ID>/` (HTTP 200 for all but the v17 page of T1685, which was 404). Software page S1213 in both versions: `https://attack.mitre.org/versions/v17/software/S1213/` (89,254 bytes, footer v17.1). | 2026-11-22 |

Referenced by name only, **not read, not copied**: the abuse.ch YARAhub rule `Lumma_ChaCha20_KeyStub_v2`; the eSentire extraction script on GitHub (its link is on the eSentire page); the CISA STIX files.

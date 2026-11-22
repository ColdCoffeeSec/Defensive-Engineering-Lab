/*
 * re_lumma_chacha_setup.yar
 *
 * LOW-CONFIDENCE, ANALYST-DERIVED [A] RULE. LIKELY BLIND AND LIKELY FP-PRONE.
 *
 * Idea: Elastic Security Labs (2025-10-14) reports that, in the version it
 * analysed, Lumma sets up its ChaCha20 context after loading WinHTTP.dll and
 * reuses the context for every decryption call [V: Elastic]. This rule looks
 * for the co-occurrence of three public strings:
 *   - the standard ChaCha20 constant "expand 32-byte k" (RFC 8439, public),
 *   - the library name "winhttp.dll",
 *   - the import name "WinHttpOpen".
 * Nothing here comes from a sample or from any public YARA rule. This repository
 * handles no samples (ENVIRONMENT_ASSUMPTIONS.md section 3), so no byte pattern
 * from our own analysis exists. We do not invent opcode bytes.
 *
 * Why this is weak [A]:
 *   - Elastic also reports that the ChaCha20 constant is decrypted at runtime with
 *     small routines and an XOR-ROL step [V: Elastic]. The plain constant may
 *     therefore be absent from the family this rule names (a false negative).
 *   - Any program that links a ChaCha20 library and uses WinHTTP matches (a false
 *     positive): HTTP clients, updaters, VPN clients and many Go or Rust programs.
 *   - A Windows-API import name in plain form says nothing about malice.
 *
 * Use it, if at all, as a hunting filter over a corpus, never as an alert, and
 * never as evidence that a file is Lumma. It does not use the pe module.
 * Only run against synthetic byte strings in this repo.
 */

rule RE_Lumma_ChaCha_WinHttp_Cooccurrence
{
    meta:
        description = "ChaCha20 constant with WinHTTP strings, a weak hunting hint for Lumma-style context setup (low confidence)"
        author = "ColdCoffeeSec"
        date = "2026-11-22"
        status = "experimental"
        basis = "analyst-derived; idea from Elastic Security Labs 2025-10-14"
        confidence = "low"
        reference = "https://www.elastic.co/security-labs/nightmare-on-0xelm-street"

    strings:
        $chacha_const = "expand 32-byte k" ascii
        $winhttp_dll  = "winhttp.dll" ascii wide nocase
        $winhttp_open = "WinHttpOpen" ascii

    condition:
        filesize < 5MB and all of them
}

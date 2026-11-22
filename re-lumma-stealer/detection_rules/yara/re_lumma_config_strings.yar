/*
 * re_lumma_config_strings.yar
 *
 * LOW-CONFIDENCE, ANALYST-DERIVED [A] RULE.
 *
 * Basis: the C2 protocol strings that Microsoft's 2025-05-21 write-up lists for
 * LummaC2: the command names carried in the "act" form field (receive_message,
 * send_message, get_message), the constant version value (ver=4.0) and the
 * identifier fields (hwid, lid or uid) [V: Microsoft 2025-05-21].
 * These strings were NOT taken from any public YARA rule and NOT from a sample.
 * This repository handles no samples (ENVIRONMENT_ASSUMPTIONS.md section 3), so
 * nothing here comes from our own reverse engineering.
 *
 * What is NOT known [U]:
 *   - whether any real build holds these strings in plain form. Microsoft
 *     describes heavy obfuscation and custom stack-based string decryption, so
 *     real samples may not contain them at rest.
 *   - which versions use which fields (lid was used up to version 5, uid in 6).
 *
 * The rule has only been run on synthetic byte strings made from its own
 * indicators. A pass on those shows the logic works. It is not a detection rate.
 *
 * Limits: matches HTTP client code, test harnesses and write-ups that quote the
 * same strings. It does not use the pe module.
 */

rule RE_Lumma_C2_Protocol_Strings
{
    meta:
        description = "Plain-text Lumma C2 protocol strings from public reporting (low confidence)"
        author = "ColdCoffeeSec"
        date = "2026-11-22"
        status = "experimental"
        basis = "analyst-derived; strings reported by Microsoft 2025-05-21"
        confidence = "low"
        reference = "https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/"

    strings:
        $cmd_recv = "receive_message" ascii wide
        $cmd_send = "send_message" ascii wide
        $cmd_get  = "get_message" ascii wide
        $ver40    = "ver=4.0" ascii wide
        $p_hwid   = "hwid=" ascii wide
        $p_lid    = "lid=" ascii wide
        $p_uid    = "uid=" ascii wide

    condition:
        filesize < 10MB and
        4 of ($cmd_*, $ver40) and
        1 of ($p_*)
}

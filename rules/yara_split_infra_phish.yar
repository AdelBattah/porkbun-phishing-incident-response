/*
  YARA Rule: Email_Phish_Porkbun_SaaS_Relay_Abuse
  Author: Adel Battah
  Description: Detects multi-stage phishing lures impersonating domain registrar Porkbun
               leveraging SaaS transactional relays (Zoho Books), direct VPS injection (paomusic.info),
               and typosquatted / hijacked payload infrastructure (ecuiliber.com, birdwatching.dk).
  Date: 2026-11-15
  Updated: 2026-11-18 (Wave 3 Subdomain Hijacking Expansion)
  Reference: IR-2026-1115-001
  MITRE ATT&CK: T1566.002, T1036.005, T1583.006, T1584.001
*/

rule Email_Phish_Porkbun_SaaS_Relay_Abuse {
    meta:
        author = "Adel Battah"
        description = "Detects Porkbun credential phishing utilizing SaaS transactional relays and typosquatted / hijacked payload subdomains"
        date = "2026-11-15"
        last_modified = "2026-11-18"
        reference = "IR-2026-1115-001"
        tlp = "CLEAR"
        severity = "HIGH"

    strings:
        // Porkbun brand lures
        $brand_1 = "Porkbun" ascii nocase
        $brand_2 = "porkbun.com" ascii nocase
        $brand_3 = "Keep your services running smoothly" ascii nocase

        // Credential harvesting / urgent billing lures
        $lure_1 = "payment method" ascii nocase
        $lure_2 = "billing attempt" ascii nocase
        $lure_3 = "unable to be processed" ascii nocase
        $lure_4 = "review your payment" ascii nocase

        // Infrastructure abuse artifacts (Wave 1 SaaS relay & Wave 2/3 VPS)
        $saas_relay_1 = "sender.zohobooks.com" ascii nocase
        $saas_relay_2 = "transmail.net" ascii nocase
        $saas_relay_3 = "zohosecurepay.com" ascii nocase
        $saas_relay_4 = "organization_id=944707351" ascii nocase
        $vps_sender_1 = "paomusic.info" ascii nocase

        // Campaign-specific payload patterns & adversary pivots
        // Wave 1 & 2: Disposable throwaway domain (ecuiliber.com) with typosquatted prefix
        $payload_domain_1 = "ecuiliber.com" ascii nocase
        $typosquat_pattern_1 = /ww[a-z]{5,15}\.ecuiliber\.com/ ascii nocase

        // Wave 3: Subdomain hijacking on legitimate domain (birdwatching.dk)
        $payload_domain_2 = "birdwatching.dk" ascii nocase
        $typosquat_pattern_2 = /ww+acco*untv?\.[a-z0-9\.-]+/ ascii nocase

    condition:
        // Case 1: Direct match on known campaign infrastructure / hijacked host
        ($payload_domain_1 or $typosquat_pattern_1 or $payload_domain_2 or $typosquat_pattern_2)
        or
        // Case 2: SaaS relay or VPS impersonating Porkbun with billing lure
        (
            (any of ($saas_relay_*) or $vps_sender_1) and
            any of ($brand_*) and
            2 of ($lure_*)
        )
}

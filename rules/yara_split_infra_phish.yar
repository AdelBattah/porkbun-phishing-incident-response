/*
  YARA Rule: Email_Phish_Porkbun_SaaS_Relay_Abuse
  Author: Adel Battah
  Description: Detects multi-stage phishing lures impersonating domain registrar Porkbun
               leveraging SaaS transactional relays (Zoho Books) and typosquatted payload infrastructure.
  Date: 2026-11-15
  Reference: IR-2026-1115-001
  MITRE ATT&CK: T1566.002, T1036.005, T1583.006
*/

rule Email_Phish_Porkbun_SaaS_Relay_Abuse {
    meta:
        author = "Adel Battah"
        description = "Detects Porkbun credential phishing utilizing SaaS transactional relays and typosquatted payload subdomains"
        date = "2026-11-15"
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

        // Infrastructure abuse artifacts
        $saas_relay_1 = "sender.zohobooks.com" ascii nocase
        $saas_relay_2 = "transmail.net" ascii nocase
        $saas_relay_3 = "zohosecurepay.com" ascii nocase
        $saas_relay_4 = "organization_id=944707351" ascii nocase

        // Campaign-specific payload patterns
        $payload_domain = "ecuiliber.com" ascii nocase
        $typosquat_pattern = /ww[a-z]{5,15}\.ecuiliber\.com/ ascii nocase

    condition:
        // Case 1: Direct match on known campaign infrastructure
        ($payload_domain or $typosquat_pattern)
        or
        // Case 2: SaaS relay impersonating Porkbun with billing lure
        (
            any of ($saas_relay_*) and
            any of ($brand_*) and
            2 of ($lure_*)
        )
}

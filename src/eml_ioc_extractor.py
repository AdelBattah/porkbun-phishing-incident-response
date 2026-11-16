#!/usr/bin/env python3
"""
eml_ioc_extractor.py - Advanced SOC Phishing Forensics & Threat Intel Engine
Author: Adel Battah (https://github.com/AdelBattah)

Features:
  - DKIM d= alignment & Sender Rewriting Scheme (SRS) envelope unwrapping
  - Multi-part ccTLD-aware apex domain extraction (.co.uk, .com.au, etc.)
  - Sender & URL High-Abuse TLD scoring (.info, .top, .xyz, etc.)
  - Recursive SafeLinks / redirect URL unwrapping & Shannon entropy calculation
  - Punycode (IDN) homograph & Levenshtein edit-distance typosquatting detection
  - Hidden HTML/CSS anti-Bayesian evasion detection (display:none, font-size:0)
  - MIME attachment SHA-256 hashing & risky extension profiling
  - Optional active enrichment (--enrich): DNS resolution, reverse-DNS (PTR),
    split-infrastructure detection (subdomain IP vs. apex IP), and X.509 TLS certificate age
  - Automated recipient PII sanitization (--sanitize) for safe SOC/OSINT sharing
  - MITRE ATT&CK technique mapping & dual raw/defanged structured JSON output
  - Automation exit codes (0 = clean, 1 = suspicious, 2 = confirmed phishing) for CI/CD

Zero external dependencies (Python 3.9+ Standard Library only).
"""

import argparse
from datetime import datetime, timezone
import email
from email import policy
from email.utils import parseaddr
import hashlib
import html
import ipaddress
import json
import math
from pathlib import Path
import re
import socket
import ssl
import sys
from urllib.parse import parse_qs, unquote, urlparse

PROTECTED_BRANDS = {
    "porkbun": ["porkbun.com"],
    "namecheap": ["namecheap.com"],
    "godaddy": ["godaddy.com"],
    "cloudflare": ["cloudflare.com"],
    "paypal": ["paypal.com"],
    "stripe": ["stripe.com"],
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com"],
    "amazon": ["amazon.com", "amazonaws.com"],
    "aws": ["amazon.com", "amazonaws.com"],
    "github": ["github.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "dropbox": ["dropbox.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "usps": ["usps.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
}

ABUSED_SAAS_RELAYS = (
    "sender.zohobooks.com",
    "zohomail.com",
    "sendgrid.net",
    "mailgun.org",
    "mandrillapp.com",
    "intuit.com",
    "amazonses.com",
    "sparkpostmail.com",
)

HIGH_ABUSE_TLDS = (
    ".info", ".top", ".xyz", ".click", ".icu", ".shop",
    ".online", ".site", ".live", ".work", ".support", ".cc", ".tk",
)

MULTI_PART_TLDS = (
    ".co.uk", ".com.au", ".org.uk", ".gov.uk", ".co.jp",
    ".com.br", ".com.mx", ".co.nz", ".co.za", ".edu.au",
    ".net.au", ".ac.uk", ".gov.au", ".com.sg", ".co.in",
)

URL_SHORTENERS = (
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
)

DANGEROUS_EXTENSIONS = (
    ".html", ".htm", ".svg", ".iso", ".img", ".lnk",
    ".one", ".vbs", ".js", ".wsf", ".hta", ".exe", ".scr",
)

LURE_KEYWORDS = (
    "unable to be processed", "billing attempt", "review payment method",
    "update your billing", "payment declined", "account suspended",
    "account will be closed", "verify your account", "confirm your identity",
    "unusual sign-in", "security alert", "password expired",
    "immediate action required", "invoice attached", "wire transfer",
)


def defang(value: str) -> str:
    """Defangs URLs and IP addresses for safe display and SOC handling."""
    value = re.sub(r"^https://", "hxxps://", value, flags=re.IGNORECASE)
    value = re.sub(r"^http://", "hxxp://", value, flags=re.IGNORECASE)
    return value.replace(".", "[.]")


def shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy to detect DGA subdomains and random tokens."""
    if not data:
        return 0.0
    freq = {c: data.count(c) / len(data) for c in set(data)}
    return -sum(p * math.log2(p) for p in freq.values())


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein edit-distance between two strings without external libraries."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if not s2:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


def unwrap_srs_address(addr: str) -> str:
    """Unwraps Sender Rewriting Scheme (SRS0=hash=TT=domain=user@forwarder) addresses."""
    _, clean_email = parseaddr(addr or "")
    match = re.match(r"^SRS[01]=[^=]+=[^=]+=([^=]+)=([^@]+)@", clean_email, re.IGNORECASE)
    if match:
        orig_domain, orig_user = match.groups()
        return f"{orig_user}@{orig_domain}"
    return clean_email


def unwrap_redirect_url(url: str, max_depth: int = 3) -> str:
    """Recursively unwraps SafeLinks, Proofpoint, and common redirect query parameters."""
    current = url
    redirect_keys = ("url", "u", "dest", "destination", "redirect", "target", "r")
    for _ in range(max_depth):
        parsed = urlparse(current)
        qs = parse_qs(parsed.query)
        next_url = None
        for key in redirect_keys:
            if key in qs and qs[key]:
                candidate = unquote(qs[key][0]).strip()
                if candidate.startswith(("http://", "https://")):
                    next_url = candidate
                    break
        if not next_url or next_url == current:
            break
        current = next_url
    return current


def get_domain(addr_header: str) -> str:
    """Extracts lowercase domain name from an email address header."""
    _, email_addr = parseaddr(addr_header or "")
    if "@" in email_addr:
        return email_addr.split("@", 1)[1].lower().strip()
    return ""


def get_registered_domain(domain: str) -> str:
    """
    Extracts the registered apex domain, correctly handling multi-part
    ccTLDs like .co.uk, .com.au, and .org.uk.
    """
    domain_clean = domain.lower().strip(".")
    for multi in MULTI_PART_TLDS:
        if domain_clean.endswith(multi):
            prefix = domain_clean[:-len(multi)]
            apex_label = prefix.split(".")[-1] if "." in prefix else prefix
            return f"{apex_label}{multi}"
    parts = [p for p in domain_clean.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain_clean


def domain_matches(domain: str, allowed_list: list) -> bool:
    """Checks if a domain exactly matches or is a subdomain of an allowed domain list."""
    return any(
        domain == allowed or domain.endswith("." + allowed)
        for allowed in allowed_list
    )


def detect_html_obfuscation(raw_bodies: list) -> list:
    """Detects anti-Bayesian hidden text (display:none, font-size:0) and data: URIs."""
    findings = []
    for body in raw_bodies:
        if re.search(r'style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|font-size\s*:\s*0(?:px|pt)?)', body, re.IGNORECASE):
            findings.append("Hidden CSS text (display:none / font-size:0) used to evade content filters")
        if re.search(r'href\s*=\s*["\']data:text/html', body, re.IGNORECASE):
            findings.append("Embedded data:text/html URI payload (HTML smuggling technique)")
    return sorted(set(findings))


def strip_html_and_css(raw_html: str) -> str:
    """Strips markup, scripts, and CSS to reveal plain rendered text."""
    cleaned = re.sub(r"<style[^>]*>.*?</style>", " ", raw_html, flags=re.IGNORECASE | re.DOTALL)
    cleaned = re.sub(r"<script[^>]*>.*?</script>", " ", cleaned, flags=re.IGNORECASE | re.DOTALL)
    cleaned = re.sub(r'\sstyle\s*=\s*["\'].*?["\']', " ", cleaned, flags=re.IGNORECASE | re.DOTALL)
    cleaned = re.sub(r"<[^>]+>", " ", cleaned)
    cleaned = html.unescape(cleaned)
    return re.sub(r"\s+", " ", cleaned).strip()


def extract_mime_artifacts(msg: email.message.EmailMessage) -> tuple:
    """Extracts raw bodies, visible text, and attachment metadata with SHA-256 hashes."""
    raw_bodies = []
    visible_chunks = []
    attachments = []
    parts = msg.walk() if msg.is_multipart() else [msg]

    for part in parts:
        ctype = part.get_content_type()
        filename = part.get_filename()
        if filename:
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": filename,
                "content_type": ctype,
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
            continue

        if ctype in ("text/plain", "text/html"):
            try:
                content = part.get_content()
            except Exception:
                payload = part.get_payload(decode=True)
                content = payload.decode("utf-8", errors="replace") if payload else ""
            if content:
                raw_bodies.append(content)
                visible_chunks.append(strip_html_and_css(content) if ctype == "text/html" else content)

    return raw_bodies, "\n".join(visible_chunks), attachments


def extract_dkim_domains(dkim_headers: list) -> list:
    """Extracts d= signing domains from all DKIM-Signature headers."""
    domains = set()
    for hdr in dkim_headers:
        match = re.search(r"\bd=([a-zA-Z0-9.-]+)", hdr)
        if match:
            domains.add(match.group(1).lower().strip("."))
    return sorted(domains)


def extract_anchor_mismatches(raw_bodies: list) -> list:
    """Identifies deceptive hyperlinks where visible link text differs from actual target host."""
    mismatches = []
    anchor_pattern = re.compile(
        r'<a\b[^>]*href=["\'](https?://[^"\']+)["\'][^>]*>(.*?)</a>',
        flags=re.IGNORECASE | re.DOTALL,
    )
    for body in raw_bodies:
        for href, inner_html in anchor_pattern.findall(body):
            unwrapped_href = unwrap_redirect_url(href)
            visible_text = strip_html_and_css(inner_html).strip()
            href_host = urlparse(unwrapped_href).netloc.lower().split(":")[0]
            if not href_host:
                continue
            url_in_text = re.search(r"(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", visible_text)
            if url_in_text:
                shown_host = url_in_text.group(1).lower()
                if get_registered_domain(shown_host) != get_registered_domain(href_host):
                    mismatches.append(f"Displays '{defang(shown_host)}' -> Links to '{defang(href_host)}'")
    return sorted(set(mismatches))


def extract_valid_public_ips(corpus: str) -> list:
    """Extracts all RFC-compliant public IPv4 addresses from email corpus."""
    candidates = re.findall(r"(?<![.\d])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![.\d])", corpus)
    valid_public = set()
    for cand in candidates:
        try:
            ip_obj = ipaddress.ip_address(cand)
            if ip_obj.version == 4 and ip_obj.is_global:
                valid_public.add(str(ip_obj))
        except ValueError:
            continue
    return sorted(valid_public)


def active_enrich_host(host: str) -> dict:
    """
    Performs active DNS resolution, PTR reverse-DNS lookups, split-infrastructure
    detection (subdomain IP vs. apex IP), and X.509 TLS certificate age calculation.
    Includes fallback handling for untrusted/self-signed certificates.
    """
    info = {
        "host": defang(host),
        "host_raw": host,
        "ips": [],
        "ptr_records": [],
        "apex_ips": [],
        "split_infra": False,
        "tls_age_hours": None,
        "tls_issuer": None,
        "tls_cert_valid": True,
    }

    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        info["ips"] = sorted({item[4][0] for item in infos})
        for ip in info["ips"]:
            try:
                ptr_host, _, _ = socket.gethostbyaddr(ip)
                info["ptr_records"].append(f"{ip} -> {defang(ptr_host)}")
            except Exception:
                pass
    except Exception:
        return info

    apex = get_registered_domain(host)
    if apex != host:
        try:
            apex_infos = socket.getaddrinfo(apex, 443, proto=socket.IPPROTO_TCP)
            info["apex_ips"] = sorted({item[4][0] for item in apex_infos})
            if info["ips"] and info["apex_ips"] and not set(info["ips"]).intersection(info["apex_ips"]):
                info["split_infra"] = True
        except Exception:
            pass

    # Inspect TLS Certificate (First try default verified, then unverified fallback)
    cert = None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except ssl.SSLCertVerificationError:
        info["tls_cert_valid"] = False
        info["tls_issuer"] = "Untrusted / Self-Signed"
    except Exception:
        pass

    if cert and "notBefore" in cert:
        try:
            not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            age_hours = (datetime.now(timezone.utc) - not_before).total_seconds() / 3600.0
            info["tls_age_hours"] = round(age_hours, 1)
            issuer_dict = dict(x[0] for x in cert.get("issuer", []))
            info["tls_issuer"] = issuer_dict.get("organizationName", "Unknown")
        except Exception:
            pass

    return info


def evaluate_phishing_landmarks(
    headers: dict,
    raw_bodies: list,
    visible_text: str,
    urls: list,
    attachments: list,
    enrichments: list,
) -> dict:
    """Heuristic SOC rule engine evaluating email landmarks and mapping MITRE ATT&CK techniques."""
    score = 0
    landmarks = []
    mitre_techniques = set()

    from_raw = headers["from"]
    display_name, _ = parseaddr(from_raw)
    from_dom = get_domain(from_raw)
    reply_dom = get_domain(headers["reply_to"])
    unwrapped_rp = unwrap_srs_address(headers["return_path"])
    rp_dom = get_domain(unwrapped_rp)

    subject_lower = (headers["subject"] or "").lower()
    combined_visible = f"{subject_lower}\n{visible_text.lower()}"

    # 1. Perimeter Auth Failures
    auth_blob = " ".join(headers["authentication_results"]).lower()
    auth_fails = [p.upper() for p in ("spf", "dkim", "dmarc") if f"{p}=fail" in auth_blob or f"{p}=softfail" in auth_blob]
    if auth_fails:
        score += 35
        mitre_techniques.add("T1566.002 - Spearphishing Link")
        landmarks.append(f"[+35] Perimeter Auth Failure: {', '.join(auth_fails)} failed")

    # 2. DKIM Signing Domain Alignment Mismatch
    dkim_doms = extract_dkim_domains(headers["dkim_signatures"])
    if from_dom and dkim_doms and not any(get_registered_domain(d) == get_registered_domain(from_dom) for d in dkim_doms):
        score += 15
        landmarks.append(f"[+15] DKIM Alignment Mismatch: From '{defang(from_dom)}' signed by {[defang(d) for d in dkim_doms]}")

    # 3. Sender Domain High-Abuse TLD Check
    sender_domains_to_check = {d for d in (from_dom, reply_dom, rp_dom) if d}
    for sdom in sorted(sender_domains_to_check):
        if any(sdom.endswith(tld) for tld in HIGH_ABUSE_TLDS):
            score += 15
            mitre_techniques.add("T1583.001 - Acquire Infrastructure: Domains")
            landmarks.append(f"[+15] High-Abuse Sender TLD: '{defang(sdom)}'")
            break

    # 4. Reply-To / Return-Path Mismatch
    if reply_dom and from_dom and get_registered_domain(reply_dom) != get_registered_domain(from_dom):
        score += 25
        mitre_techniques.add("T1114 - Email Collection")
        landmarks.append(f"[+25] Reply-To Mismatch: From '{defang(from_dom)}' vs Reply-To '{defang(reply_dom)}'")
    if rp_dom and from_dom and get_registered_domain(rp_dom) != get_registered_domain(from_dom):
        score += 15
        landmarks.append(f"[+15] Return-Path Mismatch (SRS-Unwrapped): Envelope '{defang(rp_dom)}' vs From '{defang(from_dom)}'")

    # 5. Abused SaaS Relay Origin
    if any(from_dom == s or from_dom.endswith("." + s) for s in ABUSED_SAAS_RELAYS):
        score += 20
        mitre_techniques.add("T1583.006 - Acquire Infrastructure: Web Services")
        landmarks.append(f"[+20] Abused SaaS Relay Origin: Sent via '{defang(from_dom)}'")

    # 6. Brand Impersonation & Off-Brand Links
    for brand, official_domains in PROTECTED_BRANDS.items():
        brand_regex = rf"\b{re.escape(brand)}\b"
        if re.search(brand_regex, combined_visible) or re.search(brand_regex, display_name.lower()):
            if from_dom and not domain_matches(from_dom, official_domains):
                score += 35
                mitre_techniques.add("T1036.005 - Masquerading: Match Legitimate Name or Location")
                landmarks.append(f"[+35] Brand Impersonation: Mentions '{brand.title()}' from '{defang(from_dom)}'")

            rogue_hosts = {
                urlparse(u).netloc.lower().split(":")[0]
                for u in urls
                if urlparse(u).netloc and not domain_matches(urlparse(u).netloc.lower().split(":")[0], official_domains)
                and "zohosecurepay.com" not in urlparse(u).netloc.lower()
            }
            if rogue_hosts:
                score += 40
                mitre_techniques.add("T1566.002 - Spearphishing Link")
                landmarks.append(f"[+40] Off-Brand Payload Link: Mentions '{brand.title()}' -> [{', '.join(defang(h) for h in sorted(rogue_hosts))}]")

    # 7. Anchor Mismatch & HTML Obfuscation
    for mm in extract_anchor_mismatches(raw_bodies):
        score += 35
        mitre_techniques.add("T1036 - Masquerading")
        landmarks.append(f"[+35] Deceptive Hyperlink Text: {mm}")

    for obf in detect_html_obfuscation(raw_bodies):
        score += 25
        mitre_techniques.add("T1027 - Obfuscated Files or Information")
        landmarks.append(f"[+25] HTML/CSS Obfuscation: {obf}")

    # 8. Advanced URL & Domain Heuristics (Punycode, Levenshtein, Entropy, Shorteners)
    for u in urls:
        host = urlparse(u).netloc.lower().split(":")[0]
        if not host:
            continue
        try:
            ipaddress.ip_address(host)
            score += 35
            landmarks.append(f"[+35] Raw IPv4 URL: [{defang(host)}]")
            continue
        except ValueError:
            pass

        if "xn--" in host:
            score += 35
            mitre_techniques.add("T1036.005 - IDN Homograph Spoofing")
            landmarks.append(f"[+35] Punycode / IDN Homograph Domain: '{defang(host)}'")

        if any(host == sh or host.endswith("." + sh) for sh in URL_SHORTENERS):
            score += 20
            landmarks.append(f"[+20] URL Shortener Obfuscation: [{defang(host)}]")

        if any(host.endswith(tld) for tld in HIGH_ABUSE_TLDS):
            score += 15
            landmarks.append(f"[+15] High-Abuse TLD: '{defang(host)}'")

        host_no_www = host.removeprefix("www.")
        primary_label = host_no_www.split(".")[0]
        if re.search(r"([a-z])\1{2,}", primary_label) or "accoount" in host:
            score += 25
            landmarks.append(f"[+25] Repeated-Character Typosquatting: '{defang(host)}'")

        reg_label = get_registered_domain(host).split(".")[0]
        for brand in PROTECTED_BRANDS:
            if len(brand) >= 5 and reg_label != brand and levenshtein_distance(reg_label, brand) <= 2:
                score += 30
                landmarks.append(f"[+30] Lookalike Domain (Edit Distance <=2 from '{brand}'): '{defang(host)}'")

        if shannon_entropy(primary_label) >= 3.8 and len(primary_label) >= 12:
            score += 15
            landmarks.append(f"[+15] High-Entropy Subdomain (DGA/Tracking Token): '{defang(host)}'")

    # 9. High-Risk Attachments
    for att in attachments:
        if any(att["filename"].lower().endswith(ext) for ext in DANGEROUS_EXTENSIONS):
            score += 35
            mitre_techniques.add("T1566.001 - Spearphishing Attachment")
            landmarks.append(f"[+35] High-Risk Attachment: '{att['filename']}' (SHA256: {att['sha256'][:16]}...)")

    # 10. Active Infrastructure Enrichment Signals
    for enr in enrichments:
        if enr.get("split_infra"):
            score += 30
            mitre_techniques.add("T1583.001 - Acquire Infrastructure: Domains")
            landmarks.append(f"[+30] Split-Infrastructure Hosting: Subdomain {enr['host']} ({enr['ips']}) diverges from Apex ({enr['apex_ips']})")
        if not enr.get("tls_cert_valid", True):
            score += 25
            mitre_techniques.add("T1588.004 - Obtain Capabilities: Digital Certificates")
            landmarks.append(f"[+25] Untrusted / Invalid TLS Certificate on {enr['host']}")
        elif enr.get("tls_age_hours") is not None and enr["tls_age_hours"] <= 72:
            score += 30
            mitre_techniques.add("T1588.004 - Obtain Capabilities: Digital Certificates")
            landmarks.append(f"[+30] Newly Provisioned TLS Certificate ({enr['tls_age_hours']}h old via {enr['tls_issuer']}) on {enr['host']}")

    # 11. Social Engineering Lures
    matched_lures = [kw for kw in LURE_KEYWORDS if kw in combined_visible]
    if matched_lures:
        score += 15
        landmarks.append(f"[+15] Urgency / Credential Lure: {', '.join(matched_lures[:3])}")

    verdict = (
        "CRITICAL / CONFIRMED PHISHING" if score >= 60
        else "HIGH RISK / SUSPICIOUS" if score >= 30
        else "LOW RISK / LIKELY LEGITIMATE"
    )

    return {
        "verdict": verdict,
        "risk_score": score,
        "mitre_attack": sorted(mitre_techniques),
        "triggered_landmarks": landmarks,
    }


def sanitize_report_pii(report: dict) -> dict:
    """Masks recipient email addresses in headers and IOCs for public artifact release."""
    sanitized = json.loads(json.dumps(report))
    target_emails = set()
    for hdr_key in ("to", "reply_to", "return_path"):
        val = sanitized["headers"].get(hdr_key, "")
        _, email_addr = parseaddr(val)
        if email_addr and not any(email_addr.endswith(dom) for dom in ("paomusic.info", "ecuiliber.com", "transmail.net")):
            target_emails.add(email_addr.lower())

    for target in target_emails:
        if target:
            # Replace in headers
            for k in sanitized["headers"]:
                if isinstance(sanitized["headers"][k], str) and target in sanitized["headers"][k].lower():
                    sanitized["headers"][k] = re.sub(re.escape(target), "analyst-trap@victim-domain.internal", sanitized["headers"][k], flags=re.IGNORECASE)
            # Replace in IOC email lists
            sanitized["iocs"]["email_addresses"] = [
                "analyst-trap@victim-domain.internal" if e.lower() == target else e
                for e in sanitized["iocs"]["email_addresses"]
            ]

    # Deduplicate emails after sanitization
    sanitized["iocs"]["email_addresses"] = sorted(set(sanitized["iocs"]["email_addresses"]))
    return sanitized


def analyze_eml(file_path: Path, do_enrich: bool = False, do_sanitize: bool = False) -> dict:
    """Parses .eml file, extracts artifacts, evaluates heuristics, and generates forensic telemetry."""
    msg = email.message_from_bytes(file_path.read_bytes(), policy=policy.default)
    headers = {
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "from": msg.get("From", ""),
        "reply_to": msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", ""),
        "return_path_unwrapped": unwrap_srs_address(msg.get("Return-Path", "")),
        "to": msg.get("To", ""),
        "message_id": msg.get("Message-ID", ""),
        "zoho_account_id": msg.get("X-Zoho-CM-AccountID", ""),
        "authentication_results": msg.get_all("Authentication-Results", []),
        "dkim_signatures": msg.get_all("DKIM-Signature", []),
        "received_hops": msg.get_all("Received", []),
    }

    raw_bodies, visible_text, attachments = extract_mime_artifacts(msg)
    full_corpus = "\n".join(
        [str(v) for v in headers.values() if isinstance(v, str)]
        + headers["authentication_results"]
        + headers["received_hops"]
        + raw_bodies
    )

    raw_urls = set(re.findall(r"""https?://[^\s"'<>()]+""", full_corpus))
    unwrapped_urls = {unwrap_redirect_url(u) for u in raw_urls}
    noise_domains = ("schema.org", "w3.org", "microsoft.com")
    filtered_urls = sorted(
        u for u in unwrapped_urls if not any(nd in u.lower() for nd in noise_domains)
    )

    raw_emails = set(re.findall(r"[a-zA-Z0-9.%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", full_corpus))
    saas_org_ids = set(re.findall(r"(?:organization_id|org_id|tenant_id)=([0-9a-zA-Z-]+)", full_corpus))
    public_ips = extract_valid_public_ips(full_corpus)

    enrichments = []
    if do_enrich:
        unique_hosts = sorted({urlparse(u).netloc.lower().split(":")[0] for u in filtered_urls if urlparse(u).netloc})
        for h in unique_hosts[:5]:
            enrichments.append(active_enrich_host(h))

    assessment = evaluate_phishing_landmarks(
        headers, raw_bodies, visible_text, filtered_urls, attachments, enrichments
    )

    report = {
        "file": file_path.name,
        "assessment": assessment,
        "headers": headers,
        "iocs": {
            "urls_defanged": [defang(u) for u in filtered_urls],
            "urls_raw": filtered_urls,
            "ipv4_defanged": [defang(ip) for ip in public_ips],
            "ipv4_raw": public_ips,
            "email_addresses": sorted(raw_emails),
            "saas_tenant_ids": sorted(saas_org_ids),
            "attachments": attachments,
        },
        "active_enrichment": enrichments,
    }

    if do_sanitize:
        report = sanitize_report_pii(report)

    return report


def main():
    parser = argparse.ArgumentParser(
        description="eml_ioc_extractor.py - Advanced SOC Phishing Forensics & Threat Intel Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python src/eml_ioc_extractor.py suspicious.eml\n"
               "  python src/eml_ioc_extractor.py --enrich --sanitize -o report.json suspicious.eml\n"
    )
    parser.add_argument("eml_files", nargs="+", help="Path(s) to .eml file(s) for forensic analysis")
    parser.add_argument("-o", "--output", help="Optional JSON output path for structured SIEM/MISP ingestion")
    parser.add_argument("--enrich", action="store_true", help="Perform live DNS split-infrastructure, PTR & TLS cert age lookups")
    parser.add_argument("--sanitize", action="store_true", help="Sanitize internal recipient email addresses for safe public sharing")
    args = parser.parse_args()

    results = []
    for f in args.eml_files:
        path = Path(f)
        if not path.exists():
            print(f"[!] File not found: {path}", file=sys.stderr)
            continue
        report = analyze_eml(path, do_enrich=args.enrich, do_sanitize=args.sanitize)
        results.append(report)
        assess = report["assessment"]

        print(f"\n{'='*72}")
        print(f"FILE    : {report['file']}")
        print(f"VERDICT : {assess['verdict']} (Risk Score: {assess['risk_score']})")
        if assess["mitre_attack"]:
            print(f"MITRE   : {', '.join(assess['mitre_attack'])}")
        print(f"{'='*72}")

        print("--- Triggered Phishing Landmarks ---")
        for item in assess["triggered_landmarks"] or ["* None detected"]:
            print(f"  {item}")

        print("\n--- Key Headers ---")
        print(f"  Subject     : {report['headers']['subject']}")
        print(f"  From        : {report['headers']['from']}")
        print(f"  Reply-To    : {report['headers']['reply_to']}")
        print(f"  Return-Path : {report['headers']['return_path_unwrapped']}")

        print("\n--- Extracted Indicators (Defanged) ---")
        for u in report["iocs"]["urls_defanged"]:
            print(f"  URL : {u}")
        for ip in report["iocs"]["ipv4_defanged"]:
            print(f"  IP  : {ip}")

        if report["iocs"]["attachments"]:
            print("\n--- Attachments (SHA-256) ---")
            for att in report["iocs"]["attachments"]:
                print(f"  * {att['filename']} ({att['content_type']}) -> {att['sha256']}")

        if report["active_enrichment"]:
            print("\n--- Active Infrastructure Telemetry ---")
            for enr in report["active_enrichment"]:
                cert_status = f"Valid ({enr['tls_age_hours']}h old via {enr['tls_issuer']})" if enr.get("tls_cert_valid", True) else "Untrusted / Self-Signed"
                print(f"  * Host: {enr['host']}")
                print(f"    - Subdomain IPs : {enr['ips']}")
                print(f"    - Reverse PTR   : {enr['ptr_records']}")
                print(f"    - Apex IPs      : {enr['apex_ips']} (Split-Infra: {enr['split_infra']})")
                print(f"    - TLS Cert      : {cert_status}")

    if args.output:
        Path(args.output).write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\n[+] Saved structured forensic JSON report to {args.output}")

    # Automation exit codes for CI/CD and mail gateway pipelines
    highest_score = max((r["assessment"]["risk_score"] for r in results), default=0)
    if highest_score >= 60:
        sys.exit(2)  # Confirmed Phishing
    elif highest_score >= 30:
        sys.exit(1)  # High Risk / Suspicious
    sys.exit(0)      # Clean / Low Risk


if __name__ == "__main__":
    main()

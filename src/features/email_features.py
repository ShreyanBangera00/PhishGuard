"""
Email Feature Extraction Module for PhishGuard.
Upgraded with A-HMFA v4: Non-linear sigmoidal scaling to prevent premature
score saturation at 100 when email bodies contain dense keyword payloads.
"""

import math
import re
from urllib.parse import urlparse

URGENCY_KEYWORDS = [
    'urgent', 'immediately', 'expires', 'act now', 'suspended',
    'restricted', 'verify now', 'action required', 'unauthorized',
    'within 24 hours', '24 hours', 'security alert', 'final notice',
    'attention required', 'immediate action', 'suspicious',
    'suspicious activity', 'unusual activity', 'locked', 'compromised'
]

POOR_GRAMMAR_SPAM_WORDS = [
    'dear customer', 'dear user', 'dear client', 'kindly', '100% free',
    'winner', 'you have been selected', 'click below', 'click here',
    'update your account', 'confirm your identity', 'validate your account'
]

CRED_KEYWORDS = [
    'password', 'credential', 'credentials', 'ssn', 'credit card', 'pin',
    'bank account', 'billing information', 'billing', 'verify your',
    'sign-in', 'login', 'account', 'update-account', 'session='
]

HIGH_RISK_TLDS = {
    '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.info', '.click', '.buzz', '.icu'
}

OFFICIAL_DOMAINS = {
    'paypal': ['paypal.com'],
    'amazon': ['amazon.com', 'amazon.in'],
    'microsoft': ['microsoft.com', 'office.com', 'live.com'],
    'google': ['google.com', 'gmail.com'],
    'apple': ['apple.com', 'icloud.com'],
    'netflix': ['netflix.com'],
    'facebook': ['facebook.com', 'fb.com'],
    'instagram': ['instagram.com'],
}

WEIGHTS = {
    'sender_domain_mismatch': 0.30,
    'cred_request_score': 0.25,
    'html_form_present': 0.15,
    'urgency_score': 0.15,
    'poor_grammar_score': 0.10,
    'num_links': 0.05,
}
assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-6, "WEIGHTS must sum to 1.0"

FEATURE_LABELS = {
    'sender_domain_mismatch': 'Sender Domain Spoofing',
    'cred_request_score': 'Credential Solicitation',
    'html_form_present': 'Embedded Payload / Malicious Link Structure',
    'urgency_score': 'Psychological Urgency (Zone-Weighted)',
    'poor_grammar_score': 'Generic Salutation & Spam Phrases',
    'num_links': 'Hyperlink Volume & Risk Density',
}


def _normalize(count, cap):
    if cap <= 0:
        return 0.0
    return min(count / cap, 1.0)


def _log_zone_strength(subj_count: int, body_count: int, tau: float, subj_bonus: float = 0.0) -> float:
    """
    A-HMFA zone-weighted activation function phi_i with wider headroom (tau=18.0)
    to ensure subject line edits create measurable variance before saturation.
    """
    weighted_density = (2.0 * subj_count) + (1.0 * body_count) + subj_bonus
    if weighted_density <= 0:
        return 0.0
    return min(1.0, math.log(1.0 + weighted_density) / math.log(1.0 + tau))


def _evaluate_url_risk(extracted_urls: list, claimed_org: str) -> tuple[float, list]:
    if not extracted_urls:
        return 0.0, []
    max_risk = 0.0
    reasons = []
    org_clean = re.sub(r'[^a-z0-9]', '', claimed_org.lower())

    for url in extracted_urls:
        u_score = 0.25
        parsed = urlparse(url if url.startswith('http') else f'http://{url}')
        host = parsed.netloc.lower()
        path_query = f"{parsed.path}?{parsed.query}".lower()

        if parsed.scheme == 'http':
            u_score += 0.25
            reasons.append("unencrypted HTTP link")
        if any(host.endswith(tld) for tld in HIGH_RISK_TLDS):
            u_score += 0.30
            reasons.append(f"high-risk TLD ({host.split('.')[-1]})")
        if any(tok in path_query for tok in ['update', 'login', 'verify', 'session=', 'account', 'auth']):
            u_score += 0.20
            reasons.append("credential/session harvesting URL path")
        if org_clean and org_clean in host and not host.endswith(f"{org_clean}.com"):
            u_score += 0.25
            reasons.append(f"deceptive brand-spoofed URL host ({host})")

        max_risk = max(max_risk, min(1.0, u_score))

    return round(max_risk, 3), list(dict.fromkeys(reasons))


def _check_domain_mismatch(sender: str, claimed_org: str) -> tuple[int, float, str]:
    if not claimed_org:
        return 0, 0.0, "No claimed organization provided; domain not checked"

    if '@' not in sender:
        return 1, 1.0, "Sender address has no domain to verify"

    sender_domain = sender.split('@')[-1].strip().lower()
    org_key = claimed_org.strip().lower()

    tld_penalty = 0.15 if any(sender_domain.endswith(t) for t in HIGH_RISK_TLDS) else 0.0
    hyphen_penalty = min(0.15, sender_domain.count('-') * 0.075)

    official = OFFICIAL_DOMAINS.get(org_key)
    if official:
        is_official = any(
            sender_domain == d or sender_domain.endswith(f'.{d}')
            for d in official
        )
        if is_official:
            return 0, 0.0, f"Sender domain '{sender_domain}' matches official {claimed_org} domain"
        severity = min(1.0, 0.80 + tld_penalty + hyphen_penalty) if org_key in sender_domain else min(1.0, 0.75 + tld_penalty)
        return 1, round(severity, 3), (
            f"Sender domain '{sender_domain}' spoofs '{claimed_org}' and does not match official "
            f"domain ({', '.join(official)})"
        )

    bare_domain = sender_domain.split('.')[0]
    if org_key in sender_domain and bare_domain != org_key:
        severity = min(1.0, 0.85 + tld_penalty + hyphen_penalty)
        return 1, round(severity, 3), f"Lookalike domain '{sender_domain}' embeds brand '{org_key}' with deceptive affixes"
    if org_key not in sender_domain:
        severity = min(1.0, 0.75 + tld_penalty + hyphen_penalty)
        return 1, round(severity, 3), f"Sender domain '{sender_domain}' bears no relation to claimed org '{claimed_org}'"

    return 0, 0.0, f"Sender domain '{sender_domain}' appears to match claimed org '{claimed_org}'"


def extract_email_features(email_data: dict) -> dict:
    subject = str(email_data.get('subject', ''))
    sender = str(email_data.get('sender', '')).lower()
    claimed_org = str(email_data.get('claimed_org', ''))
    body = str(email_data.get('body', ''))
    has_attachment = 1 if email_data.get('has_attachment', False) else 0

    subj_lower = subject.lower()
    body_lower = body.lower()
    full_text = f"{subj_lower} {body_lower}"

    sender_domain_mismatch, domain_severity, domain_reason = _check_domain_mismatch(sender, claimed_org)

    link_matches = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body, re.IGNORECASE)
    extracted_urls = list(set(link_matches))
    num_links = len(extracted_urls)
    url_threat_phi, url_reasons = _evaluate_url_risk(extracted_urls, claimed_org)

    urg_subj_hits = [kw for kw in URGENCY_KEYWORDS if kw in subj_lower]
    urg_body_hits = [kw for kw in URGENCY_KEYWORDS if kw in body_lower]
    urgency_score = len(urg_subj_hits) + len(urg_body_hits)

    gram_subj_hits = [kw for kw in POOR_GRAMMAR_SPAM_WORDS if kw in subj_lower]
    gram_body_hits = [kw for kw in POOR_GRAMMAR_SPAM_WORDS if kw in body_lower]
    poor_grammar_score = len(gram_subj_hits) + len(gram_body_hits)

    cred_subj_hits = [kw for kw in CRED_KEYWORDS if kw in subj_lower]
    cred_body_hits = [kw for kw in CRED_KEYWORDS if kw in body_lower]
    cred_request_score = len(cred_subj_hits) + len(cred_body_hits)

    body_length = len(body)
    words = full_text.split()
    word_count = len(words)
    html_form_present = 1 if ('<form' in body_lower or '<input' in body_lower) else 0

    binary_triggers_h = {
        'sender_domain_mismatch': 1.0 if sender_domain_mismatch > 0 else 0.0,
        'cred_request_score': 1.0 if cred_request_score > 0 else 0.0,
        'html_form_present': 1.0 if (html_form_present > 0 or url_threat_phi >= 0.7) else 0.0,
        'urgency_score': 1.0 if urgency_score > 0 else 0.0,
        'poor_grammar_score': 1.0 if poor_grammar_score > 0 else 0.0,
        'num_links': 1.0 if num_links > 0 else 0.0,
    }

    subj_exclam_bonus = 0.5 if '!' in subject else 0.0
    subj_caps_bonus = 0.4 if any(w.isupper() and len(w) >= 4 for w in subject.split()) else 0.0

    proposed_strengths_phi = {
        'sender_domain_mismatch': domain_severity,
        'cred_request_score': _log_zone_strength(len(cred_subj_hits), len(cred_body_hits), tau=16.0),
        'html_form_present': max(float(html_form_present), url_threat_phi),
        'urgency_score': _log_zone_strength(
            len(urg_subj_hits), len(urg_body_hits), tau=18.0, subj_bonus=(subj_exclam_bonus + subj_caps_bonus)
        ),
        'poor_grammar_score': _log_zone_strength(len(gram_subj_hits), len(gram_body_hits), tau=10.0),
        'num_links': min(1.0, (0.65 * url_threat_phi) + (0.35 * _normalize(num_links, 3))),
    }

    rule_evidence = {
        'sender_domain_mismatch': domain_reason,
        'cred_request_score': f"Subject ({len(cred_subj_hits)}×2.0): {cred_subj_hits} | Body ({len(cred_body_hits)}×1.0): {cred_body_hits}",
        'html_form_present': f"Malicious URL/Form indicators: {', '.join(url_reasons)}" if url_reasons else ("HTML form detected" if html_form_present else "No inline form/payload"),
        'urgency_score': f"Subject ({len(urg_subj_hits)}×2.0): {urg_subj_hits} | Body ({len(urg_body_hits)}×1.0): {urg_body_hits}",
        'poor_grammar_score': f"Detected {poor_grammar_score} generic/spam phrase(s): {gram_subj_hits + gram_body_hits}",
        'num_links': f"{num_links} URL(s) extracted (URL threat density={url_threat_phi})",
    }

    breakdown = []
    base_sh = 0.0
    proposed_raw_sh = 0.0

    for key, weight in WEIGHTS.items():
        h_val = binary_triggers_h[key]
        phi_val = proposed_strengths_phi[key]

        base_contrib = weight * h_val * 100.0
        prop_contrib = weight * phi_val * 100.0

        base_sh += base_contrib
        proposed_raw_sh += prop_contrib

        breakdown.append({
            'feature': key,
            'label': FEATURE_LABELS.get(key, key),
            'weight': weight,
            'binary_h': int(h_val),
            'base_contribution': round(base_contrib, 2),
            'strength': round(phi_val, 3),
            'contribution': round(prop_contrib, 2),
            'reason': rule_evidence.get(key, ''),
        })

    spoof_phi = proposed_strengths_phi['sender_domain_mismatch']
    url_phi = proposed_strengths_phi['html_form_present']
    urg_phi = proposed_strengths_phi['urgency_score']
    cred_phi = proposed_strengths_phi['cred_request_score']

    # Controlled synergy factor
    psi_synergy = round((6.0 * spoof_phi * url_phi) + (4.0 * urg_phi * cred_phi * url_phi), 2)
    
    # Non-linear sigmoidal mapping to prevent flat 100 ceilings
    combined_metric = proposed_raw_sh + psi_synergy
    proposed_sh_star = round(100.0 * (1.0 - math.exp(-combined_metric / 75.0)), 2)
    base_sh = round(min(100.0, base_sh), 2)

    total_signal_tokens = urgency_score + cred_request_score + poor_grammar_score
    p_ml = round(min(96.0, 28.0 + (total_signal_tokens / max(1, word_count)) * 220.0), 2)

    beta_base = 0.50
    base_final_score = round(beta_base * base_sh + (1.0 - beta_base) * p_ml, 2)

    hard_evidence = max(spoof_phi, url_phi)
    beta_adaptive = round(0.55 + 0.30 * (proposed_sh_star / 100.0) * hard_evidence, 3)
    proposed_final_score = round(beta_adaptive * proposed_sh_star + (1.0 - beta_adaptive) * p_ml, 2)

    legacy_v1_score = min(100, (min(urgency_score * 15, 30) + min(poor_grammar_score * 10, 20) + (20 if cred_request_score > 0 else 0)))

    return {
        'sender_domain_mismatch': sender_domain_mismatch,
        'sender_domain_reason': domain_reason,
        'num_links': num_links,
        'extracted_urls': extracted_urls,
        'urgency_score': urgency_score,
        'poor_grammar_score': poor_grammar_score,
        'body_length': body_length,
        'word_count': word_count,
        'html_form_present': html_form_present,
        'cred_request_score': cred_request_score,
        'has_attachment': has_attachment,
        'email_risk_score': proposed_final_score,
        'is_suspicious_email': 1 if proposed_final_score >= 50 else 0,
        'breakdown': breakdown,
        'model_comparison': {
            'legacy_v1_score': legacy_v1_score,
            'base_paper': {
                'name': 'Jadhav & Chandre (2025) Base Paper',
                'formula': 'S_H = Σ(α_i · h_i), h_i ∈ {0,1}, fixed β = 0.50',
                'S_H': base_sh,
                'beta': beta_base,
                'P_ML': p_ml,
                'final_score': base_final_score,
            },
            'proposed_ahmfa': {
                'name': 'Proposed A-HMFA Model (Ours)',
                'formula': 'S_H* = 100 · (1 - e^(-(Σ(α_i · φ_i) + Ψ) / 75))',
                'raw_SH': round(proposed_raw_sh, 2),
                'synergy_bonus': psi_synergy,
                'S_H_star': proposed_sh_star,
                'beta_adaptive': beta_adaptive,
                'P_ML': p_ml,
                'final_score': proposed_final_score,
            }
        }
    }

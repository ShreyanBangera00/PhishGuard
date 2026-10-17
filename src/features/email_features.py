"""
Email Feature Extraction Module for PhishGuard.
Extracts heuristic and NLP features from raw email text and header metadata.

----------------------------------------------------------------------------
v2: Weighted risk-score formula
----------------------------------------------------------------------------
Based on the weighted heuristic suspicion-score formula from:

  Jadhav, A., & Chandre, P. (2025). "A Hybrid Heuristic-Machine Learning
  Framework for Phishing Detection Using Multi-Domain Feature Analysis."
  Engineering, Technology & Applied Science Research, 15(5), 27219-27226.
  DOI: 10.48084/etasr.11548

  Core formula (their Sec. III.C):   S_H = sum_i ( alpha_i * h_i )
  i.e. a weighted sum over rule triggers h_i (0/1), each with its own
  weight alpha_i reflecting that rule's "criticality". The paper leaves
  the exact alpha_i values to the implementer, so the weights below are
  our own engineering choice, justified per-category in WEIGHTS.

Two changes from the previous version of this file:

1. THE SCORE IS NOW A TRUE WEIGHTED SUM, NOT A CAPPED ADDITIVE HEURISTIC.
   The old version did things like `risk_points += min(urgency_score*15,30)`
   -- a hard per-category ceiling reached after just 2 keyword hits, which
   is why editing the email's wording stopped moving the score: once a
   category hit its cap, every extra matching word did nothing. Here each
   category contributes `weight_i * strength_i * 100`, where strength_i is
   a *continuous* 0..1 value (more matches => higher strength, smoothly,
   up to a saturation point) -- so the score keeps responding to wording
   changes within the same signal.

2. THE SENDER-DOMAIN-MISMATCH CHECK WAS SILENTLY BROKEN FOR LOOK-ALIKE
   DOMAINS. The old check was:
       if claimed_org not in sender_domain: sender_domain_mismatch = 1
   This is a plain substring test, so claimed_org="paypal" against
   sender_domain="paypal-auth-center.xyz" returns `'paypal' in
   'paypal-auth-center.xyz'` == True, meaning the mismatch is NEVER
   flagged for exactly the kind of lookalike domain a phisher actually
   uses (brand name + extra words + a cheap TLD). It only fired when the
   domain didn't mention the brand at all, which is the easy case. This
   is very likely the single biggest reason the prototype's "High-Risk"
   verdict on the PayPal demo email never showed a domain-spoof reason,
   and why a sender like "amazon-account-verify.xyz" wasn't flagged as a
   mismatch either. The new `_check_domain_mismatch()` below checks the
   domain against a small table of real/official domains for common
   claimed orgs, and otherwise flags "brand name present inside a domain
   that isn't the brand's own apex domain" as a mismatch (the classic
   lookalike pattern), instead of a plain substring test.

The function's name, input shape, and ALL previously-returned dict keys
are unchanged, so src/api/main.py, the frontend, and tests/test_api.py
keep working without modification. A new 'breakdown' key is added for
anyone who wants to render the weighted contributions (see
src/api/main.py's analyze_email(), which now passes it through).
"""

import re

URGENCY_KEYWORDS = [
    'urgent', 'immediately', 'expires', 'act now', 'suspended',
    'restricted', 'verify now', 'action required', 'unauthorized',
    'within 24 hours', 'security alert', 'final notice', 'attention required',
    'immediate action'
]

POOR_GRAMMAR_SPAM_WORDS = [
    'dear customer', 'dear user', 'kindly', '100% free', 'winner',
    'you have been selected', 'click below', 'update your account',
    'confirm your identity', 'validate your account'
]

CRED_KEYWORDS = [
    'password', 'credential', 'ssn', 'credit card', 'pin',
    'bank account', 'billing information'
]

# Small table of official/apex domains for commonly-impersonated orgs.
# Extend this as your dataset of claimed_org values grows. Any claimed_org
# not in this table falls back to the heuristic lookalike check below
# rather than being silently skipped.
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

# ---------------------------------------------------------------
# WEIGHTS -- our own "criticality" judgment (the paper explicitly
# leaves these to the implementer). Sum to 1.0.
#   - Sender Domain Spoof: highest weight. A sender that isn't who it
#     claims to be is the single most reliable phishing signal and is
#     independent of how well-written the email is.
#   - Credential Solicitation: second highest -- directly leads to
#     account/financial compromise if acted on.
#   - Embedded Form: a phishing page can be delivered inline via an
#     HTML form in the email body itself, bypassing link-based checks.
#   - Psychological Urgency: strong social-engineering signal, but also
#     appears in some legitimate transactional mail (expiring OTPs,
#     shipping deadlines), so it sits below the above three.
#   - Poor Grammar & Spam Words: weakest signal today -- many modern
#     phishing kits use clean English -- kept mainly for explainability.
#   - Link Volume: a secondary, low-confidence signal on its own.
# ---------------------------------------------------------------
WEIGHTS = {
    'sender_domain_mismatch': 0.30,
    'cred_request_score': 0.25,
    'html_form_present': 0.15,
    'urgency_score': 0.15,
    'poor_grammar_score': 0.10,
    'num_links': 0.05,
}
assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-6, "WEIGHTS must sum to 1.0"


def _normalize(count, cap):
    """Map a raw match count to a continuous 0..1 strength, saturating at `cap`."""
    if cap <= 0:
        return 0.0
    return min(count / cap, 1.0)


def _check_domain_mismatch(sender: str, claimed_org: str) -> tuple[int, str]:
    """
    Returns (mismatch: 0|1, reason: str).

    Replaces the old plain substring test (`claimed_org not in
    sender_domain`), which never fires for lookalike domains that embed
    the brand name (e.g. 'paypal-auth-center.xyz' contains 'paypal').
    """
    if not claimed_org:
        return 0, "No claimed organization provided; domain not checked"

    if '@' not in sender:
        return 1, "Sender address has no domain to verify"

    sender_domain = sender.split('@')[-1].strip().lower()
    org_key = claimed_org.strip().lower()

    official = OFFICIAL_DOMAINS.get(org_key)
    if official:
        is_official = any(
            sender_domain == d or sender_domain.endswith(f'.{d}')
            for d in official
        )
        if is_official:
            return 0, f"Sender domain '{sender_domain}' matches official {claimed_org} domain"
        return 1, (
            f"Sender domain '{sender_domain}' does not match any official "
            f"{claimed_org} domain ({', '.join(official)})"
        )

    # claimed_org not in our known-domain table: fall back to the
    # lookalike heuristic -- brand name appears INSIDE the domain, but
    # the domain is not simply "<brand>.<tld>" (i.e. it's padded with
    # extra words like '-auth-center', '-support', '-verify', etc.)
    bare_domain = sender_domain.split('.')[0]
    if org_key in sender_domain and bare_domain != org_key:
        return 1, f"Domain '{sender_domain}' embeds the brand name but is not '{org_key}'s own domain"
    if org_key not in sender_domain:
        return 1, f"Sender domain '{sender_domain}' bears no relation to claimed org '{claimed_org}'"

    return 0, f"Sender domain '{sender_domain}' appears to match claimed org '{claimed_org}'"


def extract_email_features(email_data: dict) -> dict:
    """
    Extracts features from email subject, body, sender, and headers.

    Expected keys in email_data:
        - subject: str
        - sender: str (e.g., 'security@amazn-support.com' or 'service@paypal.com')
        - claimed_org: str (e.g., 'Amazon' or 'PayPal')
        - body: str
        - has_attachment: bool (optional)
    """
    subject = str(email_data.get('subject', ''))
    sender = str(email_data.get('sender', '')).lower()
    claimed_org = str(email_data.get('claimed_org', ''))
    body = str(email_data.get('body', ''))
    has_attachment = 1 if email_data.get('has_attachment', False) else 0

    full_text = f"{subject} {body}".lower()

    # 1. Sender domain mismatch (fixed lookalike-domain detection)
    sender_domain_mismatch, domain_reason = _check_domain_mismatch(sender, claimed_org)

    # 2. Number of links in body (URLs, hrefs, http/https)
    link_matches = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body, re.IGNORECASE)
    extracted_urls = list(set(link_matches))
    num_links = len(extracted_urls)

    # 3. Urgency & Grammar scores (raw counts, unchanged)
    urgency_score = sum(1 for kw in URGENCY_KEYWORDS if kw in full_text)
    poor_grammar_score = sum(1 for kw in POOR_GRAMMAR_SPAM_WORDS if kw in full_text)

    # 4. Body character and word length
    body_length = len(body)
    words = full_text.split()
    word_count = len(words)

    # 5. HTML form detection inside email body
    html_form_present = 1 if ('<form' in body.lower() or '<input' in body.lower()) else 0

    # 6. Suspicious credential keywords in email body
    cred_request_score = sum(1 for kw in CRED_KEYWORDS if kw in full_text)

    # ---------------------------------------------------------------
    # Weighted risk score: RiskScore = 100 * sum_i( weight_i * strength_i )
    # strength_i is continuous in [0,1], so the score keeps moving as
    # signal strength changes within a category, instead of jumping to
    # a fixed bucket and then staying flat.
    # ---------------------------------------------------------------
    strengths = {
        'sender_domain_mismatch': float(sender_domain_mismatch),       # already 0/1
        'cred_request_score': _normalize(cred_request_score, 2),
        'html_form_present': float(html_form_present),                # already 0/1
        'urgency_score': _normalize(urgency_score, 4),
        'poor_grammar_score': _normalize(poor_grammar_score, 3),
        'num_links': _normalize(num_links, 4),
    }

    breakdown = []
    overall_risk = 0.0
    for key, weight in WEIGHTS.items():
        strength = strengths[key]
        contribution = weight * strength * 100
        overall_risk += contribution
        breakdown.append({
            'feature': key,
            'weight': weight,
            'strength': round(strength, 2),
            'contribution': round(contribution, 1),
        })

    overall_risk = round(min(overall_risk, 100))

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
        'email_risk_score': overall_risk,
        'is_suspicious_email': 1 if overall_risk >= 50 else 0,
        'breakdown': breakdown,
    }

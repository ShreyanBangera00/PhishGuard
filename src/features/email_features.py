"""
Email Feature Extraction Module for PhishGuard.
Extracts heuristic and NLP features from raw email text and header metadata.
"""

import re

URGENCY_KEYWORDS = [
    'urgent', 'immediately', 'expires', 'act now', 'suspended',
    'restricted', 'verify now', 'action required', 'unauthorized',
    'within 24 hours', 'security alert', 'final notice'
]


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
    claimed_org = str(email_data.get('claimed_org', '')).lower()
    body = str(email_data.get('body', ''))
    has_attachment = 1 if email_data.get('has_attachment', False) else 0

    full_text = f"{subject} {body}".lower()

    # 1. Sender domain mismatch
    # If claimed_org is provided, verify if the sender domain contains it
    sender_domain_mismatch = 0
    if claimed_org:
        # Extract domain from sender
        if '@' in sender:
            sender_domain = sender.split('@')[-1]
            if claimed_org not in sender_domain:
                sender_domain_mismatch = 1
        else:
            sender_domain_mismatch = 1

    # 2. Number of links in body (URLs, hrefs, http/https)
    link_matches = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body, re.IGNORECASE)
    num_links = len(link_matches)

    # 3. Urgency score: count occurrences of psychological triggers
    urgency_score = sum(1 for kw in URGENCY_KEYWORDS if kw in full_text)

    # 4. Body character and word length
    body_length = len(body)
    words = full_text.split()
    word_count = len(words)

    # 5. HTML form detection inside email body
    html_form_present = 1 if ('<form' in body.lower() or '<input' in body.lower()) else 0

    # 6. Suspicious credential keywords in email body
    cred_keywords = ['password', 'credential', 'ssn', 'credit card', 'pin', 'bank account']
    cred_request_score = sum(1 for kw in cred_keywords if kw in full_text)

    # Heuristic combined email risk score (0 to 100)
    risk_points = 0
    if sender_domain_mismatch:
        risk_points += 35
    if urgency_score > 0:
        risk_points += min(urgency_score * 15, 30)
    if html_form_present:
        risk_points += 25
    if cred_request_score > 0:
        risk_points += 20
    if num_links > 2:
        risk_points += 10

    overall_risk = min(risk_points, 100)

    return {
        'sender_domain_mismatch': sender_domain_mismatch,
        'num_links': num_links,
        'urgency_score': urgency_score,
        'body_length': body_length,
        'word_count': word_count,
        'html_form_present': html_form_present,
        'cred_request_score': cred_request_score,
        'has_attachment': has_attachment,
        'email_risk_score': overall_risk,
        'is_suspicious_email': 1 if overall_risk >= 50 else 0
    }

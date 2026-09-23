"""
URL Feature Extraction Module for PhishGuard.
Extracts 17 structural, lexical, and statistical features from raw URLs.
"""

import math
import re
from urllib.parse import urlparse, parse_qs
import tldextract

# Suspicious keywords commonly found in credential-harvesting phishing URLs
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'secure', 'account', 'update', 'confirm',
    'bank', 'signin', 'password', 'alert', 'payment', 'support',
    'wallet', 'billing', 'security', 'authenticate', 'service'
]

# Known URL shortener domains
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd',
    'buff.ly', 'adf.ly', 'bit.do', 'short.io', 'cutt.ly', 'rb.gy'
}

# High-risk TLDs commonly abused by malicious actors
RISKY_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'loan',
    'click', 'men', 'date', 'download', 'racing', 'win', 'vip'
}

# IPv4 pattern (with optional port)
IPV4_PATTERN = re.compile(r'^(?:https?://)?(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/.*)?$', re.IGNORECASE)


def calculate_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a given text string."""
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    length = len(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return round(entropy, 4)


def extract_url_features(url: str) -> dict:
    """
    Extracts 17 distinct numerical/categorical features from a single URL string.
    Returns a dictionary of feature names mapped to numeric values.
    """
    if not url or not isinstance(url, str):
        # Return default zeroed vector for invalid inputs
        return {
            'url_length': 0,
            'hostname_length': 0,
            'num_dots': 0,
            'num_hyphens': 0,
            'num_at': 0,
            'num_subdomains': 0,
            'has_ip': 0,
            'is_https': 0,
            'has_shortener': 0,
            'path_length': 0,
            'num_query_params': 0,
            'has_suspicious_words': 0,
            'special_char_ratio': 0.0,
            'digit_ratio': 0.0,
            'has_redirect': 0,
            'tld_risk': 0,
            'entropy': 0.0
        }

    raw_url = url.strip()
    # Normalize scheme for parsing if absent
    if not (raw_url.startswith('http://') or raw_url.startswith('https://')):
        parsed_url = urlparse('http://' + raw_url)
    else:
        parsed_url = urlparse(raw_url)

    extracted_tld = tldextract.extract(raw_url)
    hostname = parsed_url.netloc or (extracted_tld.subdomain + '.' + extracted_tld.domain + '.' + extracted_tld.suffix).strip('.')
    path = parsed_url.path or ''
    query = parsed_url.query or ''

    # 1. Total character length of URL
    url_length = len(raw_url)

    # 2. Hostname length
    hostname_length = len(hostname)

    # 3. Number of dots in URL
    num_dots = raw_url.count('.')

    # 4. Number of hyphens in URL
    num_hyphens = raw_url.count('-')

    # 5. Number of '@' symbols (often used to obscure preceding authority)
    num_at = raw_url.count('@')

    # 6. Number of subdomains
    subdomain_parts = [s for s in extracted_tld.subdomain.split('.') if s] if extracted_tld.subdomain else []
    num_subdomains = len(subdomain_parts)

    # 7. Uses IP address instead of domain
    has_ip = 1 if bool(IPV4_PATTERN.match(raw_url)) or bool(re.search(r'//\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', raw_url)) else 0

    # 8. HTTPS usage
    is_https = 1 if raw_url.lower().startswith('https://') else 0

    # 9. Shortener service check
    reg_domain = f"{extracted_tld.domain}.{extracted_tld.suffix}".lower()
    has_shortener = 1 if (reg_domain in URL_SHORTENERS or hostname.lower() in URL_SHORTENERS) else 0

    # 10. Path length
    path_length = len(path)

    # 11. Number of query parameters
    try:
        query_params = parse_qs(query)
        num_query_params = len(query_params)
    except Exception:
        num_query_params = query.count('&') + (1 if query else 0)

    # 12. Suspicious keywords count in URL
    url_lower = raw_url.lower()
    suspicious_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    has_suspicious_words = min(suspicious_count, 5)

    # 13. Special character ratio
    special_chars = re.findall(r'[^a-zA-Z0-9]', raw_url)
    special_char_ratio = round(len(special_chars) / max(url_length, 1), 4)

    # 14. Digit ratio
    digits = re.findall(r'\d', raw_url)
    digit_ratio = round(len(digits) / max(url_length, 1), 4)

    # 15. Redirect indicator ('//' occurring within path)
    has_redirect = 1 if '//' in path else 0

    # 16. Risky TLD
    tld_risk = 1 if extracted_tld.suffix.lower() in RISKY_TLDS else 0

    # 17. Shannon Entropy
    entropy = calculate_entropy(raw_url)

    return {
        'url_length': url_length,
        'hostname_length': hostname_length,
        'num_dots': num_dots,
        'num_hyphens': num_hyphens,
        'num_at': num_at,
        'num_subdomains': num_subdomains,
        'has_ip': has_ip,
        'is_https': is_https,
        'has_shortener': has_shortener,
        'path_length': path_length,
        'num_query_params': num_query_params,
        'has_suspicious_words': has_suspicious_words,
        'special_char_ratio': special_char_ratio,
        'digit_ratio': digit_ratio,
        'has_redirect': has_redirect,
        'tld_risk': tld_risk,
        'entropy': entropy
    }

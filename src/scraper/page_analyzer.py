"""
Page Content Analyzer Module for PhishGuard (Multi-modal detection).
Safely retrieves and inspects DOM structure, forms, external assets, and brand consistency.
Includes SSRF protections against internal/reserved network probing and dual-stage TLS verification.
"""

import re
import socket
import ipaddress
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import tldextract

MAJOR_BRANDS = [
    'paypal', 'google', 'microsoft', 'apple', 'amazon', 'netflix',
    'facebook', 'instagram', 'wellsfargo', 'chase', 'bankofamerica',
    'citibank', 'dropbox', 'dhl', 'fedex', 'usps'
]


class SSRFSecurityError(ValueError):
    """Raised when a URL targets a private, loopback, link-local, or reserved network address."""
    pass


def is_private_or_reserved_ip(ip_str: str) -> bool:
    """Checks whether an IP address belongs to private, loopback, link-local, or reserved ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )
    except ValueError:
        return False


def check_ssrf_safe(url: str) -> tuple[bool, str]:
    """
    Validates that a URL does not resolve to loopback, private, link-local, or reserved IP ranges.
    Returns (is_safe: bool, error_message: str).
    """
    if not url or not url.strip():
        return False, "URL cannot be empty"

    target_url = url.strip()
    if not (target_url.startswith('http://') or target_url.startswith('https://')):
        target_url = 'http://' + target_url

    try:
        parsed = urlparse(target_url)
    except Exception as e:
        return False, f"Malformed URL: {str(e)}"

    hostname = parsed.hostname
    if not hostname:
        return False, "Invalid URL: missing hostname"

    # 1. Direct IP literal check
    if is_private_or_reserved_ip(hostname):
        return False, f"Access to private/loopback/reserved IP address is prohibited ({hostname})"

    # 2. DNS resolution check (protect against DNS rebinding & names resolving to internal IPs)
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for *_, sockaddr in addr_info:
            ip_candidate = sockaddr[0]
            if is_private_or_reserved_ip(ip_candidate):
                return False, f"Hostname resolves to private/loopback/reserved IP address ({ip_candidate})"
    except socket.gaierror:
        # Non-resolvable domain is not an SSRF threat, requests will handle unreachable host
        pass
    except Exception as e:
        return False, f"DNS resolution failed: {str(e)}"

    return True, ""


def analyze_page(url: str, timeout: int = 5) -> dict:
    """
    Safely fetches and inspects landing page content for phishing characteristics.
    Enforces SSRF prevention and performs dual-stage TLS verification:
    attempts verify=True first, and only falls back to verify=False if SSLError occurs
    while recording has_invalid_cert=1.
    """
    default_result = {
        'accessible': False,
        'status_code': 0,
        'has_login_form': 0,
        'num_forms': 0,
        'num_password_inputs': 0,
        'external_resource_ratio': 0.0,
        'has_brand_mismatch': 0,
        'detected_brand': None,
        'page_title': '',
        'has_invalid_cert': 0,
        'error': None
    }

    if not url:
        default_result['error'] = 'Empty URL'
        return default_result

    target_url = url.strip()
    if not (target_url.startswith('http://') or target_url.startswith('https://')):
        target_url = 'http://' + target_url

    # SSRF Guard
    is_safe, ssrf_error = check_ssrf_safe(target_url)
    if not is_safe:
        raise SSRFSecurityError(ssrf_error)

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }

    has_invalid_cert = 0

    try:
        # Dual-stage TLS verification: attempt with full verification first
        try:
            response = requests.get(
                target_url,
                headers=headers,
                timeout=timeout,
                verify=True,
                allow_redirects=True
            )
        except requests.exceptions.SSLError:
            # TLS failure is a significant phishing signal — record it and retry with verify=False
            # solely to continue inspecting DOM elements
            has_invalid_cert = 1
            response = requests.get(
                target_url,
                headers=headers,
                timeout=timeout,
                verify=False,
                allow_redirects=True
            )

        soup = BeautifulSoup(response.text, 'html.parser')
        parsed = urlparse(target_url)
        target_domain = tldextract.extract(parsed.netloc).domain.lower()

        # Forms & input elements
        forms = soup.find_all('form')
        password_inputs = soup.find_all('input', {'type': re.compile(r'^password$', re.I)})
        has_login_form = 1 if len(password_inputs) > 0 else 0

        # Title
        title_tag = soup.find('title')
        page_title = title_tag.get_text().strip() if title_tag else ''

        # External resource ratio (scripts, links, images)
        total_resources = 0
        external_resources = 0
        for tag, attr in [('script', 'src'), ('link', 'href'), ('img', 'src')]:
            for el in soup.find_all(tag):
                src = el.get(attr, '')
                if src:
                    total_resources += 1
                    if src.startswith('http://') or src.startswith('https://') or src.startswith('//'):
                        res_domain = tldextract.extract(src).domain.lower()
                        if res_domain and res_domain != target_domain:
                            external_resources += 1

        ext_ratio = round(external_resources / max(total_resources, 1), 4) if total_resources > 0 else 0.0

        # Brand mismatch analysis: if the page title or visible text claims a major brand
        # but the domain does not belong to that brand
        page_content_lower = (page_title + ' ' + (soup.body.get_text()[:1500] if soup.body else '')).lower()
        has_brand_mismatch = 0
        detected_brand = None

        for brand in MAJOR_BRANDS:
            if brand in page_content_lower:
                if brand not in target_domain:
                    has_brand_mismatch = 1
                    detected_brand = brand
                    break

        return {
            'accessible': True,
            'status_code': response.status_code,
            'has_login_form': has_login_form,
            'num_forms': len(forms),
            'num_password_inputs': len(password_inputs),
            'external_resource_ratio': ext_ratio,
            'has_brand_mismatch': has_brand_mismatch,
            'detected_brand': detected_brand,
            'page_title': page_title[:80],
            'has_invalid_cert': has_invalid_cert,
            'error': None
        }

    except requests.exceptions.Timeout:
        default_result['has_invalid_cert'] = has_invalid_cert
        default_result['error'] = 'Connection timed out (5s limit)'
        return default_result
    except requests.exceptions.SSLError:
        default_result['has_invalid_cert'] = 1
        default_result['error'] = 'SSL certificate error'
        return default_result
    except Exception as e:
        default_result['has_invalid_cert'] = has_invalid_cert
        default_result['error'] = str(e)[:100]
        return default_result

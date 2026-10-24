"""
Network and Domain Intelligence Module for PhishGuard.
Extracts WHOIS, DNS, IP Geolocation/ASN, TLS certificate metadata,
and live Sender Email Verification (Disify MX/Disposable API + WHOIS).
"""

import socket
import ssl
import logging
from datetime import datetime
from urllib.parse import urlparse, quote
import requests
import whois

logger = logging.getLogger(__name__)


def verify_sender_live(sender_email: str) -> dict:
    """
    Verifies a sender email address in real time using:
    1. Disify Free Email API (https://www.disify.com/api/email/{sender}) for live DNS MX
       records and disposable/burner email detection.
    2. Live WHOIS & DNS lookup on the sender's @domain to check domain age,
       creation date, registrar, and registration status.
    """
    result = {
        'email': sender_email,
        'domain': None,
        'format_valid': False,
        'has_mx_records': None,
        'is_disposable': False,
        'ip_address': None,
        'registrar': None,
        'creation_date': None,
        'domain_age_days': None,
        'domain_status': 'Unknown',
        'risk_severity': 0.0,
        'findings': []
    }

    if not sender_email or '@' not in sender_email:
        result['domain_status'] = 'Invalid Format'
        result['risk_severity'] = 1.0
        result['findings'].append("Sender address is missing an '@' domain")
        return result

    clean_email = sender_email.strip().lower()
    domain = clean_email.split('@')[-1].strip()
    if domain.startswith('www.'):
        domain = domain[4:]
    result['domain'] = domain

    # 1. Query Disify Free Email API (No API key needed)
    disify_ok = False
    try:
        resp = requests.get(
            f"https://www.disify.com/api/email/{quote(clean_email)}",
            timeout=3.5,
            headers={'Accept': 'application/json', 'User-Agent': 'PhishGuard-Security/1.0'}
        )
        if resp.status_code == 200:
            data = resp.json()
            disify_ok = True
            result['format_valid'] = bool(data.get('format', True))
            result['has_mx_records'] = bool(data.get('dns', False))
            result['is_disposable'] = bool(data.get('disposable', False))
    except Exception as e:
        logger.warning(f"Disify API lookup failed for {clean_email}: {e}")

    # 2. Live DNS A-Record check on sender domain
    try:
        ip_addr = socket.gethostbyname(domain)
        result['ip_address'] = ip_addr
        if not disify_ok:
            result['format_valid'] = True
            result['has_mx_records'] = True
    except Exception:
        if not disify_ok:
            result['has_mx_records'] = False

    # 3. Live WHOIS Lookup on sender domain (Domain Age & Registrar)
    try:
        w = whois.whois(domain)
        if w:
            registrar = w.registrar
            if isinstance(registrar, list):
                registrar = registrar[0] if registrar else None
            result['registrar'] = registrar

            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0] if creation_date else None

            if isinstance(creation_date, datetime):
                # Strip timezone info if present for safe subtraction
                naive_created = creation_date.replace(tzinfo=None)
                result['creation_date'] = naive_created.strftime("%Y-%m-%d")
                age_days = max(0, (datetime.now() - naive_created).days)
                result['domain_age_days'] = age_days
    except Exception as e:
        logger.warning(f"WHOIS lookup failed for sender domain {domain}: {e}")

    # 4. Classify Domain Status & Compute Live Risk Findings
    age = result['domain_age_days']
    has_mx = result['has_mx_records']
    has_ip = result['ip_address'] is not None
    has_whois = result['creation_date'] is not None or result['registrar'] is not None

    if has_mx is False and not has_ip and not has_whois:
        result['domain_status'] = 'Unregistered / Fake'
        result['risk_severity'] = max(result['risk_severity'], 0.95)
        result['findings'].append(f"Domain '{domain}' does not exist or has no active mail server (MX/DNS failed)")
    elif has_mx is False:
        result['domain_status'] = 'No Mail Server (MX)'
        result['risk_severity'] = max(result['risk_severity'], 0.85)
        result['findings'].append(f"Domain '{domain}' has no valid mail server (MX records missing)")
    elif age is not None and age < 90:
        result['domain_status'] = f'Newly Created ({age} days old)'
        result['risk_severity'] = max(result['risk_severity'], 0.80)
        result['findings'].append(f"Sender domain '{domain}' was registered very recently ({age} days ago on {result['creation_date']})")
    elif age is not None:
        years = round(age / 365.25, 1)
        result['domain_status'] = f'Established ({years} yrs old, created {result["creation_date"]})'
    elif has_mx or has_ip:
        result['domain_status'] = 'Active Domain (WHOIS age hidden)'
    else:
        result['domain_status'] = 'Unverified Domain'
        result['risk_severity'] = max(result['risk_severity'], 0.70)

    if result['is_disposable']:
        result['risk_severity'] = 1.0
        result['findings'].append(f"Sender uses a disposable/burner email provider ('{domain}')")

    return result


def get_network_intel(url: str) -> dict:
    """
    Gathers network-level intelligence for a given URL.
    Returns a dictionary with DNS, WHOIS, IP, and TLS details.
    """
    intel = {
        'domain': None,
        'ip_address': None,
        'asn_org': None,
        'country': None,
        'registrar': None,
        'creation_date': None,
        'domain_age_days': None,
        'tls_issuer': None,
        'tls_valid_days': None,
        'tls_issued_date': None
    }

    try:
        parsed_url = urlparse(url)
        domain = parsed_url.hostname
        if not domain:
            domain = url.split('/')[0]

        clean_domain = domain.replace('www.', '') if domain.startswith('www.') else domain
        intel['domain'] = clean_domain

        # 1. DNS A Record
        try:
            ip_address = socket.gethostbyname(domain)
            intel['ip_address'] = ip_address
        except Exception as e:
            logger.warning(f"Failed DNS resolution for {domain}: {e}")

        # 2. IP Geolocation & ASN
        if intel['ip_address']:
            try:
                resp = requests.get(f"http://ip-api.com/json/{intel['ip_address']}", timeout=3)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get('status') == 'success':
                        intel['country'] = data.get('country')
                        intel['asn_org'] = data.get('isp') or data.get('org') or data.get('as')
            except Exception as e:
                logger.warning(f"Failed IP geo lookup for {intel['ip_address']}: {e}")

        # 3. WHOIS (Domain Age & Registrar)
        try:
            domain_info = whois.whois(clean_domain)
            if domain_info:
                registrar = domain_info.registrar
                if isinstance(registrar, list):
                    registrar = registrar[0]
                intel['registrar'] = registrar

                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                if isinstance(creation_date, datetime):
                    naive_created = creation_date.replace(tzinfo=None)
                    intel['creation_date'] = naive_created.strftime("%Y-%m-%d")
                    age = (datetime.now() - naive_created).days
                    intel['domain_age_days'] = age
        except Exception as e:
            logger.warning(f"Failed WHOIS lookup for {clean_domain}: {e}")

        # 4. TLS Certificate Details
        if parsed_url.scheme == 'https' or not parsed_url.scheme:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                with socket.create_connection((domain, 443), timeout=3) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        if cert:
                            issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                            intel['tls_issuer'] = issuer_dict.get('organizationName') or issuer_dict.get('commonName')
                            
                            not_before = ssl.cert_time_to_seconds(cert['notBefore'])
                            not_after = ssl.cert_time_to_seconds(cert['notAfter'])
                            valid_days = int((not_after - not_before) / 86400)
                            intel['tls_valid_days'] = valid_days
                            intel['tls_issued_date'] = datetime.fromtimestamp(not_before).strftime("%Y-%m-%d")
            except Exception as e:
                logger.warning(f"Failed TLS lookup for {domain}: {e}")

    except Exception as e:
        logger.error(f"Error in network intel gathering: {e}")

    return intel

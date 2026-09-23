"""
Network and Domain Intelligence Module for PhishGuard.
Extracts WHOIS, DNS, IP Geolocation/ASN, and TLS certificate metadata.
"""

import socket
import ssl
import json
import logging
from datetime import datetime
from urllib.parse import urlparse
import requests
import whois

logger = logging.getLogger(__name__)

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
            # Maybe it doesn't have http://, try stripping
            domain = url.split('/')[0]

        # Strip www. for whois lookup
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
                    intel['creation_date'] = creation_date.strftime("%Y-%m-%d")
                    age = (datetime.now() - creation_date).days
                    intel['domain_age_days'] = age
        except Exception as e:
            logger.warning(f"Failed WHOIS lookup for {clean_domain}: {e}")

        # 4. TLS Certificate Details
        if parsed_url.scheme == 'https' or not parsed_url.scheme:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE  # We just want the metadata
                with socket.create_connection((domain, 443), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert(binary_form=False) # binary=False gets parsed dict if verify_mode=CERT_REQUIRED. Wait, with CERT_NONE it returns empty dict!
            except Exception:
                pass
            
            # Since ssl.CERT_NONE returns empty dict for getpeercert, we need to do this:
            try:
                import OpenSSL # PyOpenSSL might not be available, let's use standard library trick
            except ImportError:
                pass
            
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                # To get the cert data without raising error on invalid certs, we can catch it
                # or just try to get it. For simplicity, we require it to be somewhat valid to read it easily with standard lib
                with socket.create_connection((domain, 443), timeout=3) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        if cert:
                            # Parse issuer
                            issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                            intel['tls_issuer'] = issuer_dict.get('organizationName') or issuer_dict.get('commonName')
                            
                            # Parse dates
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
